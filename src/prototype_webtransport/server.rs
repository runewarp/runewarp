use super::{
    Result, SERVER, SESSION_PATH, Session,
    adapter::{Registry, Stream},
};
use crate::{
    quic::peer_client_identity,
    tunnel_h3::{
        TUNNEL_EVENTS_PATH,
        events::{ServerRuntimeGeneration, TunnelEventState},
    },
    vendor::{
        h3::{self, ConnectionState},
        h3_quinn, h3_webtransport,
    },
};
use bytes::{Buf, Bytes};
use http::{Method, Request, Response, StatusCode};
use std::sync::{Arc, atomic::Ordering};
use tokio::sync::{mpsc, oneshot};

type RequestStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type Opener = h3_webtransport::server::SessionOpener<h3_quinn::Connection, Bytes>;
enum Command {
    Goaway(oneshot::Sender<()>),
    Close(oneshot::Sender<()>),
}
pub(super) struct Server {
    pub connection: quinn::Connection,
    opener: Opener,
    pub registry: Arc<Registry>,
    commands: mpsc::Sender<Command>,
    task: tokio::task::JoinHandle<Result<()>>,
    pub session_id: h3::webtransport::SessionId,
}
impl Server {
    pub async fn establish(
        connection: quinn::Connection,
        expected: crate::ClientIdentity,
    ) -> Result<Self> {
        assert_eq!(peer_client_identity(&connection).as_ref(), Some(&expected));
        let (commands, receive) = mpsc::channel(4);
        let (ready, wait) = oneshot::channel();
        let registry = Arc::new(Registry::default());
        let task_registry = registry.clone();
        let transport = connection.clone();
        let task = tokio::spawn(async move {
            let result = serve(transport, receive, ready, task_registry.clone()).await;
            task_registry.close();
            result
        });
        let (opener, session_id) = wait.await?;
        Ok(Self {
            connection,
            opener,
            registry,
            commands,
            task,
            session_id,
        })
    }
    pub async fn open(&self) -> Result<Stream> {
        if self.registry.closed.load(Ordering::SeqCst)
            || self.registry.draining.load(Ordering::SeqCst)
        {
            return Err("session accepts no new Visitors".into());
        }
        let stream = self.opener.open_bi().await?;
        if self.registry.closed.load(Ordering::SeqCst)
            || self.registry.draining.load(Ordering::SeqCst)
        {
            return Err("session ended during stream open".into());
        }
        Ok(self.registry.adapt(stream))
    }
    pub async fn goaway(&self) -> Result<()> {
        let (send, wait) = oneshot::channel();
        self.commands.send(Command::Goaway(send)).await?;
        wait.await?;
        Ok(())
    }
    pub async fn close_session(&self) -> Result<()> {
        let (send, wait) = oneshot::channel();
        self.commands.send(Command::Close(send)).await?;
        wait.await?;
        Ok(())
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.registry.close();
        self.task.abort();
        self.connection.close(0x100u32.into(), b"");
    }
}

async fn serve(
    connection: quinn::Connection,
    mut commands: mpsc::Receiver<Command>,
    ready: oneshot::Sender<(Opener, h3::webtransport::SessionId)>,
    registry: Arc<Registry>,
) -> Result<()> {
    let mut driver = h3::server::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .enable_webtransport(true)
        .max_webtransport_sessions(1)
        .max_field_section_size(16384)
        .build(h3_quinn::Connection::new(connection))
        .await?;
    let mut events = None;
    let mut accepted = 0u64;
    let session = loop {
        let (request, mut stream) = driver
            .accept()
            .await?
            .ok_or("connection ended before session")?
            .resolve_request()
            .await?;
        accepted += 1;
        if is_session(&request) && events.is_some() {
            let peer = driver.settings();
            assert!(
                peer.enable_webtransport()
                    && peer.enable_datagram()
                    && peer.enable_extended_connect()
            );
            assert_eq!(peer.max_webtransport_sessions(), 1);
            break Session::accept(request, stream, driver).await?;
        }
        if request.method() == Method::GET && request.uri().path() == TUNNEL_EVENTS_PATH {
            require_bodyless(&mut stream).await?;
            stream
                .send_response(
                    Response::builder()
                        .header("content-type", "text/event-stream")
                        .body(())?,
                )
                .await?;
            stream
                .send_data(
                    TunnelEventState::current(ServerRuntimeGeneration::generate()).encode_sse(),
                )
                .await?;
            events = Some(stream);
        } else {
            status(&mut stream, StatusCode::BAD_REQUEST).await?;
        }
    };
    let id = session.session_id();
    let (mut driver, mut connect, opener) = session.into_parts();
    ready
        .send((opener, id))
        .map_err(|_| "prototype setup cancelled")?;
    let mut boundary = None;
    let mut accepting = true;
    let mut session_open = true;
    let mut sent_close = false;
    let mut capsule_buffer = Vec::new();
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(Command::Goaway(done)) => {
                    registry.draining.store(true, Ordering::SeqCst);
                    boundary = Some(accepted * 4);
                    driver.shutdown(1).await?;
                    if let Some(mut stream) = events.take() { stream.finish().await?; }
                    let _ = done.send(());
                }
                Some(Command::Close(done)) => {
                    registry.close();
                    connect.send_data(super::capsule::close()).await?;
                    connect.finish().await?;
                    sent_close = true;
                    let _ = done.send(());
                }
                None => break,
            },
            capsule = super::capsule::receive_server(&mut connect, &mut capsule_buffer), if session_open => {
                capsule?;
                registry.close();
                if !sent_close { connect.finish().await?; }
                session_open = false;
            }
            request = driver.accept(), if accepting => {
                let Some(resolver) = request? else { accepting = false; continue; };
                accepted += 1;
                let (request, mut stream) = resolver.resolve_request().await?;
                if boundary.is_some_and(|id| stream.id().into_inner() >= id) {
                    stream.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
                    stream.stop_sending(h3::error::Code::H3_REQUEST_REJECTED);
                } else if is_session(&request) {
                    // #355: one session is the prototype's advertised and enforced limit.
                    status(&mut stream, StatusCode::TOO_MANY_REQUESTS).await?;
                } else if request.method() == Method::PUT && request.uri().path() == "/v1/tunnel/withdrawal" && request.uri().host() == Some(SERVER) {
                    require_bodyless(&mut stream).await?;
                    // A coexistence stand-in only, not the production withdrawal contract.
                    status(&mut stream, StatusCode::NO_CONTENT).await?;
                } else { status(&mut stream, StatusCode::NOT_FOUND).await?; }
            }
        }
    }
    Ok(())
}
fn is_session(request: &Request<()>) -> bool {
    request.method() == Method::CONNECT
        && request.uri().scheme_str() == Some("https")
        && request.uri().host() == Some(SERVER)
        && request.uri().path() == SESSION_PATH
        && request.extensions().get::<h3::ext::Protocol>()
            == Some(&h3::ext::Protocol::WEB_TRANSPORT)
}
async fn require_bodyless(stream: &mut RequestStream) -> Result<()> {
    while let Some(data) = stream.recv_data().await? {
        if data.has_remaining() {
            return Err("request content".into());
        }
    }
    if stream.recv_trailers().await?.is_some() {
        return Err("request trailers".into());
    }
    Ok(())
}
async fn status(stream: &mut RequestStream, status: StatusCode) -> Result<()> {
    stream
        .send_response(Response::builder().status(status).body(())?)
        .await?;
    stream.finish().await?;
    Ok(())
}
