use super::{
    ClientRequest, Result, SERVER, SESSION_PATH,
    adapter::{Registry, Stream},
};
use crate::{
    tunnel_h3::{TUNNEL_EVENTS_PATH, events::TunnelEventState},
    vendor::{
        h3::{self, ConnectionState},
        h3_quinn,
    },
};
use bytes::{Buf, Bytes};
use futures_util::future::poll_fn;
use http::{Method, Request};
use std::sync::{Arc, atomic::Ordering};
use tokio::sync::{mpsc, watch};

pub(super) struct Client {
    pub connection: quinn::Connection,
    pub sender: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    incoming: mpsc::Receiver<h3_quinn::BidiStream<Bytes>>,
    task: tokio::task::JoinHandle<()>,
    session_task: Option<tokio::task::JoinHandle<Result<()>>>,
    pub registry: Arc<Registry>,
    session_id: Option<h3::webtransport::SessionId>,
    close: Option<mpsc::Sender<()>>,
    pub closed: watch::Receiver<bool>,
    pub events: Option<ClientRequest>,
}
impl Client {
    pub async fn new(connection: quinn::Connection) -> Result<Self> {
        let transport = connection.clone();
        let (mut driver, sender) = h3::client::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .enable_webtransport(true)
            .max_field_section_size(16384)
            .build(h3_quinn::Connection::new(connection))
            .await?;
        let incoming = driver.webtransport_bidi(1024);
        let registry = Arc::new(Registry::default());
        let driver_registry = registry.clone();
        let task = tokio::spawn(async move {
            let _ = poll_fn(|cx| driver.poll_close(cx)).await;
            driver_registry.close();
        });
        Ok(Self {
            connection: transport,
            sender,
            task,
            incoming,
            registry,
            session_id: None,
            session_task: None,
            close: None,
            closed: watch::channel(false).1,
            events: None,
        })
    }
    pub async fn gate(&mut self) -> Result<()> {
        let mut stream = self
            .sender
            .send_request(Request::get(format!("https://{SERVER}{TUNNEL_EVENTS_PATH}")).body(())?)
            .await?;
        stream.finish().await?;
        let response = stream.recv_response().await?;
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        let mut event = Vec::new();
        while !event.ends_with(b"\n\n") {
            let mut data = stream.recv_data().await?.ok_or("events ended")?;
            event.extend_from_slice(&data.copy_to_bytes(data.remaining()));
            if event.len() > 4096 {
                return Err("event too long".into());
            }
        }
        let text = std::str::from_utf8(&event)?;
        let data = text
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .ok_or("missing state")?;
        TunnelEventState::decode(Some("state"), data)
            .map_err(|e| format!("invalid event: {e:?}"))?;
        self.events = Some(stream);
        Ok(())
    }
    pub async fn open_session(&mut self) -> Result<h3::webtransport::SessionId> {
        if self.events.is_none() {
            return Err("event gate not passed".into());
        }
        let peer = self.sender.settings();
        if !(peer.enable_webtransport()
            && peer.enable_datagram()
            && peer.enable_extended_connect()
            && peer.max_webtransport_sessions() > 0)
        {
            return Err("WebTransport settings not negotiated".into());
        }
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://{SERVER}{SESSION_PATH}"))
            .body(())?;
        request
            .extensions_mut()
            .insert(h3::ext::Protocol::WEB_TRANSPORT);
        let mut stream = self.sender.send_request(request).await?;
        if stream.recv_response().await?.status() != 200 {
            return Err("session rejected".into());
        }
        let id = h3::webtransport::SessionId::try_from(stream.id().into_inner())
            .map_err(|e| format!("session ID: {e:?}"))?;
        self.session_id = Some(id);
        let (close, mut commands) = mpsc::channel(1);
        let (closed, closed_watch) = watch::channel(false);
        self.close = Some(close);
        self.closed = closed_watch;
        let registry = self.registry.clone();
        self.session_task = Some(tokio::spawn(async move {
            let mut buffer = Vec::new();
            let mut sent = false;
            let result: Result<()> = async {
                loop {
                    tokio::select! {
                        command = commands.recv(), if !sent => {
                            command.ok_or("session owner dropped")?;
                            registry.close();
                            stream.send_data(super::capsule::close()).await?;
                            stream.finish().await?;
                            sent = true;
                        }
                        result = super::capsule::receive_client(&mut stream, &mut buffer) => {
                            result?;
                            registry.close();
                            if !sent { stream.finish().await?; }
                            return Ok(());
                        }
                    }
                }
            }
            .await;
            registry.close();
            closed.send_replace(true);
            result
        }));
        Ok(id)
    }
    pub async fn accept(&mut self) -> Result<Stream> {
        let id = self.session_id.ok_or("no live session")?;
        let stream = self.incoming.recv().await.ok_or("driver ended")?;
        let mut framed = h3::frame::FrameStream::new(h3::stream::BufRecvStream::new(stream));
        let frame = poll_fn(|cx| framed.poll_next(cx))
            .await
            .map_err(|e| format!("prefix decode: {e:?}"))?;
        match frame {
            Some(h3::proto::frame::Frame::WebTransportStream(received))
                if received == id && !self.registry.closed.load(Ordering::SeqCst) =>
            {
                Ok(self
                    .registry
                    .adapt(crate::vendor::h3_webtransport::stream::BidiStream::new(
                        framed.into_inner(),
                    )))
            }
            other => {
                use h3::quic::{RecvStream, SendStream};
                let mut stream = framed.into_inner();
                stream.reset(0x170d7b68);
                stream.stop_sending(0x170d7b68);
                Err(format!("unexpected WebTransport prefix/session: {other:?}").into())
            }
        }
    }
    pub async fn close_session(&mut self) -> Result<()> {
        self.close.as_ref().ok_or("no session")?.send(()).await?;
        self.closed.wait_for(|closed| *closed).await?;
        Ok(())
    }
    pub async fn put(&mut self) -> Result<()> {
        let mut stream = self
            .sender
            .send_request(Request::put(format!("https://{SERVER}/v1/tunnel/withdrawal")).body(())?)
            .await?;
        stream.finish().await?;
        assert_eq!(stream.recv_response().await?.status(), 204);
        assert!(stream.recv_data().await?.is_none());
        Ok(())
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.registry.close();
        self.task.abort();
        if let Some(task) = &self.session_task {
            task.abort();
        }
    }
}
