use super::{
    Profile, Result, SERVER, STEP,
    association::{self, ClientContexts, Counters, PacketSender, Read, ServerContexts, Write},
};
use crate::{
    prototype_webtransport::{
        adapter::{Registry, Stream},
        fixture::Fixture,
    },
    tunnel_h3::{
        TUNNEL_EVENTS_PATH, TunnelStream,
        events::{ServerRuntimeGeneration, TunnelEventState},
    },
    vendor::{
        h3::{self, ConnectionState},
        h3_quinn, h3_webtransport,
    },
};
use bytes::Bytes;
use futures_util::future::poll_fn;
use http::{Method, Request, Response};
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, watch},
    task::JoinHandle,
};

type Driver = h3::server::Connection<h3_quinn::Connection, Bytes>;
type ServerRequest = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type ClientRequest = super::super::ClientRequest;
type Opener = h3_webtransport::server::SessionOpener<h3_quinn::Connection, Bytes>;
type Incoming = mpsc::Receiver<h3_quinn::BidiStream<Bytes>>;
type Requests = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

struct Native {
    commands: mpsc::Sender<()>,
    done: watch::Receiver<bool>,
    task: JoinHandle<()>,
}
impl Native {
    fn start(mut read: Read, mut write: Write, closed: Arc<dyn Fn() + Send + Sync>) -> Self {
        let (commands, mut receive) = mpsc::channel(1);
        let (done, watch) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut sent = false;
            let mut buffer = Vec::new();
            let result:Result<()>=async {loop {tokio::select! {
                command=receive.recv(),if !sent=>{
                    command.ok_or("native owner gone")?;closed();
                    write.write_all(&super::super::capsule::close()).await?;write.flush().await?;write.shutdown().await?;sent=true;
                }
                result=read_native(&mut read,&mut buffer)=>{result?;closed();if !sent{write.shutdown().await?;}return Ok(());}
            }}}.await;
            let _ = result;
            closed();
            done.send_replace(true);
        });
        Self {
            commands,
            done: watch,
            task,
        }
    }
    async fn close(&mut self) -> Result<()> {
        self.commands.send(()).await?;
        self.done.wait_for(|closed| *closed).await?;
        Ok(())
    }
}
impl Drop for Native {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn read_native(read: &mut Read, buffer: &mut Vec<u8>) -> Result<()> {
    let mut chunk = [0u8; 512];
    loop {
        let n = read.read(&mut chunk).await?;
        if n == 0 {
            return super::super::capsule::validate(buffer);
        }
        if buffer.len() + n > 8192 {
            return Err("native CLOSE intake bound".into());
        }
        buffer.extend_from_slice(&chunk[..n]);
    }
}
fn server_bytes(stream: ServerRequest) -> (Read, Write) {
    let (send, recv) = stream.split();
    let (read, write) = TunnelStream::new(recv, send, Arc::new(())).into_split();
    (Box::new(read), Box::new(write))
}
fn client_bytes(stream: ClientRequest) -> (Read, Write) {
    let (send, recv) = stream.split();
    let (read, write) = TunnelStream::new(recv, send, Arc::new(())).into_split();
    (Box::new(read), Box::new(write))
}
fn server_scope(
    registry: Arc<Registry>,
    udp: bool,
    contexts: Arc<Mutex<ServerContexts>>,
    closed: Arc<AtomicBool>,
) -> Arc<dyn Fn() + Send + Sync> {
    Arc::new(move || {
        registry.close();
        if udp {
            closed.store(true, Ordering::SeqCst);
            contexts.lock().expect("server contexts").close();
        }
    })
}
fn client_scope(
    registry: Arc<Registry>,
    udp: bool,
    contexts: Arc<ClientContexts>,
) -> Arc<dyn Fn() + Send + Sync> {
    Arc::new(move || {
        registry.close();
        if udp {
            contexts.close();
        }
    })
}
struct ServerSetup {
    driver: Driver,
    opener: Opener,
    udp_opener: Option<Opener>,
    natives: Vec<Native>,
    dedicated: Option<(Read, Write)>,
    events: ServerRequest,
}
struct ClientSetup {
    requests: Requests,
    incoming: Incoming,
    task: JoinHandle<()>,
    natives: Vec<Native>,
    dedicated: Option<(Read, Write)>,
    events: ClientRequest,
}

async fn server_setup(
    connection: quinn::Connection,
    profile: Profile,
    tcp: Arc<Registry>,
    udp: Arc<Registry>,
    contexts: Arc<Mutex<ServerContexts>>,
    closed: Arc<AtomicBool>,
) -> Result<ServerSetup> {
    let mut driver = h3::server::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .enable_webtransport(true)
        .max_webtransport_sessions(2)
        .max_field_section_size(16384)
        .build(h3_quinn::Connection::new(connection))
        .await?;
    let (request, mut events) = driver
        .accept()
        .await?
        .ok_or("missing GET")?
        .resolve_request()
        .await?;
    assert_eq!(request.method(), Method::GET);
    assert_eq!(request.uri().path(), TUNNEL_EVENTS_PATH);
    assert!(events.recv_data().await?.is_none());
    events
        .send_response(
            Response::builder()
                .header("content-type", "text/event-stream")
                .body(())?,
        )
        .await?;
    events
        .send_data(TunnelEventState::current(ServerRuntimeGeneration::generate()).encode_sse())
        .await?;
    let (request, stream) = driver
        .accept()
        .await?
        .ok_or("missing TCP session")?
        .resolve_request()
        .await?;
    assert_eq!(
        request.extensions().get::<h3::ext::Protocol>(),
        Some(&h3::ext::Protocol::WEB_TRANSPORT)
    );
    assert!(driver.settings().enable_datagram() && driver.settings().enable_webtransport());
    let session =
        h3_webtransport::server::WebTransportSession::accept(request, stream, driver).await?;
    let (mut driver, stream, opener) = session.into_parts();
    let (read, write) = server_bytes(stream);
    let mut natives = vec![Native::start(
        read,
        write,
        server_scope(
            tcp,
            profile == Profile::Unified,
            contexts.clone(),
            closed.clone(),
        ),
    )];
    let mut udp_opener = None;
    let mut dedicated = None;
    if profile != Profile::Unified {
        let (request, mut stream) = driver
            .accept()
            .await?
            .ok_or("missing UDP carrier")?
            .resolve_request()
            .await?;
        assert_eq!(request.method(), Method::CONNECT);
        assert_eq!(request.uri().host(), Some(SERVER));
        if profile == Profile::SplitWt {
            assert_eq!(
                request.extensions().get::<h3::ext::Protocol>(),
                Some(&h3::ext::Protocol::WEB_TRANSPORT)
            );
            let session =
                h3_webtransport::server::WebTransportSession::accept(request, stream, driver)
                    .await?;
            let (next, stream, opener) = session.into_parts();
            driver = next;
            udp_opener = Some(opener);
            let (read, write) = server_bytes(stream);
            natives.push(Native::start(
                read,
                write,
                server_scope(udp, true, contexts, closed),
            ));
        } else {
            assert_eq!(
                request.extensions().get::<h3::ext::Protocol>(),
                Some(&h3::ext::Protocol::RUNEWARP_PROTOTYPE_UDP)
            );
            stream
                .send_response(
                    Response::builder()
                        .header("capsule-protocol", "?1")
                        .body(())?,
                )
                .await?;
            dedicated = Some(server_bytes(stream));
        }
    }
    Ok(ServerSetup {
        driver,
        opener,
        udp_opener,
        natives,
        dedicated,
        events,
    })
}
async fn connect(
    requests: &mut Requests,
    path: &str,
    protocol: h3::ext::Protocol,
) -> Result<ClientRequest> {
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://{SERVER}{path}"))
        .body(())?;
    request.extensions_mut().insert(protocol);
    let mut stream = requests.send_request(request).await?;
    assert_eq!(stream.recv_response().await?.status(), 200);
    Ok(stream)
}
async fn client_setup(
    connection: quinn::Connection,
    profile: Profile,
    tcp: Arc<Registry>,
    udp: Arc<Registry>,
    contexts: Arc<ClientContexts>,
) -> Result<ClientSetup> {
    let (mut driver, mut requests) = h3::client::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .enable_webtransport(true)
        .max_field_section_size(16384)
        .build(h3_quinn::Connection::new(connection))
        .await?;
    let incoming = driver.webtransport_bidi(128);
    let close_tcp = tcp.clone();
    let close_udp = udp.clone();
    let state = contexts.clone();
    let task = tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
        close_tcp.close();
        close_udp.close();
        state.close();
    });
    let mut events = requests
        .send_request(Request::get(format!("https://{SERVER}{TUNNEL_EVENTS_PATH}")).body(())?)
        .await?;
    events.finish().await?;
    assert_eq!(events.recv_response().await?.status(), 200);
    let mut data = Vec::new();
    while !data.ends_with(b"\n\n") {
        use bytes::Buf;
        let mut chunk = events.recv_data().await?.ok_or("missing state")?;
        data.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        if data.len() > 4096 {
            return Err("event bound".into());
        }
    }
    let text = std::str::from_utf8(&data)?;
    let json = text
        .lines()
        .find_map(|s| s.strip_prefix("data: "))
        .ok_or("state missing")?;
    TunnelEventState::decode(Some("state"), json).map_err(|e| format!("state: {e:?}"))?;
    assert_eq!(requests.settings().max_webtransport_sessions(), 2);
    let stream = connect(
        &mut requests,
        "/prototype/tcp",
        h3::ext::Protocol::WEB_TRANSPORT,
    )
    .await?;
    assert_eq!(stream.id().into_inner(), 4);
    let (read, write) = client_bytes(stream);
    let mut natives = vec![Native::start(
        read,
        write,
        client_scope(tcp, profile == Profile::Unified, contexts.clone()),
    )];
    let mut dedicated = None;
    if profile != Profile::Unified {
        let protocol = if profile == Profile::SplitWt {
            h3::ext::Protocol::WEB_TRANSPORT
        } else {
            h3::ext::Protocol::RUNEWARP_PROTOTYPE_UDP
        };
        let stream = connect(&mut requests, "/prototype/udp", protocol).await?;
        assert_eq!(stream.id().into_inner(), 8);
        let (read, write) = client_bytes(stream);
        if profile == Profile::SplitWt {
            natives.push(Native::start(
                read,
                write,
                client_scope(udp, true, contexts),
            ));
        } else {
            dedicated = Some((read, write));
        }
    }
    Ok(ClientSetup {
        requests,
        incoming,
        task,
        natives,
        dedicated,
        events,
    })
}
async fn incoming(
    incoming: &mut Incoming,
    registry: &Registry,
    id: u64,
    role: u8,
) -> Result<Stream> {
    let stream = incoming.recv().await.ok_or("client driver ended")?;
    let mut framed = h3::frame::FrameStream::new(h3::stream::BufRecvStream::new(stream));
    let frame = poll_fn(|cx| framed.poll_next(cx))
        .await
        .map_err(|e| format!("WT prefix: {e:?}"))?;
    assert!(
        matches!(frame,Some(h3::proto::frame::Frame::WebTransportStream(session)) if session.into_inner()==id)
    );
    let mut stream = registry.adapt(h3_webtransport::stream::BidiStream::new(
        framed.into_inner(),
    ));
    assert_eq!(stream.read_u8().await?, role);
    Ok(stream)
}

pub(super) struct Harness {
    pub profile: Profile,
    pub server: quinn::Connection,
    pub client: quinn::Connection,
    opener: Opener,
    incoming: Incoming,
    tcp_server: Arc<Registry>,
    tcp_client: Arc<Registry>,
    pub contexts: Arc<Mutex<ServerContexts>>,
    pub received: Arc<ClientContexts>,
    pub send: PacketSender,
    pub reply: PacketSender,
    pub ingress: Arc<tokio::net::UdpSocket>,
    control: Write,
    server_native: Vec<Native>,
    _client_native: Vec<Native>,
    forwarder: Option<super::forwarder::Forwarder>,
    requests: Requests,
    _events: ClientRequest,
    tasks: Vec<JoinHandle<()>>,
    _fixture: Fixture,
}
impl Harness {
    pub async fn new(profile: Profile, credit: u32, mtu: u16) -> Result<Self> {
        Self::new_path(profile, credit, mtu, false).await
    }
    pub async fn new_path(profile: Profile, credit: u32, mtu: u16, impaired: bool) -> Result<Self> {
        let fixture = Fixture::packet_fixture(credit, mtu)?;
        let forwarder = if impaired {
            Some(super::forwarder::Forwarder::new(fixture.server.local_addr()?).await?)
        } else {
            None
        };
        let (server, client) = if let Some(path) = &forwarder {
            fixture.connect_to(path.address).await?
        } else {
            fixture.connect().await?
        };
        assert_eq!(
            crate::quic::peer_client_identity(&server).as_ref(),
            Some(&fixture.identity)
        );
        let backend = association::socket().await?;
        let backend_addr = backend.local_addr()?;
        let echo = tokio::spawn(async move {
            let mut bytes = vec![0; 65536];
            while let Ok((n, source)) = backend.recv_from(&mut bytes).await {
                let _ = backend.send_to(&bytes[..n], source).await;
            }
        });
        let server_closed = Arc::new(AtomicBool::new(false));
        let client_closed = Arc::new(AtomicBool::new(false));
        let send = PacketSender::new(
            server.clone(),
            profile.udp_id(),
            server_closed.clone(),
            Arc::new(Counters::default()),
        );
        let reply = PacketSender::new(
            client.clone(),
            profile.udp_id(),
            client_closed,
            Arc::new(Counters::default()),
        );
        let contexts = Arc::new(Mutex::new(ServerContexts::default()));
        let received = Arc::new(ClientContexts::new(backend_addr, reply.clone()));
        let tcp_server = Arc::new(Registry::default());
        let tcp_client = Arc::new(Registry::default());
        let udp_server = if profile == Profile::Unified {
            tcp_server.clone()
        } else {
            Arc::new(Registry::default())
        };
        let udp_client = if profile == Profile::Unified {
            tcp_client.clone()
        } else {
            Arc::new(Registry::default())
        };
        let (server_setup, client_setup) = tokio::join!(
            server_setup(
                server.clone(),
                profile,
                tcp_server.clone(),
                udp_server.clone(),
                contexts.clone(),
                server_closed.clone()
            ),
            client_setup(
                client.clone(),
                profile,
                tcp_client.clone(),
                udp_client.clone(),
                received.clone()
            )
        );
        let mut s = server_setup?;
        let mut c = client_setup?;
        let (control_read, control, control_reply, control_server_read) = if profile
            == Profile::Dedicated
        {
            let (server_read, server_write) = s.dedicated.take().ok_or("server control missing")?;
            let (client_read, client_write) = c.dedicated.take().ok_or("client control missing")?;
            (client_read, server_write, client_write, server_read)
        } else {
            let opener = s.udp_opener.as_ref().unwrap_or(&s.opener);
            let mut stream = udp_server.adapt(opener.open_bi().await?);
            stream.write_all(&[0]).await?;
            stream.flush().await?;
            let peer = incoming(&mut c.incoming, &udp_client, profile.udp_id(), 0).await?;
            let (sr, sw) = stream.into_split();
            let (cr, cw) = peer.into_split();
            (
                Box::new(cr) as Read,
                Box::new(sw) as Write,
                Box::new(cw) as Write,
                Box::new(sr) as Read,
            )
        };
        let state = received.clone();
        let consumer = tokio::spawn(async move {
            let _ = association::consume(control_read, state).await;
            // Return FIN on the control direction so the Server retires routes too.
            let mut reply = control_reply;
            let _ = reply.shutdown().await;
        });
        let state = contexts.clone();
        let closed = server_closed.clone();
        let observer = tokio::spawn(async move {
            let mut read = control_server_read;
            let mut buffer = [0u8; 128];
            while let Ok(n) = read.read(&mut buffer).await {
                if n == 0 {
                    break;
                }
            }
            closed.store(true, Ordering::SeqCst);
            state.lock().expect("server contexts").close();
        });
        let driver = tokio::spawn(async move {
            let _events = s.events;
            while let Ok(Some(resolver)) = s.driver.accept().await {
                let Ok((request, mut stream)) = resolver.resolve_request().await else {
                    continue;
                };
                let status = if request.method() == Method::PUT {
                    204
                } else {
                    404
                };
                let _ = stream.recv_data().await;
                let _ = stream
                    .send_response(Response::builder().status(status).body(()).expect("status"))
                    .await;
                let _ = stream.finish().await;
            }
        });
        let ingress = Arc::new(association::socket().await?);
        let source = ingress.clone();
        let route = contexts.clone();
        let sender = send.clone();
        let intake = tokio::spawn(async move {
            let mut bytes = vec![0u8; 65536];
            while let Ok((n, source_addr)) = source.recv_from(&mut bytes).await {
                let id = route
                    .lock()
                    .expect("server contexts")
                    .sources
                    .get(&source_addr)
                    .copied();
                if let Some(id) = id {
                    sender.send(id, &bytes[..n]);
                } else {
                    sender.counters.unknown.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        let sender = reply.clone();
        let state = received.clone();
        let conn = client.clone();
        let downlink = tokio::spawn(async move {
            while let Ok(bytes) = conn.read_datagram().await {
                if let Some((id, payload)) = sender.decode(bytes) {
                    state.enqueue(id, payload);
                }
            }
            state.close();
        });
        let conn = server.clone();
        let source = ingress.clone();
        let route = contexts.clone();
        let sender = send.clone();
        let uplink = tokio::spawn(async move {
            while let Ok(bytes) = conn.read_datagram().await {
                if let Some((id, payload)) = sender.decode(bytes) {
                    let dest = route
                        .lock()
                        .expect("server contexts")
                        .routes
                        .get(&id)
                        .copied();
                    if let Some(dest) = dest {
                        let _ = source.send_to(&payload, dest).await;
                        sender.counters.delivered.fetch_add(1, Ordering::Relaxed);
                    } else {
                        sender.counters.unknown.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
        Ok(Self {
            profile,
            server,
            client,
            opener: s.opener,
            incoming: c.incoming,
            tcp_server,
            tcp_client,
            contexts,
            received,
            send,
            reply,
            ingress,
            control,
            server_native: s.natives,
            _client_native: c.natives,
            forwarder,
            requests: c.requests,
            _events: c.events,
            tasks: vec![
                echo, consumer, observer, driver, c.task, intake, downlink, uplink,
            ],
            _fixture: fixture,
        })
    }
    pub fn path_counts(&self) -> (u64, u64) {
        self.forwarder
            .as_ref()
            .map(|path| {
                (
                    path.packets.load(Ordering::Relaxed),
                    path.dropped.load(Ordering::Relaxed),
                )
            })
            .unwrap_or((0, 0))
    }
    pub async fn announce(&mut self, source: SocketAddr) -> Result<u64> {
        let id = self
            .contexts
            .lock()
            .expect("server contexts")
            .register(source)?;
        if self.send.payload_limit(id) < 1200 {
            self.contexts.lock().expect("server contexts").retire(id);
            return Err("outer path cannot carry a 1200-byte Initial".into());
        }
        association::record(&mut self.control, association::REGISTER, id).await?;
        Ok(id)
    }
    pub async fn wait_registered(&self, id: u64) -> Result<()> {
        tokio::time::timeout(STEP, async {
            while !self.received.contains(id) {
                if self.received.closed.load(Ordering::SeqCst) {
                    return Err("UDP carrier closed".into());
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            Ok::<_, super::Error>(())
        })
        .await?
    }
    pub async fn register(&mut self, source: SocketAddr) -> Result<u64> {
        let id = self.announce(source).await?;
        self.wait_registered(id).await?;
        Ok(id)
    }
    pub async fn retire(&mut self, id: u64) -> Result<()> {
        self.contexts.lock().expect("server contexts").retire(id);
        association::record(&mut self.control, association::RETIRE, id).await?;
        tokio::time::timeout(STEP, async {
            while self.received.contains(id) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }
    pub async fn withdraw_udp(&mut self) -> Result<()> {
        self.send.closed.store(true, Ordering::SeqCst);
        self.contexts.lock().expect("server contexts").close();
        association::record(&mut self.control, association::WITHDRAW, 0).await?;
        self.wait_udp_closed().await
    }
    pub async fn wait_udp_closed(&self) -> Result<()> {
        tokio::time::timeout(STEP, async {
            while !self.received.closed.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }
    pub async fn close_udp_native(&mut self) -> Result<()> {
        if self.profile == Profile::Dedicated {
            self.send.closed.store(true, Ordering::SeqCst);
            self.contexts.lock().expect("server contexts").close();
            self.control.shutdown().await?;
        } else {
            let index = usize::from(self.profile != Profile::Unified);
            self.server_native[index].close().await?;
        }
        self.wait_udp_closed().await
    }
    pub async fn open_tcp(&mut self) -> Result<(Stream, Stream)> {
        let mut stream = self.open_server_tcp().await?;
        stream.write_all(&[1]).await?;
        stream.flush().await?;
        let peer = incoming(&mut self.incoming, &self.tcp_client, 4, 1).await?;
        Ok((stream, peer))
    }
    pub async fn open_server_tcp(&self) -> Result<Stream> {
        if self.tcp_server.closed.load(Ordering::SeqCst) {
            return Err("TCP session closed".into());
        }
        Ok(self.tcp_server.adapt(self.opener.open_bi().await?))
    }
    pub async fn truncate_control(&mut self) -> Result<()> {
        self.control.write_all(&[0x7f, 0, 2, 1]).await?;
        self.control.flush().await?;
        self.control.shutdown().await?;
        Ok(())
    }
    pub async fn put(&mut self) -> Result<()> {
        let mut stream = self
            .requests
            .send_request(Request::put(format!("https://{SERVER}/v1/tunnel/withdrawal")).body(())?)
            .await?;
        stream.finish().await?;
        assert_eq!(stream.recv_response().await?.status(), 204);
        assert!(stream.recv_data().await?.is_none());
        Ok(())
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.received.close();
        self.send.closed.store(true, Ordering::SeqCst);
        self.contexts.lock().expect("server contexts").close();
        for task in &self.tasks {
            task.abort();
        }
        self.server.close(0x100u32.into(), b"");
    }
}
