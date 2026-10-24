use super::Result;
use crate::vendor::{
    h3::{proto::varint::VarInt, quic::StreamId},
    h3_datagram::datagram::Datagram,
};
use bytes::{Buf, Bytes, BytesMut};
use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use tokio::{
    net::UdpSocket,
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    task::JoinHandle,
};

pub(super) const ASSOCIATIONS: usize = 16;
pub(super) const PER_CONTEXT: usize = 8;
pub(super) const GLOBAL_PACKETS: usize = 32;
pub(super) const REGISTER: u64 = 0x3f00;
pub(super) const RETIRE: u64 = 0x3f01;
pub(super) const WITHDRAW: u64 = 0x3f02;
pub(super) type Read = Box<dyn tokio::io::AsyncRead + Send + Unpin>;
pub(super) type Write = Box<dyn tokio::io::AsyncWrite + Send + Unpin>;
pub(super) async fn socket() -> Result<UdpSocket> {
    Ok(UdpSocket::bind("127.0.0.1:0").await?)
}
pub(super) fn varint(value: u64, output: &mut BytesMut) {
    VarInt::from_u64(value)
        .expect("bounded prototype integer")
        .encode(output);
}
pub(super) async fn read_varint(read: &mut Read) -> Result<Option<u64>> {
    use tokio::io::AsyncReadExt;
    let mut first = [0u8; 1];
    if read.read(&mut first).await? == 0 {
        return Ok(None);
    }
    let size = 1usize << (first[0] >> 6);
    let mut value = u64::from(first[0] & 63);
    for _ in 1..size {
        value = (value << 8) | u64::from(read.read_u8().await?);
    }
    Ok(Some(value))
}
pub(super) async fn record(write: &mut Write, kind: u64, id: u64) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut payload = BytesMut::new();
    varint(id, &mut payload);
    let mut bytes = BytesMut::new();
    varint(kind, &mut bytes);
    varint(payload.len() as u64, &mut bytes);
    bytes.extend_from_slice(&payload);
    write.write_all(&bytes).await?;
    write.flush().await?;
    Ok(())
}
pub(super) async fn read_record(read: &mut Read) -> Result<Option<(u64, u64)>> {
    use tokio::io::AsyncReadExt;
    let Some(kind) = read_varint(read).await? else {
        return Ok(None);
    };
    let length = read_varint(read).await?.ok_or("truncated record")?;
    if length > 128 {
        return Err("control record too large".into());
    }
    let mut bytes = vec![0u8; length as usize];
    read.read_exact(&mut bytes).await?;
    let mut cursor = bytes.as_slice();
    let id = VarInt::decode(&mut cursor)
        .map_err(|e| format!("record integer: {e:?}"))?
        .into_inner();
    if !cursor.is_empty() {
        return Err("control record trailing bytes".into());
    }
    Ok(Some((kind, id)))
}
#[derive(Default)]
pub(super) struct Counters {
    pub delivered: AtomicU64,
    pub unknown: AtomicU64,
    pub queue_full: AtomicU64,
    pub oversized: AtomicU64,
    pub send_full: AtomicU64,
    pub wrong_carrier: AtomicU64,
    pub malformed: AtomicU64,
}
impl Counters {
    pub fn summary(&self) -> String {
        format!(
            "forwarded={} unknown={} queue_full={} oversized={} send_full={} wrong_carrier={} malformed={}",
            self.delivered.load(Ordering::Relaxed),
            self.unknown.load(Ordering::Relaxed),
            self.queue_full.load(Ordering::Relaxed),
            self.oversized.load(Ordering::Relaxed),
            self.send_full.load(Ordering::Relaxed),
            self.wrong_carrier.load(Ordering::Relaxed),
            self.malformed.load(Ordering::Relaxed)
        )
    }
}
#[derive(Clone)]
pub(super) struct PacketSender {
    pub connection: quinn::Connection,
    pub carrier: u64,
    pub closed: Arc<AtomicBool>,
    pub counters: Arc<Counters>,
    gate: Arc<Mutex<()>>,
}
impl PacketSender {
    pub fn new(
        connection: quinn::Connection,
        carrier: u64,
        closed: Arc<AtomicBool>,
        counters: Arc<Counters>,
    ) -> Self {
        Self {
            connection,
            carrier,
            closed,
            counters,
            gate: Arc::new(Mutex::new(())),
        }
    }
    pub fn payload_limit(&self, id: u64) -> usize {
        let context = VarInt::from_u64(id).expect("context ID").size();
        let quarter = VarInt::from_u64(self.carrier / 4)
            .expect("quarter ID")
            .size();
        self.connection
            .max_datagram_size()
            .unwrap_or(0)
            .saturating_sub(context + quarter)
    }
    pub fn send(&self, id: u64, payload: &[u8]) -> bool {
        if self.closed.load(Ordering::SeqCst) {
            self.counters.unknown.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if payload.len() > self.payload_limit(id) {
            self.counters.oversized.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let mut body = BytesMut::with_capacity(payload.len() + 8);
        varint(id, &mut body);
        body.extend_from_slice(payload);
        let mut datagram = Datagram::new(
            StreamId::try_from(self.carrier).expect("CONNECT ID"),
            body.freeze(),
        )
        .encode();
        let bytes = datagram.copy_to_bytes(datagram.remaining());
        let _guard = self.gate.lock().expect("prototype sender gate");
        // Drop newest explicitly; never rely on Quinn evicting an older queued packet.
        if self.connection.datagram_send_buffer_space() < bytes.len() {
            self.counters.send_full.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        match self.connection.send_datagram(bytes) {
            Ok(()) => true,
            Err(quinn::SendDatagramError::TooLarge) => {
                self.counters.oversized.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(_) => {
                self.counters.send_full.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }
    pub fn decode(&self, bytes: Bytes) -> Option<(u64, Bytes)> {
        let packet = match Datagram::decode(bytes) {
            Ok(packet) => packet,
            Err(_) => {
                self.counters.malformed.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };
        if packet.stream_id().into_inner() != self.carrier {
            self.counters.wrong_carrier.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let mut payload = packet.into_payload();
        let id = match VarInt::decode(&mut payload) {
            Ok(id) => id.into_inner(),
            Err(_) => {
                self.counters.malformed.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };
        Some((id, payload))
    }
}
pub(super) struct ServerContexts {
    pub routes: BTreeMap<u64, SocketAddr>,
    pub sources: HashMap<SocketAddr, u64>,
    next: u64,
    pub withdrawn: bool,
}
impl Default for ServerContexts {
    fn default() -> Self {
        Self {
            routes: BTreeMap::new(),
            sources: HashMap::new(),
            next: 62,
            withdrawn: false,
        }
    }
}
impl ServerContexts {
    pub fn register(&mut self, source: SocketAddr) -> Result<u64> {
        if self.withdrawn || self.routes.len() >= ASSOCIATIONS || self.sources.contains_key(&source)
        {
            return Err("association capacity unavailable".into());
        }
        let id = self.next;
        self.next = self
            .next
            .checked_add(1)
            .filter(|id| *id < (1 << 62))
            .ok_or("context ID exhausted")?;
        self.routes.insert(id, source);
        self.sources.insert(source, id);
        Ok(id)
    }
    pub fn retire(&mut self, id: u64) {
        if let Some(source) = self.routes.remove(&id) {
            self.sources.remove(&source);
        }
    }
    pub fn close(&mut self) {
        self.withdrawn = true;
        self.routes.clear();
        self.sources.clear();
    }
}
struct Packet {
    bytes: Bytes,
    _permit: OwnedSemaphorePermit,
}
struct Handler {
    send: mpsc::Sender<Packet>,
    task: JoinHandle<()>,
}
impl Drop for Handler {
    fn drop(&mut self) {
        self.task.abort();
    }
}
pub(super) struct ClientContexts {
    handlers: Mutex<BTreeMap<u64, Handler>>,
    high: Mutex<Option<u64>>,
    pub closed: Arc<AtomicBool>,
    pub budget: Arc<Semaphore>,
    sender: PacketSender,
    backend: SocketAddr,
    pub counters: Arc<Counters>,
}
impl ClientContexts {
    pub fn new(backend: SocketAddr, sender: PacketSender) -> Self {
        Self {
            handlers: Mutex::new(BTreeMap::new()),
            high: Mutex::new(None),
            closed: sender.closed.clone(),
            budget: Arc::new(Semaphore::new(GLOBAL_PACKETS)),
            counters: sender.counters.clone(),
            sender,
            backend,
        }
    }
    pub fn contains(&self, id: u64) -> bool {
        self.handlers
            .lock()
            .expect("prototype handlers")
            .contains_key(&id)
    }
    pub fn count(&self) -> usize {
        self.handlers.lock().expect("prototype handlers").len()
    }
    pub async fn register(&self, id: u64) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) || self.count() >= ASSOCIATIONS {
            return Err("Client association cap".into());
        }
        {
            let mut high = self.high.lock().expect("prototype high ID");
            if high.is_some_and(|old| id <= old) {
                return Err("context ID reuse".into());
            }
            *high = Some(id);
        }
        let socket = socket().await?;
        let backend = self.backend;
        let sender = self.sender.clone();
        let (send, mut input) = mpsc::channel::<Packet>(PER_CONTEXT);
        let task = tokio::spawn(async move {
            let mut buffer = vec![0u8; 65536];
            loop {
                tokio::select! {
                    packet=input.recv()=>match packet {Some(packet)=>{let _=socket.send_to(&packet.bytes,backend).await;},None=>break},
                    reply=socket.recv_from(&mut buffer)=>match reply {Ok((size,source)) if source==backend=>{sender.send(id,&buffer[..size]);},Ok(_)=>{},Err(_)=>break},
                }
            }
        });
        self.handlers
            .lock()
            .expect("prototype handlers")
            .insert(id, Handler { send, task });
        Ok(())
    }
    pub fn enqueue(&self, id: u64, bytes: Bytes) {
        let handlers = self.handlers.lock().expect("prototype handlers");
        let Some(handler) = handlers.get(&id) else {
            self.counters.unknown.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let Ok(permit) = self.budget.clone().try_acquire_owned() else {
            self.counters.queue_full.fetch_add(1, Ordering::Relaxed);
            return;
        };
        match handler.send.try_send(Packet {
            bytes,
            _permit: permit,
        }) {
            Ok(()) => {
                self.counters.delivered.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.counters.queue_full.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn retire(&self, id: u64) {
        self.handlers
            .lock()
            .expect("prototype handlers")
            .remove(&id);
    }
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.handlers.lock().expect("prototype handlers").clear();
    }
}
pub(super) async fn consume(mut read: Read, contexts: Arc<ClientContexts>) -> Result<()> {
    let result: Result<()> = async {
        while let Some((kind, id)) = read_record(&mut read).await? {
            match kind {
                REGISTER => contexts.register(id).await?,
                RETIRE => contexts.retire(id),
                WITHDRAW => {
                    contexts.close();
                    return Ok(());
                }
                _ => return Err("unknown prototype control record".into()),
            }
        }
        Ok(())
    }
    .await;
    contexts.close();
    result
}
