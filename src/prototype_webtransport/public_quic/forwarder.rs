//! Controlled outer-path delay/loss, never an inner-packet retransmission mechanism.
use super::Result;
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    task::JoinHandle,
    time::{Instant, sleep_until},
};
pub(super) struct Forwarder {
    pub address: SocketAddr,
    pub packets: Arc<AtomicU64>,
    pub dropped: Arc<AtomicU64>,
    task: JoinHandle<()>,
}
impl Forwarder {
    pub async fn new(server: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let address = socket.local_addr()?;
        let packets = Arc::new(AtomicU64::new(0));
        let dropped = Arc::new(AtomicU64::new(0));
        let count = packets.clone();
        let drop_count = dropped.clone();
        let task = tokio::spawn(async move {
            let mut client = None;
            let mut buffer = vec![0; 65536];
            let mut waiting = VecDeque::new();
            loop {
                let next = waiting
                    .front()
                    .map(|(at, _, _): &(Instant, Vec<u8>, SocketAddr)| *at);
                tokio::select! {
                    incoming=socket.recv_from(&mut buffer)=>{
                        let Ok((size,source))=incoming else{break;};
                        let target=if source==server{let Some(address)=client else{continue;};address}else{if client.is_some_and(|address|source!=address){continue;}client=Some(source);server};
                        let number=count.fetch_add(1,Ordering::Relaxed)+1;
                        if number.is_multiple_of(33) || waiting.len()>=128{drop_count.fetch_add(1,Ordering::Relaxed);continue;}
                        waiting.push_back((Instant::now()+Duration::from_millis(3),buffer[..size].to_vec(),target));
                    }
                    _=async{if let Some(at)=next{sleep_until(at).await;}else{std::future::pending::<()>().await;}}=>{
                        if let Some((_,bytes,target))=waiting.pop_front(){let _=socket.send_to(&bytes,target).await;}
                    }
                }
            }
        });
        Ok(Self {
            address,
            packets,
            dropped,
            task,
        })
    }
}
impl Drop for Forwarder {
    fn drop(&mut self) {
        self.task.abort();
    }
}
