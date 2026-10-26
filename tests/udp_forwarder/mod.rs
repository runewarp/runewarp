//! A UDP forwarder standing in for one Server address in front of replaceable runtimes.
//!
//! Each new Client source address becomes a flow pinned to the target current at its first
//! datagram, like a load balancer with connection affinity. Changing the target moves only new
//! flows, so a candidate on a fresh socket reaches the new runtime while the primary stays put.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;
use tokio::task::{JoinHandle, JoinSet};

pub struct UdpForwarder {
    local_addr: SocketAddr,
    target: Arc<Mutex<SocketAddr>>,
    flows: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl UdpForwarder {
    pub async fn start(bind_addr: SocketAddr, target: SocketAddr) -> Self {
        let listener = Arc::new(UdpSocket::bind(bind_addr).await.unwrap());
        let local_addr = listener.local_addr().unwrap();
        let target = Arc::new(Mutex::new(target));
        let flows = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn({
            let target = Arc::clone(&target);
            let flows = Arc::clone(&flows);
            async move {
                let mut upstreams: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
                // Reply tasks end with this task: a JoinSet aborts them on drop.
                let mut replies = JoinSet::new();
                let mut buffer = vec![0_u8; 65_535];
                while let Ok((length, source)) = listener.recv_from(&mut buffer).await {
                    let upstream = match upstreams.entry(source) {
                        std::collections::hash_map::Entry::Occupied(entry) => {
                            Arc::clone(entry.get())
                        }
                        std::collections::hash_map::Entry::Vacant(entry) => {
                            let destination = *target.lock().unwrap();
                            let loopback: SocketAddr = if destination.is_ipv4() {
                                "127.0.0.1:0".parse().unwrap()
                            } else {
                                "[::1]:0".parse().unwrap()
                            };
                            let upstream = Arc::new(UdpSocket::bind(loopback).await.unwrap());
                            upstream.connect(destination).await.unwrap();
                            flows.fetch_add(1, Ordering::SeqCst);
                            replies.spawn({
                                let upstream = Arc::clone(&upstream);
                                let listener = Arc::clone(&listener);
                                async move {
                                    let mut buffer = vec![0_u8; 65_535];
                                    while let Ok(length) = upstream.recv(&mut buffer).await {
                                        let _ = listener.send_to(&buffer[..length], source).await;
                                    }
                                }
                            });
                            Arc::clone(entry.insert(upstream))
                        }
                    };
                    let _ = upstream.send(&buffer[..length]).await;
                }
            }
        });
        Self {
            local_addr,
            target,
            flows,
            task,
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Send new flows to `target`; existing flows keep theirs.
    #[allow(dead_code)]
    pub fn set_target(&self, target: SocketAddr) {
        *self.target.lock().unwrap() = target;
    }

    /// Number of Client source addresses seen so far: one per connection attempt socket.
    pub fn flows(&self) -> usize {
        self.flows.load(Ordering::SeqCst)
    }
}

impl Drop for UdpForwarder {
    fn drop(&mut self) {
        self.task.abort();
    }
}
