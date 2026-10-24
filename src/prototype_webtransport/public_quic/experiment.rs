use super::{
    Profile, Result, STEP,
    association::{self, ASSOCIATIONS, GLOBAL_PACKETS, PER_CONTEXT},
    network::Harness,
};
use std::{sync::atomic::Ordering, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn echo(harness: &Harness, socket: &tokio::net::UdpSocket, payload: &[u8]) -> Result<()> {
    socket
        .send_to(payload, harness.ingress.local_addr()?)
        .await?;
    let mut reply = vec![0u8; 65536];
    let (n, source) = tokio::time::timeout(STEP, socket.recv_from(&mut reply)).await??;
    assert_eq!(source, harness.ingress.local_addr()?);
    assert_eq!(&reply[..n], payload);
    Ok(())
}
async fn interleaved(profile: Profile) -> Result<()> {
    let mut h = Harness::new(profile, 8, 1280).await?;
    let (mut tcp, mut peer) = h.open_tcp().await?;
    let mut sockets = Vec::new();
    let mut ids = Vec::new();
    for _ in 0..8 {
        let socket = association::socket().await?;
        ids.push(h.register(socket.local_addr()?).await?);
        sockets.push(socket);
    }
    assert_eq!(&ids[..3], &[62, 63, 64]);
    for sequence in 0..4 {
        let size = if sequence % 2 == 0 { 64 } else { 1200 };
        for (index, socket) in sockets.iter().enumerate() {
            let payload = vec![(index * 4 + sequence) as u8; size];
            socket.send_to(&payload, h.ingress.local_addr()?).await?;
        }
        for (index, socket) in sockets.iter().enumerate() {
            let mut payload = vec![0; size + 1];
            let (n, _) = socket.recv_from(&mut payload).await?;
            assert_eq!(n, size);
            assert!(
                payload[..n]
                    .iter()
                    .all(|byte| *byte == (index * 4 + sequence) as u8)
            );
        }
        tcp.write_all(b"TCP while UDP associations interleave")
            .await?;
        tcp.flush().await?;
        let mut bytes = [0u8; 37];
        peer.read_exact(&mut bytes).await?;
        assert_eq!(&bytes, b"TCP while UDP associations interleave");
        h.put().await?;
    }
    h.retire(ids[2]).await?;
    h.retire(ids[2]).await?;
    let before = h.reply.counters.unknown.load(Ordering::Relaxed);
    assert!(h.send.send(ids[2], b"stale"));
    tokio::time::timeout(STEP, async {
        while h.reply.counters.unknown.load(Ordering::Relaxed) == before {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    echo(&h, &sockets[0], b"other association survives").await?;
    tcp.shutdown().await?;
    assert_eq!(
        peer.read_u8().await.err().map(|e| e.kind()),
        Some(std::io::ErrorKind::UnexpectedEof)
    );
    Ok(())
}
async fn lifecycle(profile: Profile) -> Result<()> {
    let mut h = Harness::new(profile, 8, 1280).await?;
    let socket = association::socket().await?;
    h.register(socket.local_addr()?).await?;
    let (mut tcp, mut peer) = h.open_tcp().await?;
    h.withdraw_udp().await?;
    assert_eq!(h.received.count(), 0);
    assert!(h.register(socket.local_addr()?).await.is_err());
    tcp.write_all(b"app-isolated").await?;
    tcp.flush().await?;
    let mut bytes = [0; 12];
    peer.read_exact(&mut bytes).await?;
    assert_eq!(&bytes, b"app-isolated");
    h.put().await?;
    drop(h);
    let mut h = Harness::new(profile, 8, 1280).await?;
    let (mut tcp, mut peer) = h.open_tcp().await?;
    h.close_udp_native().await?;
    if profile == Profile::Unified {
        assert!(peer.read_u8().await.is_err());
        assert!(h.open_server_tcp().await.is_err());
    } else {
        tcp.write_all(b"native-isolated").await?;
        tcp.flush().await?;
        let mut bytes = [0u8; 15];
        peer.read_exact(&mut bytes).await?;
        assert_eq!(&bytes, b"native-isolated");
        let _new = h.open_tcp().await?;
    }
    h.put().await?;
    Ok(())
}
async fn capacity(profile: Profile) -> Result<()> {
    let mut h = Harness::new(profile, 2, 1280).await?;
    let mut sockets = Vec::new();
    let mut ids = Vec::new();
    for _ in 0..ASSOCIATIONS {
        let socket = association::socket().await?;
        ids.push(h.register(socket.local_addr()?).await?);
        sockets.push(socket);
    }
    let extra = association::socket().await?;
    assert!(h.register(extra.local_addr()?).await.is_err());
    h.retire(ids[0]).await?;
    let replacement = h.register(extra.local_addr()?).await?;
    assert!(replacement > *ids.last().expect("contexts"));
    let streams = if profile == Profile::Dedicated { 2 } else { 1 };
    let mut active = Vec::new();
    for _ in 0..streams {
        active.push(h.open_tcp().await?);
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(50), h.open_server_tcp())
            .await
            .is_err()
    );
    echo(&h, &sockets[1], b"UDP with exhausted stream credit").await?;
    h.put().await?;
    // On the current-thread runner no worker can drain between these synchronous enqueues.
    let before = h.reply.counters.queue_full.load(Ordering::Relaxed);
    for _ in 0..100 {
        h.received
            .enqueue(ids[1], bytes::Bytes::from_static(b"hot"));
    }
    assert!(
        h.reply.counters.queue_full.load(Ordering::Relaxed) >= before + 100 - PER_CONTEXT as u64
    );
    h.received
        .enqueue(ids[2], bytes::Bytes::from_static(b"quiet"));
    assert!(h.received.budget.available_permits() < GLOBAL_PACKETS - PER_CONTEXT);
    for id in ids.iter().skip(2) {
        for _ in 0..PER_CONTEXT {
            h.received
                .enqueue(*id, bytes::Bytes::from_static(b"bounded"));
        }
    }
    assert_eq!(h.received.budget.available_permits(), 0);
    drop(active);
    Ok(())
}
async fn mtu(profile: Profile) -> Result<()> {
    let mut low = Harness::new(profile, 4, 1200).await?;
    let socket = association::socket().await?;
    assert!(low.send.payload_limit(64) < 1200);
    assert!(low.register(socket.local_addr()?).await.is_err());
    assert_eq!(low.received.count(), 0);
    let mut h = Harness::new(profile, 4, 1280).await?;
    let id = h.register(socket.local_addr()?).await?;
    assert!(h.send.payload_limit(id) >= 1200);
    echo(&h, &socket, &vec![0xa5; 1200]).await?;
    let limit = h.send.payload_limit(id);
    assert!(!h.send.send(id, &vec![0; limit + 1]));
    assert_eq!(h.send.counters.oversized.load(Ordering::Relaxed), 1);
    Ok(())
}
async fn connection_loss(profile: Profile) -> Result<()> {
    let mut h = Harness::new(profile, 4, 1280).await?;
    let socket = association::socket().await?;
    h.register(socket.local_addr()?).await?;
    let (_tcp, mut peer) = h.open_tcp().await?;
    h.server.close(0x102u32.into(), b"prototype loss");
    h.client.closed().await;
    h.wait_udp_closed().await?;
    assert_eq!(h.received.count(), 0);
    assert!(peer.read_u8().await.is_err());
    Ok(())
}
async fn control_failure(profile: Profile) -> Result<()> {
    let mut h = Harness::new(profile, 4, 1280).await?;
    let socket = association::socket().await?;
    h.register(socket.local_addr()?).await?;
    let (mut tcp, mut peer) = h.open_tcp().await?;
    h.truncate_control().await?;
    h.wait_udp_closed().await?;
    tokio::time::timeout(Duration::from_millis(200), async {
        while !h.contexts.lock().expect("server contexts").withdrawn {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(h.received.count(), 0);
    tcp.write_all(b"control-isolated").await?;
    tcp.flush().await?;
    let mut bytes = [0u8; 16];
    peer.read_exact(&mut bytes).await?;
    assert_eq!(&bytes, b"control-isolated");
    h.put().await?;
    Ok(())
}

async fn routing_guards(profile: Profile) -> Result<()> {
    use super::association::{Counters, PacketSender};
    use std::sync::{Arc, atomic::AtomicBool};
    let mut h = Harness::new(profile, 4, 1280).await?;
    assert!(h.send.send(62, b"before registration"));
    tokio::time::timeout(STEP, async {
        while h.reply.counters.unknown.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(h.received.count(), 0);
    let socket = association::socket().await?;
    let id = h.register(socket.local_addr()?).await?;
    assert_eq!(id, 62);
    let wrong = PacketSender::new(
        h.server.clone(),
        profile.udp_id() + 4,
        Arc::new(AtomicBool::new(false)),
        Arc::new(Counters::default()),
    );
    assert!(wrong.send(id, b"wrong request"));
    tokio::time::timeout(STEP, async {
        while h.reply.counters.wrong_carrier.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let before = h.send.counters.unknown.load(Ordering::Relaxed);
    assert!(h.reply.send(999, b"forged reply"));
    tokio::time::timeout(STEP, async {
        while h.send.counters.unknown.load(Ordering::Relaxed) == before {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    echo(&h, &socket, b"registered association still works").await?;
    Ok(())
}

/// Run the throwaway Public QUIC carrier comparison.
pub async fn run() -> Result<()> {
    for profile in Profile::ALL {
        tokio::time::timeout(STEP, interleaved(profile)).await??;
        println!(
            "PASS {} interleaved UDP contexts + TCP + PUT + idempotent context close",
            profile.name()
        );
        tokio::time::timeout(STEP, lifecycle(profile)).await??;
        println!(
            "PASS {} UDP app withdrawal preserves TCP; native UDP-carrier close TCP_survives={}",
            profile.name(),
            profile != Profile::Unified
        );
        tokio::time::timeout(STEP, capacity(profile)).await??;
        println!(
            "PASS {} context cap={} queues={}/{} stream-credit exhaustion does not stop UDP/PUT",
            profile.name(),
            ASSOCIATIONS,
            PER_CONTEXT,
            GLOBAL_PACKETS
        );
        tokio::time::timeout(STEP, mtu(profile)).await??;
        println!(
            "PASS {} 1200-byte Initial capacity is path gated; oversize has no reliable fallback",
            profile.name()
        );
        tokio::time::timeout(STEP, control_failure(profile)).await??;
        println!(
            "PASS {} truncated UDP control retires both peers while TCP survives",
            profile.name()
        );
        tokio::time::timeout(STEP, routing_guards(profile)).await??;
        println!(
            "PASS {} unknown/stale contexts and wrong request IDs cannot create or redirect associations",
            profile.name()
        );
        tokio::time::timeout(STEP, connection_loss(profile)).await??;
        println!(
            "PASS {} connection loss retires all associations",
            profile.name()
        );
    }
    super::measure::run().await?;
    Ok(())
}
#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn interleaved_udp_associations_share_the_tcp_connection() {
        for profile in super::Profile::ALL {
            tokio::time::timeout(super::STEP, super::interleaved(profile))
                .await
                .expect("deadline")
                .expect("interleaved associations");
        }
    }
    #[tokio::test]
    async fn udp_scope_and_native_carrier_have_distinct_lifetimes() {
        for profile in super::Profile::ALL {
            tokio::time::timeout(super::STEP, super::lifecycle(profile))
                .await
                .expect("deadline")
                .expect("lifecycle");
        }
    }
    #[tokio::test]
    async fn association_queues_and_tcp_credit_are_bounded_independently() {
        for profile in super::Profile::ALL {
            tokio::time::timeout(super::STEP, super::capacity(profile))
                .await
                .expect("deadline")
                .expect("capacity");
        }
    }
    #[tokio::test]
    async fn admission_requires_a_1200_byte_inner_packet() {
        for profile in super::Profile::ALL {
            tokio::time::timeout(super::STEP, super::mtu(profile))
                .await
                .expect("deadline")
                .expect("MTU");
        }
    }
    #[tokio::test]
    async fn connection_loss_retires_every_carrier() {
        for profile in super::Profile::ALL {
            tokio::time::timeout(super::STEP, super::connection_loss(profile))
                .await
                .expect("deadline")
                .expect("loss");
        }
    }
    #[tokio::test]
    async fn truncated_control_retires_udp_on_both_peers_without_stopping_tcp() {
        for profile in super::Profile::ALL {
            tokio::time::timeout(super::STEP, super::control_failure(profile))
                .await
                .expect("deadline")
                .expect("control cleanup");
        }
    }
    #[tokio::test]
    async fn packets_cannot_create_contexts_or_cross_carriers() {
        for profile in super::Profile::ALL {
            tokio::time::timeout(super::STEP, super::routing_guards(profile))
                .await
                .expect("deadline")
                .expect("routing guards");
        }
    }
    #[test]
    fn dedicated_connect_has_a_named_narrow_protocol() {
        assert!(
            "runewarp-prototype-udp"
                .parse::<crate::vendor::h3::ext::Protocol>()
                .is_ok()
        );
    }
}
