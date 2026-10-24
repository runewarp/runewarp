use super::{Profile, Result, STEP, association, network::Harness};
use std::{
    collections::HashSet,
    sync::Arc,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
};
const CONTEXTS: usize = 8;
const PACKETS: usize = 64;
struct Observation {
    count: usize,
    times: Vec<u128>,
    last: u128,
}
async fn collect(
    socket: Arc<UdpSocket>,
    tag: usize,
    payload: usize,
    epoch: Instant,
) -> Result<Observation> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(1200);
    let mut bytes = vec![0u8; 65536];
    let mut seen = HashSet::new();
    let mut times = Vec::new();
    let mut last = 0;
    while seen.len() < PACKETS {
        let Ok(received) = tokio::time::timeout_at(deadline, socket.recv_from(&mut bytes)).await
        else {
            break;
        };
        let (size, _) = received?;
        assert_eq!(size, payload);
        assert_eq!(
            u64::from_be_bytes(bytes[..8].try_into().expect("tag")),
            tag as u64
        );
        let sequence = u64::from_be_bytes(bytes[8..16].try_into().expect("sequence"));
        assert!(sequence < PACKETS as u64);
        assert!(seen.insert(sequence), "duplicate packet");
        assert!(bytes[24..size].iter().all(|value| *value == tag as u8));
        let sent = u64::from_be_bytes(bytes[16..24].try_into().expect("timestamp"));
        last = epoch.elapsed().as_nanos();
        times.push((last - u128::from(sent)) / 1000);
    }
    Ok(Observation {
        count: seen.len(),
        times,
        last,
    })
}
async fn sample(profile: Profile, payload: usize, impaired: bool, loaded: bool) -> Result<()> {
    let mut h = Harness::new_path(profile, 8, 1280, impaired).await?;
    let mut sockets = Vec::new();
    for _ in 0..CONTEXTS {
        let socket = Arc::new(association::socket().await?);
        h.register(socket.local_addr()?).await?;
        sockets.push(socket);
    }
    let (mut tcp, mut peer) = h.open_tcp().await?;
    let epoch = Instant::now();
    let before = h.path_counts();
    let tcp_size = if loaded { 512 * 1024 } else { 1 };
    let bulk = tokio::spawn(async move {
        let sending = async {
            tcp.write_all(&vec![0xa7; tcp_size]).await?;
            tcp.shutdown().await?;
            Ok::<_, super::Error>(())
        };
        let receiving = async {
            let mut bytes = Vec::new();
            peer.read_to_end(&mut bytes).await?;
            assert_eq!(bytes.len(), tcp_size);
            assert!(bytes.iter().all(|value| *value == 0xa7));
            Ok::<_, super::Error>(())
        };
        tokio::try_join!(sending, receiving)?;
        Ok::<_, super::Error>(epoch.elapsed().as_micros())
    });
    let mut collectors = Vec::new();
    for (tag, socket) in sockets.iter().enumerate() {
        let socket = socket.clone();
        collectors.push(tokio::spawn(collect(socket, tag, payload, epoch)));
    }
    let target = h.ingress.local_addr()?;
    let offering = tokio::spawn(async move {
        for sequence in 0..PACKETS {
            for (tag, socket) in sockets.iter().enumerate() {
                let mut bytes = vec![tag as u8; payload];
                bytes[..8].copy_from_slice(&(tag as u64).to_be_bytes());
                bytes[8..16].copy_from_slice(&(sequence as u64).to_be_bytes());
                bytes[16..24].copy_from_slice(&(epoch.elapsed().as_nanos() as u64).to_be_bytes());
                socket.send_to(&bytes, target).await?;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Ok::<_, super::Error>(())
    });
    let mut put_max = 0;
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let start = Instant::now();
        h.put().await?;
        put_max = put_max.max(start.elapsed().as_micros());
    }
    offering.await??;
    let mut delivered = 0;
    let mut minimum = PACKETS;
    let mut maximum = 0;
    let mut times = Vec::new();
    let mut last = 0;
    for collector in collectors {
        let observed = collector.await??;
        delivered += observed.count;
        minimum = minimum.min(observed.count);
        maximum = maximum.max(observed.count);
        last = last.max(observed.last);
        times.extend(observed.times);
    }
    let tcp_time = tokio::time::timeout(STEP, bulk).await???;
    times.sort_unstable();
    let percentile = |percent: usize| {
        times
            .get(times.len().saturating_sub(1) * percent / 100)
            .copied()
            .unwrap_or(0)
    };
    let goodput = if last > 0 {
        (delivered * payload * 8) as f64 / (last as f64 / 1_000_000_000.0) / 1_000_000.0
    } else {
        0.0
    };
    let after = h.path_counts();
    println!(
        "PACKETS profile={} impaired={} loaded={} payload={} offered={} delivered={} per_context_min={} max={} rtt_us_p50={} p95={} goodput_mbps={:.2} tcp_us={} put_us_max={} path_packets={} path_drops={} server[{}] client[{}]",
        profile.name(),
        impaired,
        loaded,
        payload,
        CONTEXTS * PACKETS,
        delivered,
        minimum,
        maximum,
        percentile(50),
        percentile(95),
        goodput,
        tcp_time,
        put_max,
        after.0 - before.0,
        after.1 - before.1,
        h.send.counters.summary(),
        h.reply.counters.summary()
    );
    assert!(
        delivered > 0 && minimum > 0,
        "every association makes progress"
    );
    assert_eq!(
        h.send.counters.malformed.load(Ordering::Relaxed)
            + h.reply.counters.malformed.load(Ordering::Relaxed),
        0
    );
    Ok(())
}
pub(super) async fn run() -> Result<()> {
    for repeat in 0..2 {
        for impaired in [false, true] {
            for payload in [64, 1200] {
                for offset in 0..3 {
                    let profile = Profile::ALL[(repeat + offset) % 3];
                    tokio::time::timeout(
                        Duration::from_secs(8),
                        sample(profile, payload, impaired, true),
                    )
                    .await??;
                }
            }
        }
        for impaired in [false, true] {
            for offset in 0..3 {
                let profile = Profile::ALL[(repeat + offset) % 3];
                tokio::time::timeout(
                    Duration::from_secs(8),
                    sample(profile, 1200, impaired, false),
                )
                .await??;
            }
        }
    }
    Ok(())
}
