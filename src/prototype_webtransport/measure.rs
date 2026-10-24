//! Directional loopback timings. This deliberately is not a benchmark framework.
use super::{Result, SERVER, STEP, experiment::pair, fixture::Fixture};
use crate::{
    ServerHostname,
    tunnel_h3::{ClientTunnelH3, ServerRuntimeGeneration, ServerTunnelH3},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

fn payload(index: usize) -> Vec<u8> {
    let mut bytes = b"PROXYv2+ClientHello".to_vec();
    bytes.extend_from_slice(&(index as u64).to_be_bytes());
    bytes
}
async fn send(stream: &mut (impl AsyncWrite + Unpin), index: usize) -> Result<()> {
    stream.write_all(&payload(index)).await?;
    stream.flush().await?;
    Ok(())
}
async fn receive(stream: &mut (impl AsyncRead + Unpin), count: usize) -> Result<(usize, Instant)> {
    let mut bytes = [0u8; 27];
    stream.read_exact(&mut bytes).await?;
    assert_eq!(&bytes[..19], b"PROXYv2+ClientHello");
    let index = u64::from_be_bytes(bytes[19..].try_into().expect("eight bytes")) as usize;
    assert!(index < count);
    Ok((index, Instant::now()))
}
fn report(
    carrier: &str,
    count: usize,
    starts: Vec<Instant>,
    placed: Vec<Instant>,
    mut received: Vec<(usize, Instant)>,
) {
    let last = received
        .iter()
        .map(|(_, time)| *time)
        .max()
        .expect("nonempty");
    received.sort_unstable_by_key(|(index, _)| *index);
    for (expected, (index, _)) in received.iter().enumerate() {
        assert_eq!(expected, *index);
    }
    let received: Vec<_> = received.into_iter().map(|(_, time)| time).collect();
    let percentile = |mut values: Vec<u128>, percent: usize| {
        values.sort_unstable();
        values[(values.len() - 1) * percent / 100]
    };
    let placement: Vec<_> = placed
        .iter()
        .zip(&starts)
        .map(|(end, start)| end.duration_since(*start).as_micros())
        .collect();
    let delivery: Vec<_> = received
        .iter()
        .zip(&starts)
        .map(|(end, start)| end.duration_since(*start).as_micros())
        .collect();
    println!(
        "TIMING {carrier} n={count} placement_us_p50={} p95={} delivery_us_p50={} p95={} burst_us={}",
        percentile(placement.clone(), 50),
        percentile(placement, 95),
        percentile(delivery.clone(), 50),
        percentile(delivery, 95),
        last.duration_since(starts[0]).as_micros()
    );
}
pub(super) async fn wt(count: usize) -> Result<()> {
    let (_fixture, server, mut client) = pair(128).await?;
    let sending = async {
        let mut streams = Vec::new();
        let mut starts = Vec::new();
        let mut placed = Vec::new();
        for index in 0..count {
            starts.push(Instant::now());
            let mut stream = server.open().await?;
            send(&mut stream, index).await?;
            placed.push(Instant::now());
            streams.push(stream);
        }
        Ok::<_, super::Error>((streams, starts, placed))
    };
    let receiving = async {
        let mut streams = Vec::new();
        let mut received = Vec::new();
        for _ in 0..count {
            let mut stream = client.accept().await?;
            received.push(receive(&mut stream, count).await?);
            streams.push(stream);
        }
        Ok::<_, super::Error>((streams, received))
    };
    let ((streams, starts, placed), (peers, received)) = tokio::try_join!(sending, receiving)?;
    report("webtransport", count, starts, placed, received);
    drop((streams, peers));
    Ok(())
}
async fn slots(count: usize) -> Result<()> {
    let fixture = Fixture::new(0, true)?;
    let (server, client) = fixture.connect().await?;
    let hostname = ServerHostname::try_from(SERVER).expect("fixed prototype hostname");
    let (server, client) = tokio::join!(
        ServerTunnelH3::establish(
            server,
            hostname.clone(),
            ServerRuntimeGeneration::generate()
        ),
        ClientTunnelH3::establish(
            client,
            &hostname,
            Arc::new(tokio::sync::Semaphore::new(256))
        )
    );
    let server = server?;
    let mut client = client?;
    // Let the production slot keeper pre-open its 32 idle requests before measurement.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let sending = async {
        let mut streams = Vec::new();
        let mut starts = Vec::new();
        let mut placed = Vec::new();
        for index in 0..count {
            starts.push(Instant::now());
            let mut stream = server.open_tunnel_stream(STEP).await?;
            send(&mut stream, index).await?;
            placed.push(Instant::now());
            streams.push(stream);
        }
        Ok::<_, super::Error>((streams, starts, placed))
    };
    let receiving = async {
        let mut streams = Vec::new();
        let mut received = Vec::new();
        for _ in 0..count {
            let mut stream = client.accept_tunnel_stream().await.ok_or("slots ended")?;
            received.push(receive(&mut stream, count).await?);
            streams.push(stream);
        }
        Ok::<_, super::Error>((streams, received))
    };
    let ((streams, starts, placed), (peers, received)) = tokio::try_join!(sending, receiving)?;
    report("receive-slots", count, starts, placed, received);
    drop((streams, peers));
    Ok(())
}
pub(super) async fn run() -> Result<()> {
    for _ in 0..3 {
        for count in [1, 32, 64, 128] {
            tokio::time::timeout(STEP, slots(count)).await??;
            tokio::time::timeout(STEP, wt(count)).await??;
        }
    }
    Ok(())
}
