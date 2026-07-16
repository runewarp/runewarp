use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use tokio::io::{AsyncRead, AsyncReadExt};

pub const MAX_PROXY_V2_HEADER_LEN: usize = 16 * 1024;
const SIGNATURE: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyProtocolVersion {
    V2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VisitorTcpAddresses {
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

impl VisitorTcpAddresses {
    pub fn from_socket(stream: &tokio::net::TcpStream) -> std::io::Result<Self> {
        Ok(Self {
            source: stream.peer_addr()?,
            destination: stream.local_addr()?,
        })
    }

    pub fn encode_proxy_v2(self) -> Vec<u8> {
        let mut output = Vec::with_capacity(52);
        output.extend_from_slice(&SIGNATURE);
        output.push(0x21);
        match (self.source, self.destination) {
            (SocketAddr::V4(source), SocketAddr::V4(destination)) => {
                output.push(0x11);
                output.extend_from_slice(&12_u16.to_be_bytes());
                output.extend_from_slice(&source.ip().octets());
                output.extend_from_slice(&destination.ip().octets());
                output.extend_from_slice(&source.port().to_be_bytes());
                output.extend_from_slice(&destination.port().to_be_bytes());
            }
            (SocketAddr::V6(source), SocketAddr::V6(destination)) => {
                output.push(0x21);
                output.extend_from_slice(&36_u16.to_be_bytes());
                output.extend_from_slice(&source.ip().octets());
                output.extend_from_slice(&destination.ip().octets());
                output.extend_from_slice(&source.port().to_be_bytes());
                output.extend_from_slice(&destination.port().to_be_bytes());
            }
            _ => unreachable!("TCP socket source and destination families must match"),
        }
        output
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedNetwork {
    network: IpAddr,
    prefix: u8,
}

impl TrustedNetwork {
    pub fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }
}

impl FromStr for TrustedNetwork {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = value.split_once('/').ok_or("must use CIDR notation")?;
        let network = address
            .parse::<IpAddr>()
            .map_err(|_| "contains an invalid IP address")?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| "contains an invalid prefix")?;
        let maximum = if network.is_ipv4() { 32 } else { 128 };
        if prefix > maximum {
            return Err("contains an invalid prefix");
        }
        let is_canonical = match network {
            IpAddr::V4(network) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                u32::from(network) & mask == u32::from(network)
            }
            IpAddr::V6(network) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                u128::from(network) & mask == u128::from(network)
            }
        };
        if !is_canonical {
            return Err("must use a canonical network address");
        }
        Ok(Self { network, prefix })
    }
}

#[derive(Debug)]
pub enum ProxyV2Error {
    Io(std::io::Error),
    Invalid(&'static str),
}

impl fmt::Display for ProxyV2Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(
                formatter,
                "failed to read PROXY protocol v2 header: {error}"
            ),
            Self::Invalid(reason) => {
                write!(formatter, "invalid PROXY protocol v2 header: {reason}")
            }
        }
    }
}

impl std::error::Error for ProxyV2Error {}

impl From<std::io::Error> for ProxyV2Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub async fn read_proxy_v2<R>(reader: &mut R) -> Result<VisitorTcpAddresses, ProxyV2Error>
where
    R: AsyncRead + Unpin,
{
    let mut fixed = [0_u8; 16];
    reader.read_exact(&mut fixed).await?;
    if fixed[..12] != SIGNATURE {
        return Err(ProxyV2Error::Invalid("signature mismatch"));
    }
    if fixed[12] != 0x21 {
        return Err(ProxyV2Error::Invalid("only the PROXY command is supported"));
    }
    let payload_len = u16::from_be_bytes([fixed[14], fixed[15]]) as usize;
    if 16 + payload_len > MAX_PROXY_V2_HEADER_LEN {
        return Err(ProxyV2Error::Invalid("header exceeds the 16 KiB limit"));
    }
    let required = match fixed[13] {
        0x11 => 12,
        0x21 => 36,
        _ => {
            return Err(ProxyV2Error::Invalid(
                "only TCP over IPv4 or IPv6 is supported",
            ));
        }
    };
    if payload_len < required {
        return Err(ProxyV2Error::Invalid("address payload is truncated"));
    }
    let mut payload = vec![0_u8; payload_len];
    reader.read_exact(&mut payload).await?;
    let addresses = if fixed[13] == 0x11 {
        VisitorTcpAddresses {
            source: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(
                    payload[0], payload[1], payload[2], payload[3],
                )),
                u16::from_be_bytes([payload[8], payload[9]]),
            ),
            destination: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(
                    payload[4], payload[5], payload[6], payload[7],
                )),
                u16::from_be_bytes([payload[10], payload[11]]),
            ),
        }
    } else {
        let source = <[u8; 16]>::try_from(&payload[0..16]).expect("validated IPv6 payload");
        let destination = <[u8; 16]>::try_from(&payload[16..32]).expect("validated IPv6 payload");
        VisitorTcpAddresses {
            source: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(source)),
                u16::from_be_bytes([payload[32], payload[33]]),
            ),
            destination: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(destination)),
                u16::from_be_bytes([payload[34], payload[35]]),
            ),
        }
    };
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trips_ipv4_and_ignores_tlvs() {
        let expected = VisitorTcpAddresses {
            source: "192.0.2.1:1234".parse().unwrap(),
            destination: "198.51.100.2:443".parse().unwrap(),
        };
        let mut bytes = expected.encode_proxy_v2();
        bytes[14..16].copy_from_slice(&15_u16.to_be_bytes());
        bytes.extend_from_slice(&[0x01, 0x00, 0x00]);
        assert_eq!(
            read_proxy_v2(&mut bytes.as_slice()).await.unwrap(),
            expected
        );
    }

    #[tokio::test]
    async fn rejects_local_udp_and_oversized_headers() {
        let addresses = VisitorTcpAddresses {
            source: "192.0.2.1:1234".parse().unwrap(),
            destination: "198.51.100.2:443".parse().unwrap(),
        };

        let mut local = addresses.encode_proxy_v2();
        local[12] = 0x20;
        assert!(read_proxy_v2(&mut local.as_slice()).await.is_err());

        let mut udp = addresses.encode_proxy_v2();
        udp[13] = 0x12;
        assert!(read_proxy_v2(&mut udp.as_slice()).await.is_err());

        let mut oversized = addresses.encode_proxy_v2();
        oversized[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(read_proxy_v2(&mut oversized.as_slice()).await.is_err());
    }

    #[tokio::test]
    async fn rejects_missing_and_malformed_headers() {
        assert!(read_proxy_v2(&mut [].as_slice()).await.is_err());
        let mut malformed = vec![0_u8; 16];
        malformed[12] = 0x21;
        malformed[13] = 0x11;
        malformed[14..16].copy_from_slice(&12_u16.to_be_bytes());
        assert!(read_proxy_v2(&mut malformed.as_slice()).await.is_err());
    }

    #[test]
    fn cidr_membership_requires_matching_family_and_prefix() {
        let network: TrustedNetwork = "10.0.0.0/8".parse().unwrap();
        assert!(network.contains("10.1.2.3".parse().unwrap()));
        assert!(!network.contains("11.1.2.3".parse().unwrap()));
        assert!("10.0.0.1".parse::<TrustedNetwork>().is_err());
    }

    #[test]
    fn cidr_networks_require_canonical_network_addresses() {
        assert!("10.0.0.1/8".parse::<TrustedNetwork>().is_err());
        assert!("2001:db8::1/32".parse::<TrustedNetwork>().is_err());
        assert!("192.0.2.1/32".parse::<TrustedNetwork>().is_ok());
        assert!("2001:db8::1/128".parse::<TrustedNetwork>().is_ok());
    }
}
