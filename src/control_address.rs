use std::fmt;

use crate::{ServerHostname, ServerHostnameError};

pub(crate) const DEFAULT_CONTROL_PORT: u16 = 443;

/// Control endpoint address: a DNS hostname with an optional port.
///
/// HTTPS is mandatory and inferred; schemes, paths, and IP literals are rejected.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ControlAddress {
    hostname: ServerHostname,
    port: u16,
}

impl ControlAddress {
    pub fn parse(value: &str) -> Result<Self, ControlAddressError> {
        if value.contains("://") {
            return Err(ControlAddressError::Scheme);
        }
        if value.contains('/') {
            return Err(ControlAddressError::Path);
        }

        let (raw_hostname, port) = match value.rsplit_once(':') {
            Some((hostname, raw_port)) => {
                let port = raw_port
                    .parse::<u16>()
                    .map_err(|_| ControlAddressError::InvalidPort)?;
                (hostname, port)
            }
            None => (value, DEFAULT_CONTROL_PORT),
        };

        if raw_hostname.is_empty() {
            return Err(ControlAddressError::MissingHostname);
        }

        let hostname =
            ServerHostname::try_from(raw_hostname).map_err(ControlAddressError::InvalidHostname)?;
        if port == 0 {
            return Err(ControlAddressError::InvalidPort);
        }
        Ok(Self { hostname, port })
    }

    pub fn hostname(&self) -> &ServerHostname {
        &self.hostname
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for ControlAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.port == DEFAULT_CONTROL_PORT {
            write!(formatter, "{}", self.hostname)
        } else {
            write!(formatter, "{}:{}", self.hostname, self.port)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlAddressError {
    MissingHostname,
    InvalidPort,
    Scheme,
    Path,
    InvalidHostname(ServerHostnameError),
}

impl fmt::Display for ControlAddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHostname => formatter.write_str("hostname must not be empty"),
            Self::InvalidPort => formatter.write_str("port must be a valid u16"),
            Self::Scheme => formatter.write_str(
                "control address must be a DNS hostname with an optional port, not a URL with a scheme",
            ),
            Self::Path => formatter.write_str(
                "control address must be a DNS hostname with an optional port, without a path",
            ),
            Self::InvalidHostname(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ControlAddressError {}

#[cfg(test)]
mod tests {
    use super::{ControlAddress, ControlAddressError, DEFAULT_CONTROL_PORT};
    use crate::PublicHostnameError;

    #[test]
    fn parses_hostname_and_defaults_to_port_443() {
        let address = ControlAddress::parse("control.example.test").unwrap();
        assert_eq!(address.hostname().as_str(), "control.example.test");
        assert_eq!(address.port(), DEFAULT_CONTROL_PORT);
        assert_eq!(address.to_string(), "control.example.test");
    }

    #[test]
    fn parses_hostname_with_explicit_port() {
        let address = ControlAddress::parse("Control.Example.Test.:8443").unwrap();
        assert_eq!(address.hostname().as_str(), "control.example.test");
        assert_eq!(address.port(), 8443);
        assert_eq!(address.to_string(), "control.example.test:8443");
    }

    #[test]
    fn rejects_schemes() {
        assert_eq!(
            ControlAddress::parse("https://control.example.test").unwrap_err(),
            ControlAddressError::Scheme
        );
    }

    #[test]
    fn rejects_paths() {
        assert_eq!(
            ControlAddress::parse("control.example.test/v1").unwrap_err(),
            ControlAddressError::Path
        );
    }

    #[test]
    fn rejects_ip_literals() {
        assert_eq!(
            ControlAddress::parse("127.0.0.1").unwrap_err(),
            ControlAddressError::InvalidHostname(PublicHostnameError::IpLiteral)
        );
    }

    #[test]
    fn rejects_empty_hostname_before_port() {
        assert_eq!(
            ControlAddress::parse(":443").unwrap_err(),
            ControlAddressError::MissingHostname
        );
    }

    #[test]
    fn rejects_port_zero() {
        assert_eq!(
            ControlAddress::parse("control.example.test:0").unwrap_err(),
            ControlAddressError::InvalidPort
        );
    }
}
