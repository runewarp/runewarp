use std::fmt;

use crate::hostname::validate_public_hostname;

pub(crate) const DEFAULT_SERVER_PORT: u16 = 443;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServerAddress {
    hostname: String,
    port: u16,
}

impl ServerAddress {
    pub(crate) fn parse(value: &str) -> Result<Self, ServerAddressError> {
        let (raw_hostname, port) = match value.rsplit_once(':') {
            Some((hostname, raw_port)) => {
                let port = raw_port
                    .parse::<u16>()
                    .map_err(|_| ServerAddressError::InvalidPort)?;
                (hostname, port)
            }
            None => (value, DEFAULT_SERVER_PORT),
        };

        if raw_hostname.is_empty() {
            return Err(ServerAddressError::MissingHostname);
        }

        let hostname =
            validate_public_hostname(raw_hostname).map_err(ServerAddressError::InvalidHostname)?;
        Ok(Self { hostname, port })
    }

    pub(crate) fn hostname(&self) -> &str {
        &self.hostname
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ServerAddressError {
    MissingHostname,
    InvalidPort,
    InvalidHostname(crate::hostname::PublicHostnameError),
}

impl fmt::Display for ServerAddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHostname => formatter.write_str("hostname must not be empty"),
            Self::InvalidPort => formatter.write_str("port must be a valid u16"),
            Self::InvalidHostname(error) => write!(formatter, "{error}"),
        }
    }
}
