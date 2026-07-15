//! Role-specific Managed-session snapshot input validation.
//!
//! Protocol JSON uses snake_case plural fields only. Validation reuses the same
//! Public-hostname, Client-identity, and Server-address normalization rules as
//! static configuration, while permitting an empty overall collection.

use std::collections::HashSet;
use std::fmt;

use serde::Deserialize;
use serde_json::Value;

use super::limits::{ManagedSessionLimitKind, ManagedSessionLimits};

use crate::config::ServerTunnelConfig;
use crate::{ClientIdentity, PublicHostname, ServerAddress, TunnelId};

/// Validated Server role input from a Managed-session snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerManagedInput {
    pub tunnels: Vec<ServerTunnelConfig>,
}

/// Validated Client role input from a Managed-session snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientManagedInput {
    pub server_addresses: Vec<ServerAddress>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InputError {
    MissingTunnels,
    MissingServerAddresses,
    InvalidShape(String),
    LimitExceeded {
        limit: ManagedSessionLimitKind,
        value: usize,
        max: usize,
    },
}

impl fmt::Display for InputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingTunnels => formatter.write_str("server input omitted tunnels"),
            Self::MissingServerAddresses => {
                formatter.write_str("client input omitted server_addresses")
            }
            Self::InvalidShape(message) => formatter.write_str(message),
            Self::LimitExceeded { limit, value, max } => write!(
                formatter,
                "input {} limit exceeded: value={value} max={max}",
                limit.as_str()
            ),
        }
    }
}

impl std::error::Error for InputError {}

#[derive(Debug, Deserialize)]
struct RawServerInput {
    tunnels: Option<Vec<RawServerTunnel>>,
}

#[derive(Debug, Deserialize)]
struct RawServerTunnel {
    id: Option<String>,
    public_hostnames: Option<Vec<String>>,
    client_identities: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct RawClientInput {
    server_addresses: Option<Vec<String>>,
}

fn limit_exceeded(limit: ManagedSessionLimitKind, value: usize, max: usize) -> InputError {
    InputError::LimitExceeded { limit, value, max }
}

/// Parse and validate Server snapshot `input`.
pub fn parse_server_input(
    input: Value,
    limits: &ManagedSessionLimits,
) -> Result<ServerManagedInput, InputError> {
    match input.get("tunnels") {
        None => return Err(InputError::MissingTunnels),
        Some(Value::Array(tunnels)) if tunnels.len() > limits.max_tunnels => {
            return Err(limit_exceeded(
                ManagedSessionLimitKind::Tunnels,
                tunnels.len(),
                limits.max_tunnels,
            ));
        }
        Some(Value::Array(_)) => {}
        Some(_) => {
            return Err(InputError::InvalidShape(
                "server input was not a JSON object with tunnel entries".into(),
            ));
        }
    }

    let raw: RawServerInput = serde_json::from_value(input).map_err(|_| {
        InputError::InvalidShape("server input was not a JSON object with tunnel entries".into())
    })?;
    let Some(raw_tunnels) = raw.tunnels else {
        return Err(InputError::MissingTunnels);
    };

    let mut tunnels = Vec::with_capacity(raw_tunnels.len());
    let mut total_public_hostnames = 0usize;
    let mut total_client_identities = 0usize;
    for (index, tunnel) in raw_tunnels.into_iter().enumerate() {
        tunnels.push(parse_server_tunnel(
            index,
            tunnel,
            limits,
            &mut total_public_hostnames,
            &mut total_client_identities,
        )?);
    }

    validate_unique_tunnel_ids(&tunnels)?;
    validate_unique_public_hostnames(&tunnels)?;
    validate_unique_client_identities(&tunnels)?;

    Ok(ServerManagedInput { tunnels })
}

/// Parse and validate Client snapshot `input`.
pub fn parse_client_input(
    input: Value,
    limits: &ManagedSessionLimits,
) -> Result<ClientManagedInput, InputError> {
    match input.get("server_addresses") {
        None => return Err(InputError::MissingServerAddresses),
        Some(Value::Array(addresses)) if addresses.len() > limits.max_server_addresses => {
            return Err(limit_exceeded(
                ManagedSessionLimitKind::ServerAddresses,
                addresses.len(),
                limits.max_server_addresses,
            ));
        }
        Some(Value::Array(_)) => {}
        Some(_) => {
            return Err(InputError::InvalidShape(
                "client input was not a JSON object with server_addresses".into(),
            ));
        }
    }

    let raw: RawClientInput = serde_json::from_value(input).map_err(|_| {
        InputError::InvalidShape("client input was not a JSON object with server_addresses".into())
    })?;
    let Some(raw_addresses) = raw.server_addresses else {
        return Err(InputError::MissingServerAddresses);
    };

    let mut server_addresses = Vec::with_capacity(raw_addresses.len());
    for (index, address) in raw_addresses.into_iter().enumerate() {
        let parsed = ServerAddress::parse(&address).map_err(|error| {
            InputError::InvalidShape(format!(
                "server_addresses[{index}] is invalid `{address}`: {error}"
            ))
        })?;
        server_addresses.push(parsed);
    }

    validate_unique_server_addresses(&server_addresses)?;
    Ok(ClientManagedInput { server_addresses })
}

fn parse_server_tunnel(
    index: usize,
    tunnel: RawServerTunnel,
    limits: &ManagedSessionLimits,
    total_public_hostnames: &mut usize,
    total_client_identities: &mut usize,
) -> Result<ServerTunnelConfig, InputError> {
    let Some(raw_id) = tunnel.id else {
        return Err(InputError::InvalidShape(format!(
            "tunnels[{index}] omitted id"
        )));
    };
    let id = TunnelId::parse(&raw_id).map_err(|error| {
        InputError::InvalidShape(format!(
            "tunnels[{index}].id is invalid `{raw_id}`: {error}"
        ))
    })?;

    let Some(raw_hostnames) = tunnel.public_hostnames else {
        return Err(InputError::InvalidShape(format!(
            "tunnels[{index}] omitted public_hostnames"
        )));
    };
    if raw_hostnames.is_empty() {
        return Err(InputError::InvalidShape(format!(
            "tunnels[{index}].public_hostnames must not be empty"
        )));
    }

    let Some(raw_identities) = tunnel.client_identities else {
        return Err(InputError::InvalidShape(format!(
            "tunnels[{index}] omitted client_identities"
        )));
    };
    if raw_identities.is_empty() {
        return Err(InputError::InvalidShape(format!(
            "tunnels[{index}].client_identities must not be empty"
        )));
    }

    if raw_hostnames.len() > limits.max_public_hostnames_per_tunnel {
        return Err(limit_exceeded(
            ManagedSessionLimitKind::PublicHostnamesPerTunnel,
            raw_hostnames.len(),
            limits.max_public_hostnames_per_tunnel,
        ));
    }
    if raw_identities.len() > limits.max_client_identities_per_tunnel {
        return Err(limit_exceeded(
            ManagedSessionLimitKind::ClientIdentitiesPerTunnel,
            raw_identities.len(),
            limits.max_client_identities_per_tunnel,
        ));
    }

    let new_public_hostnames_total = total_public_hostnames.saturating_add(raw_hostnames.len());
    if new_public_hostnames_total > limits.max_public_hostnames_total {
        return Err(limit_exceeded(
            ManagedSessionLimitKind::PublicHostnamesTotal,
            new_public_hostnames_total,
            limits.max_public_hostnames_total,
        ));
    }
    let new_client_identities_total = total_client_identities.saturating_add(raw_identities.len());
    if new_client_identities_total > limits.max_client_identities_total {
        return Err(limit_exceeded(
            ManagedSessionLimitKind::ClientIdentitiesTotal,
            new_client_identities_total,
            limits.max_client_identities_total,
        ));
    }

    let mut public_hostnames = Vec::with_capacity(raw_hostnames.len());
    for hostname in raw_hostnames {
        let parsed = PublicHostname::try_from(hostname.as_str()).map_err(|error| {
            InputError::InvalidShape(format!(
                "tunnels[{index}].public_hostnames contains invalid hostname `{hostname}`: {error}"
            ))
        })?;
        public_hostnames.push(parsed);
    }

    let mut authorized_client_identities = Vec::with_capacity(raw_identities.len());
    for identity in raw_identities {
        let parsed = identity.parse::<ClientIdentity>().map_err(|error| {
            InputError::InvalidShape(format!(
                "tunnels[{index}].client_identities contains invalid identity `{identity}`: {error}"
            ))
        })?;
        authorized_client_identities.push(parsed);
    }

    *total_public_hostnames = new_public_hostnames_total;
    *total_client_identities = new_client_identities_total;

    Ok(ServerTunnelConfig {
        id: Some(id),
        public_hostnames,
        authorized_client_identities,
    })
}

fn validate_unique_tunnel_ids(tunnels: &[ServerTunnelConfig]) -> Result<(), InputError> {
    let mut seen = HashSet::new();
    for tunnel in tunnels {
        let Some(id) = tunnel.id.as_ref() else {
            return Err(InputError::InvalidShape(
                "managed tunnels must include an id".into(),
            ));
        };
        if !seen.insert(id.clone()) {
            return Err(InputError::InvalidShape(format!(
                "tunnel ids must be unique across all tunnels: {id}"
            )));
        }
    }
    Ok(())
}

fn validate_unique_public_hostnames(tunnels: &[ServerTunnelConfig]) -> Result<(), InputError> {
    let mut seen = HashSet::new();
    for tunnel in tunnels {
        for hostname in &tunnel.public_hostnames {
            if !seen.insert(hostname.clone()) {
                return Err(InputError::InvalidShape(format!(
                    "public_hostnames must be unique after normalization: {hostname}"
                )));
            }
        }
    }
    Ok(())
}

fn validate_unique_client_identities(tunnels: &[ServerTunnelConfig]) -> Result<(), InputError> {
    let mut seen = HashSet::new();
    for tunnel in tunnels {
        for identity in &tunnel.authorized_client_identities {
            let rendered = identity.to_string();
            if !seen.insert(rendered.clone()) {
                return Err(InputError::InvalidShape(format!(
                    "client_identities must be unique across all tunnels: {rendered}"
                )));
            }
        }
    }
    Ok(())
}

fn validate_unique_server_addresses(addresses: &[ServerAddress]) -> Result<(), InputError> {
    let mut seen = HashSet::new();
    for address in addresses {
        let rendered = format!("{}:{}", address.hostname().as_str(), address.port());
        if !seen.insert(rendered.clone()) {
            return Err(InputError::InvalidShape(format!(
                "server_addresses contains duplicate Server address `{rendered}`"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        ClientManagedInput, InputError, ServerManagedInput, parse_client_input, parse_server_input,
    };
    use crate::managed_session::limits::{ManagedSessionLimitKind, ManagedSessionLimits};
    use crate::{ClientIdentity, PublicHostname, ServerAddress, ServerTunnelConfig, TunnelId};

    const IDENTITY_A: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const IDENTITY_B: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn default_limits() -> ManagedSessionLimits {
        ManagedSessionLimits::default()
    }

    fn two_tunnel_json() -> serde_json::Value {
        json!({
            "tunnels": [
                {
                    "id": "t1",
                    "public_hostnames": ["app.example.test"],
                    "client_identities": [IDENTITY_A],
                },
                {
                    "id": "t2",
                    "public_hostnames": ["api.example.test"],
                    "client_identities": [IDENTITY_B],
                },
            ]
        })
    }

    #[test]
    fn server_input_accepts_empty_tunnels() {
        let input = parse_server_input(json!({"tunnels": []}), &default_limits()).unwrap();
        assert_eq!(input, ServerManagedInput { tunnels: vec![] });
    }

    #[test]
    fn server_input_accepts_plural_fields_and_normalizes_hostnames() {
        let input = parse_server_input(
            json!({
                "tunnels": [{
                    "id": "tunnel-a",
                    "public_hostnames": ["App.Example.Test."],
                    "client_identities": [IDENTITY_A],
                    "ignored": true
                }]
            }),
            &default_limits(),
        )
        .unwrap();
        assert_eq!(
            input,
            ServerManagedInput {
                tunnels: vec![ServerTunnelConfig {
                    id: Some(TunnelId::parse("tunnel-a").unwrap()),
                    public_hostnames: vec![PublicHostname::try_from("app.example.test").unwrap()],
                    authorized_client_identities: vec![
                        IDENTITY_A.parse::<ClientIdentity>().unwrap()
                    ],
                }]
            }
        );
    }

    #[test]
    fn server_input_rejects_missing_or_empty_entry_collections() {
        assert_eq!(
            parse_server_input(json!({}), &default_limits()).unwrap_err(),
            InputError::MissingTunnels
        );
        assert!(matches!(
            parse_server_input(
                json!({
                    "tunnels": [{"public_hostnames": ["app.example.test"], "client_identities": [IDENTITY_A]}]
                }),
                &default_limits(),
            )
            .unwrap_err(),
            InputError::InvalidShape(message) if message.contains("omitted id")
        ));
        assert!(matches!(
            parse_server_input(
                json!({
                    "tunnels": [{"id": "t1", "client_identities": [IDENTITY_A]}]
                }),
                &default_limits(),
            )
            .unwrap_err(),
            InputError::InvalidShape(message) if message.contains("public_hostnames")
        ));
        assert!(matches!(
            parse_server_input(
                json!({
                    "tunnels": [{"id": "t1", "public_hostnames": ["app.example.test"]}]
                }),
                &default_limits(),
            )
            .unwrap_err(),
            InputError::InvalidShape(message) if message.contains("client_identities")
        ));
        assert!(matches!(
            parse_server_input(
                json!({
                    "tunnels": [{"id": "t1", "public_hostnames": [], "client_identities": [IDENTITY_A]}]
                }),
                &default_limits(),
            )
            .unwrap_err(),
            InputError::InvalidShape(message) if message.contains("public_hostnames must not be empty")
        ));
        assert!(matches!(
            parse_server_input(
                json!({
                    "tunnels": [{"id": "t1", "public_hostnames": ["app.example.test"], "client_identities": []}]
                }),
                &default_limits(),
            )
            .unwrap_err(),
            InputError::InvalidShape(message) if message.contains("client_identities must not be empty")
        ));
    }

    #[test]
    fn server_input_rejects_invalid_and_duplicate_tunnel_ids() {
        assert!(matches!(
            parse_server_input(
                json!({
                    "tunnels": [{
                        "id": "bad id",
                        "public_hostnames": ["app.example.test"],
                        "client_identities": [IDENTITY_A]
                    }]
                }),
                &default_limits(),
            )
            .unwrap_err(),
            InputError::InvalidShape(message) if message.contains("id is invalid")
        ));
        assert!(matches!(
            parse_server_input(
                json!({
                    "tunnels": [
                        {
                            "id": "same",
                            "public_hostnames": ["app.example.test"],
                            "client_identities": [IDENTITY_A]
                        },
                        {
                            "id": "same",
                            "public_hostnames": ["api.example.test"],
                            "client_identities": [IDENTITY_B]
                        }
                    ]
                }),
                &default_limits(),
            )
            .unwrap_err(),
            InputError::InvalidShape(message) if message.contains("tunnel ids must be unique")
        ));
    }

    #[test]
    fn server_input_rejects_duplicate_hostnames_and_identities() {
        assert!(matches!(
            parse_server_input(
                json!({
                    "tunnels": [
                        {
                            "id": "t1",
                            "public_hostnames": ["app.example.test"],
                            "client_identities": [IDENTITY_A]
                        },
                        {
                            "id": "t2",
                            "public_hostnames": ["App.Example.Test."],
                            "client_identities": [IDENTITY_B]
                        }
                    ]
                }),
                &default_limits(),
            )
            .unwrap_err(),
            InputError::InvalidShape(message) if message.contains("public_hostnames must be unique")
        ));
        assert!(matches!(
            parse_server_input(
                json!({
                    "tunnels": [
                        {
                            "id": "t1",
                            "public_hostnames": ["app.example.test"],
                            "client_identities": [IDENTITY_A]
                        },
                        {
                            "id": "t2",
                            "public_hostnames": ["api.example.test"],
                            "client_identities": [IDENTITY_A]
                        }
                    ]
                }),
                &default_limits(),
            )
            .unwrap_err(),
            InputError::InvalidShape(message) if message.contains("client_identities must be unique")
        ));
    }

    #[test]
    fn server_input_does_not_accept_singular_aliases_as_required_fields() {
        // Singular aliases are not protocol fields; omitting plurals fails closed.
        assert!(matches!(
            parse_server_input(
                json!({
                    "tunnels": [{
                        "id": "t1",
                        "public_hostname": "app.example.test",
                        "client_identity": IDENTITY_A
                    }]
                }),
                &default_limits(),
            )
            .unwrap_err(),
            InputError::InvalidShape(message) if message.contains("public_hostnames")
        ));
    }

    #[test]
    fn server_input_rejects_tunnel_count_over_limit() {
        let limits = ManagedSessionLimits {
            max_tunnels: 1,
            ..default_limits()
        };
        assert_eq!(
            parse_server_input(two_tunnel_json(), &limits).unwrap_err(),
            InputError::LimitExceeded {
                limit: ManagedSessionLimitKind::Tunnels,
                value: 2,
                max: 1,
            }
        );
    }

    #[test]
    fn server_input_rejects_public_hostnames_per_tunnel_over_limit() {
        let limits = ManagedSessionLimits {
            max_public_hostnames_per_tunnel: 1,
            ..default_limits()
        };
        assert_eq!(
            parse_server_input(
                json!({
                    "tunnels": [{
                        "id": "t1",
                        "public_hostnames": ["app.example.test", "api.example.test"],
                        "client_identities": [IDENTITY_A],
                    }]
                }),
                &limits,
            )
            .unwrap_err(),
            InputError::LimitExceeded {
                limit: ManagedSessionLimitKind::PublicHostnamesPerTunnel,
                value: 2,
                max: 1,
            }
        );
    }

    #[test]
    fn server_input_rejects_client_identities_per_tunnel_over_limit() {
        let limits = ManagedSessionLimits {
            max_client_identities_per_tunnel: 1,
            ..default_limits()
        };
        assert_eq!(
            parse_server_input(
                json!({
                    "tunnels": [{
                        "id": "t1",
                        "public_hostnames": ["app.example.test"],
                        "client_identities": [IDENTITY_A, IDENTITY_B],
                    }]
                }),
                &limits,
            )
            .unwrap_err(),
            InputError::LimitExceeded {
                limit: ManagedSessionLimitKind::ClientIdentitiesPerTunnel,
                value: 2,
                max: 1,
            }
        );
    }

    #[test]
    fn server_input_rejects_public_hostnames_total_over_limit() {
        let limits = ManagedSessionLimits {
            max_public_hostnames_total: 1,
            ..default_limits()
        };
        assert_eq!(
            parse_server_input(two_tunnel_json(), &limits).unwrap_err(),
            InputError::LimitExceeded {
                limit: ManagedSessionLimitKind::PublicHostnamesTotal,
                value: 2,
                max: 1,
            }
        );
    }

    #[test]
    fn server_input_rejects_client_identities_total_over_limit() {
        let limits = ManagedSessionLimits {
            max_client_identities_total: 1,
            ..default_limits()
        };
        assert_eq!(
            parse_server_input(two_tunnel_json(), &limits).unwrap_err(),
            InputError::LimitExceeded {
                limit: ManagedSessionLimitKind::ClientIdentitiesTotal,
                value: 2,
                max: 1,
            }
        );
    }

    #[test]
    fn client_input_accepts_empty_server_addresses() {
        let input = parse_client_input(json!({"server_addresses": []}), &default_limits()).unwrap();
        assert_eq!(
            input,
            ClientManagedInput {
                server_addresses: vec![]
            }
        );
    }

    #[test]
    fn client_input_parses_dns_optional_port_and_defaults_to_443() {
        let input = parse_client_input(
            json!({
                "server_addresses": ["Tunnel.Example.Test.", "other.example.test:8443"],
                "ignored": 1
            }),
            &default_limits(),
        )
        .unwrap();
        assert_eq!(
            input.server_addresses,
            vec![
                ServerAddress::parse("tunnel.example.test").unwrap(),
                ServerAddress::parse("other.example.test:8443").unwrap(),
            ]
        );
        assert_eq!(input.server_addresses[0].port(), 443);
    }

    #[test]
    fn client_input_rejects_missing_duplicates_and_invalid_values() {
        assert_eq!(
            parse_client_input(json!({}), &default_limits()).unwrap_err(),
            InputError::MissingServerAddresses
        );
        assert!(matches!(
            parse_client_input(
                json!({
                    "server_addresses": ["tunnel.example.test", "Tunnel.Example.Test."]
                }),
                &default_limits(),
            )
            .unwrap_err(),
            InputError::InvalidShape(message) if message.contains("duplicate")
        ));
        assert!(matches!(
            parse_client_input(
                json!({"server_addresses": ["127.0.0.1"]}),
                &default_limits()
            )
            .unwrap_err(),
            InputError::InvalidShape(_)
        ));
        assert!(matches!(
            parse_client_input(
                json!({"server_addresses": ["https://tunnel.example.test"]}),
                &default_limits(),
            )
            .unwrap_err(),
            InputError::InvalidShape(_)
        ));
    }

    #[test]
    fn client_input_does_not_accept_singular_alias_as_required_field() {
        assert_eq!(
            parse_client_input(
                json!({"server_address": "tunnel.example.test"}),
                &default_limits(),
            )
            .unwrap_err(),
            InputError::MissingServerAddresses
        );
    }

    #[test]
    fn client_input_rejects_server_address_count_over_limit() {
        let limits = ManagedSessionLimits {
            max_server_addresses: 1,
            ..default_limits()
        };
        assert_eq!(
            parse_client_input(
                json!({
                    "server_addresses": ["a.example.test", "b.example.test"]
                }),
                &limits,
            )
            .unwrap_err(),
            InputError::LimitExceeded {
                limit: ManagedSessionLimitKind::ServerAddresses,
                value: 2,
                max: 1,
            }
        );
    }

    #[test]
    fn limit_exceeded_display_includes_kind_and_counts() {
        let error = InputError::LimitExceeded {
            limit: ManagedSessionLimitKind::Tunnels,
            value: 3,
            max: 1,
        };
        assert_eq!(
            error.to_string(),
            "input tunnels limit exceeded: value=3 max=1"
        );
    }
}
