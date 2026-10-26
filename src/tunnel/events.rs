//! Tunnel event-stream state and its SSE wire encoding.
//!
//! The Server sends its full current state as the first event of every subscription and again
//! whenever it changes. There is no event history, `Last-Event-ID`, or acknowledgment: a new
//! subscription always starts from current state.

use std::fmt;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::sse::SseLimits;

/// Tunnel protocol version carried by every event-stream state.
///
/// The Client offers no availability to a Server whose state carries any other version. Changing
/// it is a lockstep protocol break; there is no version range or fallback.
pub const TUNNEL_PROTOCOL_VERSION: u32 = 1;

const STATE_EVENT_TYPE: &str = "state";
const GENERATION_BYTES: usize = 16;

/// SSE bounds for the Tunnel event stream: the Managed-session line and event-name bounds, with a
/// small data cap because lifecycle state never carries configuration.
pub(crate) const TUNNEL_EVENT_SSE_LIMITS: SseLimits = SseLimits {
    max_line_bytes: 4 * 1024,
    max_event_type_bytes: 64,
    max_event_data_bytes: 4 * 1024,
};

/// Comment frame that keeps a quiet event stream observably alive.
pub(crate) const KEEPALIVE_COMMENT: &[u8] = b": keepalive\n\n";

/// Opaque identifier of one Server process incarnation.
///
/// A Server generates a fresh value at startup. It is neither a credential nor enrollment
/// identity; Clients only compare values to tell one runtime generation of the same Server from
/// another.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ServerRuntimeGeneration([u8; GENERATION_BYTES]);

impl ServerRuntimeGeneration {
    /// Generate a fresh random generation for a starting Server process.
    pub fn generate() -> Self {
        Self(rand::random())
    }

    /// Parse the wire form: exactly 32 lowercase hexadecimal characters.
    fn parse(value: &str) -> Option<Self> {
        if value.len() != GENERATION_BYTES * 2 {
            return None;
        }
        let mut bytes = [0_u8; GENERATION_BYTES];
        let (pairs, _) = value.as_bytes().as_chunks::<2>();
        for (byte, [high, low]) in bytes.iter_mut().zip(pairs) {
            *byte = (lower_hex_value(*high)? << 4) | lower_hex_value(*low)?;
        }
        Some(Self(bytes))
    }
}

fn lower_hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

impl fmt::Display for ServerRuntimeGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0
            .iter()
            .try_for_each(|byte| write!(formatter, "{byte:02x}"))
    }
}

impl fmt::Debug for ServerRuntimeGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ServerRuntimeGeneration({self})")
    }
}

/// Full Server state delivered on the Tunnel event stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TunnelEventState {
    pub protocol_version: u32,
    pub server_generation: ServerRuntimeGeneration,
}

#[derive(Deserialize, Serialize)]
struct WireState {
    version: u32,
    generation: String,
}

/// Why an event-stream event is incompatible with this Runewarp build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TunnelEventError {
    UnexpectedEventType,
    MalformedState,
    UnsupportedVersion,
    InvalidGeneration,
}

impl TunnelEventError {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::UnexpectedEventType => "unexpected-event-type",
            Self::MalformedState => "malformed-state",
            Self::UnsupportedVersion => "unsupported-version",
            Self::InvalidGeneration => "invalid-generation",
        }
    }
}

impl TunnelEventState {
    /// Current state of a Server running `server_generation`.
    pub(crate) fn current(server_generation: ServerRuntimeGeneration) -> Self {
        Self {
            protocol_version: TUNNEL_PROTOCOL_VERSION,
            server_generation,
        }
    }

    /// One complete `state` SSE event.
    pub(crate) fn encode_sse(&self) -> Bytes {
        let wire = WireState {
            version: self.protocol_version,
            generation: self.server_generation.to_string(),
        };
        let data = serde_json::to_string(&wire)
            .expect("serializing a u32 and a hex string into JSON cannot fail");
        Bytes::from(format!("event: {STATE_EVENT_TYPE}\ndata: {data}\n\n"))
    }

    /// Decode one dispatched SSE event, accepting only a supported `state`.
    pub(crate) fn decode(event_type: Option<&str>, data: &str) -> Result<Self, TunnelEventError> {
        if event_type != Some(STATE_EVENT_TYPE) {
            return Err(TunnelEventError::UnexpectedEventType);
        }
        let wire: WireState =
            serde_json::from_str(data).map_err(|_| TunnelEventError::MalformedState)?;
        if wire.version != TUNNEL_PROTOCOL_VERSION {
            return Err(TunnelEventError::UnsupportedVersion);
        }
        let server_generation = ServerRuntimeGeneration::parse(&wire.generation)
            .ok_or(TunnelEventError::InvalidGeneration)?;
        Ok(Self {
            protocol_version: wire.version,
            server_generation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ServerRuntimeGeneration, TUNNEL_EVENT_SSE_LIMITS, TUNNEL_PROTOCOL_VERSION,
        TunnelEventError, TunnelEventState,
    };
    use crate::sse::{SseParseItem, SseParser};

    fn decode_wire(bytes: &[u8]) -> Result<TunnelEventState, TunnelEventError> {
        let mut parser = SseParser::new(TUNNEL_EVENT_SSE_LIMITS);
        let items = parser.push(bytes).expect("valid SSE framing");
        let [SseParseItem::Event(event)] = items.as_slice() else {
            panic!("expected exactly one event, got {items:?}");
        };
        TunnelEventState::decode(event.event_type.as_deref(), &event.data)
    }

    #[test]
    fn generations_are_fresh_and_render_as_32_lowercase_hex_characters() {
        let first = ServerRuntimeGeneration::generate();
        let second = ServerRuntimeGeneration::generate();

        assert_ne!(first, second);
        let rendered = first.to_string();
        assert_eq!(rendered.len(), 32);
        assert!(
            rendered
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert_eq!(ServerRuntimeGeneration::parse(&rendered), Some(first));
    }

    #[test]
    fn state_round_trips_through_its_sse_encoding() {
        let state = TunnelEventState::current(ServerRuntimeGeneration::generate());

        assert_eq!(decode_wire(&state.encode_sse()), Ok(state));
    }

    #[test]
    fn decode_ignores_unknown_state_fields() {
        let generation = ServerRuntimeGeneration::generate();
        let data = format!(r#"{{"version":1,"generation":"{generation}","future":true}}"#);

        assert_eq!(
            TunnelEventState::decode(Some("state"), &data),
            Ok(TunnelEventState::current(generation))
        );
    }

    #[test]
    fn decode_rejects_incompatible_events() {
        let generation = ServerRuntimeGeneration::generate();
        let valid = format!(r#"{{"version":1,"generation":"{generation}"}}"#);
        let other_version = format!(
            r#"{{"version":{},"generation":"{generation}"}}"#,
            TUNNEL_PROTOCOL_VERSION + 1
        );

        for (event_type, data, expected) in [
            (None, valid.clone(), TunnelEventError::UnexpectedEventType),
            (Some("other"), valid, TunnelEventError::UnexpectedEventType),
            (
                Some("state"),
                "not json".to_owned(),
                TunnelEventError::MalformedState,
            ),
            (
                Some("state"),
                r#"{"version":1}"#.to_owned(),
                TunnelEventError::MalformedState,
            ),
            (
                Some("state"),
                other_version,
                TunnelEventError::UnsupportedVersion,
            ),
            (
                Some("state"),
                r#"{"version":1,"generation":"abc"}"#.to_owned(),
                TunnelEventError::InvalidGeneration,
            ),
            (
                Some("state"),
                r#"{"version":1,"generation":"0123456789ABCDEF0123456789ABCDEF"}"#.to_owned(),
                TunnelEventError::InvalidGeneration,
            ),
        ] {
            assert_eq!(
                TunnelEventState::decode(event_type, &data),
                Err(expected),
                "{event_type:?} {data}"
            );
        }
    }
}
