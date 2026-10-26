//! Tunnel event-stream snapshots and their SSE wire encoding.
//!
//! The Server sends its full current snapshot as the first event of every subscription and again
//! whenever it changes. There is no event history, `Last-Event-ID`, or acknowledgment: a new
//! subscription always starts from the current snapshot.

use std::fmt;
use std::sync::Arc;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use uuid::{Uuid, Variant, Version};

use crate::sse::SseLimits;

const SNAPSHOT_EVENT_TYPE: &str = "snapshot";

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
/// A Server mints a fresh UUIDv7 at startup. It is neither a credential nor enrollment identity;
/// Clients only compare values to tell one runtime generation of the same Server from another.
/// UUIDv7 embeds its mint time, so generations sort by Server start time and reveal it.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ServerRuntimeGeneration(Uuid);

impl ServerRuntimeGeneration {
    /// Mint a fresh generation for a starting Server process.
    pub fn generate() -> Self {
        Self(Uuid::now_v7())
    }

    /// Parse the wire form: a UUIDv7 in canonical lowercase hyphenated form. Uppercase,
    /// unhyphenated, braced, URN, other-version, and other-variant forms are rejected.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        let uuid = Uuid::try_parse(value).ok()?;
        let canonical = uuid.hyphenated().encode_lower(&mut Uuid::encode_buffer()) == value;
        (canonical
            && uuid.get_version() == Some(Version::SortRand)
            && uuid.get_variant() == Variant::RFC4122)
            .then_some(Self(uuid))
    }
}

impl fmt::Display for ServerRuntimeGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0.hyphenated(), formatter)
    }
}

impl fmt::Debug for ServerRuntimeGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ServerRuntimeGeneration({self})")
    }
}

/// Full Server snapshot delivered on the Tunnel event stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TunnelEventState {
    /// Generation of the Server runtime serving this connection.
    pub server_generation: ServerRuntimeGeneration,
    /// Replacement hint: another runtime generation behind the same Server address that Clients
    /// may open a candidate connection to. `None` when the Server advertises no replacement.
    pub replacement_generation: Option<ServerRuntimeGeneration>,
}

#[derive(Serialize)]
struct WireSnapshotOut {
    generation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    replacement_generation: Option<String>,
}

#[derive(Deserialize)]
struct WireSnapshotIn {
    generation: String,
    /// Absent means no hint; `null` or another type fails to deserialize.
    #[serde(default, deserialize_with = "present_string")]
    replacement_generation: Option<String>,
}

fn present_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

/// Why an event-stream event is incompatible with this Runewarp build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TunnelEventError {
    UnexpectedEventType,
    MalformedState,
    InvalidGeneration,
}

impl TunnelEventError {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::UnexpectedEventType => "unexpected-event-type",
            Self::MalformedState => "malformed-state",
            Self::InvalidGeneration => "invalid-generation",
        }
    }
}

impl TunnelEventState {
    /// Snapshot of a Server running `server_generation` with no replacement hint.
    pub(crate) fn current(server_generation: ServerRuntimeGeneration) -> Self {
        Self {
            server_generation,
            replacement_generation: None,
        }
    }

    /// One complete `snapshot` SSE event.
    pub(crate) fn encode_sse(&self) -> Bytes {
        let wire = WireSnapshotOut {
            generation: self.server_generation.to_string(),
            replacement_generation: self.replacement_generation.map(|value| value.to_string()),
        };
        let data = serde_json::to_string(&wire)
            .expect("serializing hex strings into a JSON object cannot fail");
        Bytes::from(format!("event: {SNAPSHOT_EVENT_TYPE}\ndata: {data}\n\n"))
    }

    /// Decode one dispatched SSE event, accepting only a valid `snapshot`.
    pub(crate) fn decode(event_type: Option<&str>, data: &str) -> Result<Self, TunnelEventError> {
        if event_type != Some(SNAPSHOT_EVENT_TYPE) {
            return Err(TunnelEventError::UnexpectedEventType);
        }
        let wire: WireSnapshotIn =
            serde_json::from_str(data).map_err(|_| TunnelEventError::MalformedState)?;
        let server_generation = ServerRuntimeGeneration::parse(&wire.generation)
            .ok_or(TunnelEventError::InvalidGeneration)?;
        let replacement_generation = wire
            .replacement_generation
            .map(|value| {
                ServerRuntimeGeneration::parse(&value).ok_or(TunnelEventError::MalformedState)
            })
            .transpose()?;
        Ok(Self {
            server_generation,
            replacement_generation,
        })
    }
}

/// Server-wide source of the current Tunnel event-stream snapshot.
///
/// Every Tunnel connection of one Server runtime follows the same source. Publishing a new
/// replacement hint wakes each live subscription, which writes only the latest snapshot: a
/// subscription blocked on flow control coalesces intermediate changes instead of queueing them.
#[derive(Clone, Debug)]
pub struct ServerTunnelEvents {
    snapshot: Arc<watch::Sender<TunnelEventState>>,
}

impl ServerTunnelEvents {
    /// Source for a Server running `server_generation`, starting with no replacement hint.
    pub fn new(server_generation: ServerRuntimeGeneration) -> Self {
        Self {
            snapshot: Arc::new(watch::Sender::new(TunnelEventState::current(
                server_generation,
            ))),
        }
    }

    /// Generation of this Server runtime.
    pub fn server_generation(&self) -> ServerRuntimeGeneration {
        self.snapshot.borrow().server_generation
    }

    /// Advertise `replacement` to every live subscription, or clear the hint with `None`.
    ///
    /// A hint naming this runtime's own generation is suppressed, so one input can be published
    /// to both the old and new runtime. Publishing the advertised value again wakes nobody.
    pub fn set_replacement_generation(&self, replacement: Option<ServerRuntimeGeneration>) {
        self.snapshot.send_if_modified(|snapshot| {
            let advertised = replacement.filter(|value| *value != snapshot.server_generation);
            let changed = snapshot.replacement_generation != advertised;
            snapshot.replacement_generation = advertised;
            changed
        });
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<TunnelEventState> {
        self.snapshot.subscribe()
    }
}

impl From<ServerRuntimeGeneration> for ServerTunnelEvents {
    fn from(server_generation: ServerRuntimeGeneration) -> Self {
        Self::new(server_generation)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ServerRuntimeGeneration, ServerTunnelEvents, TUNNEL_EVENT_SSE_LIMITS, TunnelEventError,
        TunnelEventState,
    };
    use crate::sse::{SseParseItem, SseParser};

    const GENERATION: &str = "01928f3e-7b6a-7c3d-8e4f-0123456789ab";
    const REPLACEMENT: &str = "01928f3e-9c1d-7fed-9cba-9876543210fe";

    fn generation(value: &str) -> ServerRuntimeGeneration {
        ServerRuntimeGeneration::parse(value).expect("valid generation")
    }

    fn decode_wire(bytes: &[u8]) -> Result<TunnelEventState, TunnelEventError> {
        let mut parser = SseParser::new(TUNNEL_EVENT_SSE_LIMITS);
        let items = parser.push(bytes).expect("valid SSE framing");
        let [SseParseItem::Event(event)] = items.as_slice() else {
            panic!("expected exactly one event, got {items:?}");
        };
        TunnelEventState::decode(event.event_type.as_deref(), &event.data)
    }

    #[test]
    fn generations_are_time_ordered_uuidv7s_in_canonical_form() {
        let first = ServerRuntimeGeneration::generate();
        let second = ServerRuntimeGeneration::generate();

        assert_ne!(first, second);
        let rendered = first.to_string();
        assert_eq!(rendered.len(), 36);
        for (index, byte) in rendered.bytes().enumerate() {
            match index {
                8 | 13 | 18 | 23 => assert_eq!(byte, b'-', "{rendered}"),
                14 => assert_eq!(byte, b'7', "version nibble: {rendered}"),
                19 => assert!(b"89ab".contains(&byte), "variant: {rendered}"),
                _ => assert!(
                    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
                    "{rendered}"
                ),
            }
        }
        assert!(
            rendered < second.to_string(),
            "later generations sort after earlier ones"
        );
        assert_eq!(ServerRuntimeGeneration::parse(&rendered), Some(first));
    }

    #[test]
    fn generation_parsing_accepts_only_the_canonical_uuidv7_form() {
        assert!(ServerRuntimeGeneration::parse(GENERATION).is_some());
        for invalid in [
            "",
            "01928F3E-7B6A-7C3D-8E4F-0123456789AB",
            "01928f3e7b6a7c3d8e4f0123456789ab",
            "{01928f3e-7b6a-7c3d-8e4f-0123456789ab}",
            "urn:uuid:01928f3e-7b6a-7c3d-8e4f-0123456789ab",
            "01928f3e-7b6a-4c3d-8e4f-0123456789ab",
            "01928f3e-7b6a-7c3d-ce4f-0123456789ab",
            "01928f3e-7b6a-7c3d-8e4f-0123456789a",
            "0123456789abcdef0123456789abcdef",
            "00000000-0000-0000-0000-000000000000",
        ] {
            assert_eq!(ServerRuntimeGeneration::parse(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn snapshot_without_a_hint_has_the_documented_wire_bytes_and_round_trips() {
        let state = TunnelEventState::current(generation(GENERATION));

        let encoded = state.encode_sse();
        assert_eq!(
            &encoded[..],
            format!("event: snapshot\ndata: {{\"generation\":\"{GENERATION}\"}}\n\n").as_bytes()
        );
        assert_eq!(decode_wire(&encoded), Ok(state));
    }

    #[test]
    fn snapshot_with_a_hint_has_the_documented_wire_bytes_and_round_trips() {
        let state = TunnelEventState {
            server_generation: generation(GENERATION),
            replacement_generation: Some(generation(REPLACEMENT)),
        };

        let encoded = state.encode_sse();
        assert_eq!(
            &encoded[..],
            format!(
                "event: snapshot\ndata: {{\"generation\":\"{GENERATION}\",\"replacement_generation\":\"{REPLACEMENT}\"}}\n\n"
            )
            .as_bytes()
        );
        assert_eq!(decode_wire(&encoded), Ok(state));
    }

    #[test]
    fn decode_ignores_unknown_snapshot_fields() {
        let data = format!(r#"{{"version":1,"generation":"{GENERATION}","future":true}}"#);

        assert_eq!(
            TunnelEventState::decode(Some("snapshot"), &data),
            Ok(TunnelEventState::current(generation(GENERATION)))
        );
    }

    #[test]
    fn decode_rejects_incompatible_events() {
        let valid = format!(r#"{{"generation":"{GENERATION}"}}"#);
        let hint = |value: &str| {
            format!(r#"{{"generation":"{GENERATION}","replacement_generation":{value}}}"#)
        };

        for (event_type, data, expected) in [
            (None, valid.clone(), TunnelEventError::UnexpectedEventType),
            (
                Some("state"),
                valid.clone(),
                TunnelEventError::UnexpectedEventType,
            ),
            (Some("other"), valid, TunnelEventError::UnexpectedEventType),
            (
                Some("snapshot"),
                "not json".to_owned(),
                TunnelEventError::MalformedState,
            ),
            (
                Some("snapshot"),
                "{}".to_owned(),
                TunnelEventError::MalformedState,
            ),
            (
                Some("snapshot"),
                r#"{"generation":"abc"}"#.to_owned(),
                TunnelEventError::InvalidGeneration,
            ),
            (
                Some("snapshot"),
                r#"{"generation":"01928F3E-7B6A-7C3D-8E4F-0123456789AB"}"#.to_owned(),
                TunnelEventError::InvalidGeneration,
            ),
            (
                Some("snapshot"),
                r#"{"generation":"0123456789abcdef0123456789abcdef"}"#.to_owned(),
                TunnelEventError::InvalidGeneration,
            ),
            (
                Some("snapshot"),
                hint("null"),
                TunnelEventError::MalformedState,
            ),
            (
                Some("snapshot"),
                hint("7"),
                TunnelEventError::MalformedState,
            ),
            (
                Some("snapshot"),
                hint(r#"["x"]"#),
                TunnelEventError::MalformedState,
            ),
            (
                Some("snapshot"),
                hint(r#""abc""#),
                TunnelEventError::MalformedState,
            ),
            (
                Some("snapshot"),
                hint(r#""01928F3E-9C1D-7FED-9CBA-9876543210FE""#),
                TunnelEventError::MalformedState,
            ),
            (
                Some("snapshot"),
                hint(r#""fedcba9876543210fedcba9876543210""#),
                TunnelEventError::MalformedState,
            ),
        ] {
            assert_eq!(
                TunnelEventState::decode(event_type, &data),
                Err(expected),
                "{event_type:?} {data}"
            );
        }
    }

    #[test]
    fn published_hints_wake_subscribers_except_self_and_repeated_hints() {
        let events = ServerTunnelEvents::new(generation(GENERATION));
        let mut subscriber = events.subscribe();
        subscriber.mark_unchanged();

        events.set_replacement_generation(Some(generation(GENERATION)));
        assert!(!subscriber.has_changed().expect("source alive"));

        events.set_replacement_generation(Some(generation(REPLACEMENT)));
        assert!(subscriber.has_changed().expect("source alive"));
        assert_eq!(
            subscriber.borrow_and_update().replacement_generation,
            Some(generation(REPLACEMENT))
        );

        events.set_replacement_generation(Some(generation(REPLACEMENT)));
        assert!(!subscriber.has_changed().expect("source alive"));

        events.set_replacement_generation(Some(generation(GENERATION)));
        assert_eq!(subscriber.borrow_and_update().replacement_generation, None);
    }
}
