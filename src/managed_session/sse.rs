//! Server-Sent Events framing for Managed-session downlinks.
//!
//! Parses the standard SSE wire format used by Control. Comment keepalives are
//! observed as byte activity but do not deliver snapshots. `id` and `retry`
//! fields are accepted and ignored so they cannot steer revision or reconnect
//! behavior. Line, event-type, and accumulated data sizes are enforced
//! incrementally across fragmented chunks.

use std::fmt;

use super::limits::{ManagedSessionLimitKind, ManagedSessionLimits};

/// One complete SSE event after a blank-line dispatch boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SseEvent {
    pub event_type: Option<String>,
    pub data: String,
}

/// Incremental SSE framing parser.
#[derive(Debug)]
pub(crate) struct SseParser {
    limits: ManagedSessionLimits,
    pending: Vec<u8>,
    event_type: Option<String>,
    data_lines: Vec<String>,
    data_bytes: usize,
    saw_cr: bool,
}

impl Default for SseParser {
    fn default() -> Self {
        Self::new(ManagedSessionLimits::default())
    }
}

/// Outcome of feeding bytes into [`SseParser`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SseParseItem {
    /// Colon-prefixed comment line (keepalive or other).
    Comment,
    /// Complete event dispatched by a blank line.
    Event(SseEvent),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SseParseError {
    InvalidUtf8,
    LimitExceeded {
        limit: ManagedSessionLimitKind,
        value: usize,
        max: usize,
    },
}

impl fmt::Display for SseParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8 => formatter.write_str("SSE stream contained invalid UTF-8"),
            Self::LimitExceeded { limit, value, max } => write!(
                formatter,
                "SSE {} limit exceeded: value={value} max={max}",
                limit.as_str()
            ),
        }
    }
}

impl std::error::Error for SseParseError {}

impl SseParser {
    pub fn new(limits: ManagedSessionLimits) -> Self {
        Self {
            limits,
            pending: Vec::new(),
            event_type: None,
            data_lines: Vec::new(),
            data_bytes: 0,
            saw_cr: false,
        }
    }

    /// Feed newly received SSE bytes and return any completed items in order.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<SseParseItem>, SseParseError> {
        let mut items = Vec::new();
        for &byte in chunk {
            if self.saw_cr {
                self.saw_cr = false;
                if byte == b'\n' {
                    self.finish_line(&mut items)?;
                    continue;
                }
                // Lone CR ends a line; the next byte starts the following line.
                self.finish_line(&mut items)?;
            }

            match byte {
                b'\n' => self.finish_line(&mut items)?,
                b'\r' => self.saw_cr = true,
                _ => {
                    if self.pending.len() >= self.limits.max_sse_line_bytes {
                        return Err(SseParseError::LimitExceeded {
                            limit: ManagedSessionLimitKind::SseLineBytes,
                            value: self.pending.len().saturating_add(1),
                            max: self.limits.max_sse_line_bytes,
                        });
                    }
                    self.pending.push(byte);
                }
            }
        }
        Ok(items)
    }

    fn finish_line(&mut self, items: &mut Vec<SseParseItem>) -> Result<(), SseParseError> {
        let line_bytes = std::mem::take(&mut self.pending);
        if line_bytes.is_empty() {
            items.push(SseParseItem::Event(self.dispatch_event()));
            return Ok(());
        }

        let line = std::str::from_utf8(&line_bytes).map_err(|_| SseParseError::InvalidUtf8)?;
        if line.starts_with(':') {
            items.push(SseParseItem::Comment);
            return Ok(());
        }

        let (field, value) = match line.split_once(':') {
            Some((field, rest)) => {
                let value = rest.strip_prefix(' ').unwrap_or(rest);
                (field, value)
            }
            None => (line, ""),
        };

        match field {
            "event" => {
                if value.len() > self.limits.max_sse_event_type_bytes {
                    return Err(SseParseError::LimitExceeded {
                        limit: ManagedSessionLimitKind::SseEventTypeBytes,
                        value: value.len(),
                        max: self.limits.max_sse_event_type_bytes,
                    });
                }
                self.event_type = Some(value.to_owned());
            }
            "data" => {
                let added = if self.data_lines.is_empty() {
                    value.len()
                } else {
                    value.len().saturating_add(1)
                };
                let next = self.data_bytes.saturating_add(added);
                if next > self.limits.max_sse_event_data_bytes {
                    return Err(SseParseError::LimitExceeded {
                        limit: ManagedSessionLimitKind::SseEventDataBytes,
                        value: next,
                        max: self.limits.max_sse_event_data_bytes,
                    });
                }
                self.data_bytes = next;
                self.data_lines.push(value.to_owned());
            }
            "id" | "retry" => {
                // Accepted and ignored: Core owns revision equality and reconnect timing.
            }
            _ => {
                // Unknown fields are ignored per the SSE grammar.
            }
        }
        Ok(())
    }

    fn dispatch_event(&mut self) -> SseEvent {
        let event_type = self.event_type.take();
        let data = self.data_lines.join("\n");
        self.data_lines.clear();
        self.data_bytes = 0;
        SseEvent { event_type, data }
    }
}

#[cfg(test)]
mod tests {
    use super::{SseParseError, SseParseItem, SseParser};
    use crate::managed_session::limits::{ManagedSessionLimitKind, ManagedSessionLimits};

    fn tiny_limits() -> ManagedSessionLimits {
        ManagedSessionLimits {
            max_sse_line_bytes: 16,
            max_sse_event_type_bytes: 8,
            max_sse_event_data_bytes: 32,
            ..ManagedSessionLimits::default()
        }
    }

    #[test]
    fn parses_snapshot_event_with_data_and_ignores_id_retry() {
        let mut parser = SseParser::new(ManagedSessionLimits::default());
        let items = parser
            .push(
                b"id: ignored\n\
                  retry: 5000\n\
                  event: snapshot\n\
                  data: {\"revision\":\"rev-1\",\"input\":{}}\n\
                  \n",
            )
            .unwrap();

        assert_eq!(
            items,
            vec![SseParseItem::Event(super::SseEvent {
                event_type: Some("snapshot".to_owned()),
                data: "{\"revision\":\"rev-1\",\"input\":{}}".to_owned(),
            })]
        );
    }

    #[test]
    fn comment_keepalives_are_reported_without_dispatching_an_event() {
        let mut parser = SseParser::new(ManagedSessionLimits::default());
        let items = parser.push(b": keepalive\n").unwrap();
        assert_eq!(items, vec![SseParseItem::Comment]);
        assert!(parser.push(b"event: snapshot\ndata: {}\n\n").unwrap().len() == 1);
    }

    #[test]
    fn joins_multiline_data_with_lf() {
        let mut parser = SseParser::new(ManagedSessionLimits::default());
        let items = parser
            .push(b"event: snapshot\ndata: {\"a\":1,\ndata: \"b\":2}\n\n")
            .unwrap();
        assert_eq!(
            items,
            vec![SseParseItem::Event(super::SseEvent {
                event_type: Some("snapshot".to_owned()),
                data: "{\"a\":1,\n\"b\":2}".to_owned(),
            })]
        );
    }

    #[test]
    fn accepts_crlf_line_endings() {
        let mut parser = SseParser::new(ManagedSessionLimits::default());
        let items = parser
            .push(b"event: snapshot\r\ndata: {\"revision\":\"r\"}\r\n\r\n")
            .unwrap();
        assert_eq!(
            items,
            vec![SseParseItem::Event(super::SseEvent {
                event_type: Some("snapshot".to_owned()),
                data: "{\"revision\":\"r\"}".to_owned(),
            })]
        );
    }

    #[test]
    fn rejects_invalid_utf8() {
        let mut parser = SseParser::new(ManagedSessionLimits::default());
        let error = parser.push(b"data: \xff\n\n").unwrap_err();
        assert_eq!(error, SseParseError::InvalidUtf8);
    }

    #[test]
    fn buffers_across_chunk_boundaries() {
        let mut parser = SseParser::new(ManagedSessionLimits::default());
        assert!(parser.push(b"event: snap").unwrap().is_empty());
        assert!(parser.push(b"shot\ndata: x").unwrap().is_empty());
        let items = parser.push(b"y\n\n").unwrap();
        assert_eq!(
            items,
            vec![SseParseItem::Event(super::SseEvent {
                event_type: Some("snapshot".to_owned()),
                data: "xy".to_owned(),
            })]
        );
    }

    #[test]
    fn rejects_oversize_line_across_fragments() {
        let mut parser = SseParser::new(tiny_limits());
        assert!(parser.push(b"data: 1234567890").unwrap().is_empty());
        let error = parser.push(b"abcdef\n").unwrap_err();
        assert_eq!(
            error,
            SseParseError::LimitExceeded {
                limit: ManagedSessionLimitKind::SseLineBytes,
                value: 17,
                max: 16,
            }
        );
    }

    #[test]
    fn rejects_oversize_event_type() {
        let mut parser = SseParser::new(tiny_limits());
        let error = parser.push(b"event: toolonggg\ndata: x\n\n").unwrap_err();
        assert_eq!(
            error,
            SseParseError::LimitExceeded {
                limit: ManagedSessionLimitKind::SseEventTypeBytes,
                value: 9,
                max: 8,
            }
        );
    }

    #[test]
    fn rejects_oversize_accumulated_data_across_lines() {
        let limits = ManagedSessionLimits {
            max_sse_line_bytes: 64,
            max_sse_event_type_bytes: 8,
            max_sse_event_data_bytes: 32,
            ..ManagedSessionLimits::default()
        };
        let mut parser = SseParser::new(limits);
        assert!(parser.push(b"data: aaaaaaaaaaaaaaaa\n").unwrap().is_empty());
        let error = parser.push(b"data: bbbbbbbbbbbbbbbb\n\n").unwrap_err();
        assert!(matches!(
            error,
            SseParseError::LimitExceeded {
                limit: ManagedSessionLimitKind::SseEventDataBytes,
                ..
            }
        ));
    }
}
