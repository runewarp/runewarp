//! Server-Sent Events framing for Managed-session downlinks.
//!
//! Parses the standard SSE wire format used by Control. Comment keepalives are
//! observed as byte activity but do not deliver snapshots. `id` and `retry`
//! fields are accepted and ignored so they cannot steer revision or reconnect
//! behavior.

use std::fmt;

/// One complete SSE event after a blank-line dispatch boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SseEvent {
    pub event_type: Option<String>,
    pub data: String,
}

/// Incremental SSE framing parser.
#[derive(Debug, Default)]
pub struct SseParser {
    pending: Vec<u8>,
    event_type: Option<String>,
    data_lines: Vec<String>,
    saw_cr: bool,
}

/// Outcome of feeding bytes into [`SseParser`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SseParseItem {
    /// Colon-prefixed comment line (keepalive or other).
    Comment,
    /// Complete event dispatched by a blank line.
    Event(SseEvent),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SseParseError {
    InvalidUtf8,
    MalformedField,
}

impl fmt::Display for SseParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8 => formatter.write_str("SSE stream contained invalid UTF-8"),
            Self::MalformedField => formatter.write_str("SSE stream contained a malformed field"),
        }
    }
}

impl std::error::Error for SseParseError {}

impl SseParser {
    pub fn new() -> Self {
        Self::default()
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
                _ => self.pending.push(byte),
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
                self.event_type = Some(value.to_owned());
            }
            "data" => {
                self.data_lines.push(value.to_owned());
            }
            "id" | "retry" => {
                // Accepted and ignored: Core owns revision equality and reconnect timing.
            }
            "" => return Err(SseParseError::MalformedField),
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
        SseEvent { event_type, data }
    }
}

#[cfg(test)]
mod tests {
    use super::{SseParseError, SseParseItem, SseParser};

    #[test]
    fn parses_snapshot_event_with_data_and_ignores_id_retry() {
        let mut parser = SseParser::new();
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
        let mut parser = SseParser::new();
        let items = parser.push(b": keepalive\n").unwrap();
        assert_eq!(items, vec![SseParseItem::Comment]);
        assert!(parser.push(b"event: snapshot\ndata: {}\n\n").unwrap().len() == 1);
    }

    #[test]
    fn joins_multiline_data_with_lf() {
        let mut parser = SseParser::new();
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
        let mut parser = SseParser::new();
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
        let mut parser = SseParser::new();
        let error = parser.push(b"data: \xff\n\n").unwrap_err();
        assert_eq!(error, SseParseError::InvalidUtf8);
    }

    #[test]
    fn buffers_across_chunk_boundaries() {
        let mut parser = SseParser::new();
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
}
