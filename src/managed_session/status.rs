//! Managed-session status policy for SSE downlink and state-acknowledgment responses.

use http::{HeaderMap, StatusCode, header};
use http_body_util::BodyExt;
use hyper::body::Incoming;

/// Outcome of classifying an SSE response before body parsing begins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SseResponseClass {
    /// Exact status 200 with an event-stream media type.
    Success,
    /// Any other outcome: retry by replacing the Managed session.
    RetryableFailure,
}

/// Outcome of classifying a state-acknowledgment response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StateResponseClass {
    /// Exact status 204 with an already-ended empty body.
    Success,
    /// Any other outcome: leave SSE undisturbed and retry later.
    Failure,
}

/// Classify an SSE response. Redirects, 204, other non-success statuses, and
/// wrong media types are all retryable session failures.
pub(crate) fn classify_sse_response(status: StatusCode, headers: &HeaderMap) -> SseResponseClass {
    if status.is_redirection() {
        return SseResponseClass::RetryableFailure;
    }
    if status != StatusCode::OK {
        return SseResponseClass::RetryableFailure;
    }
    if !content_type_is_event_stream(headers) {
        return SseResponseClass::RetryableFailure;
    }
    SseResponseClass::Success
}

/// Classify a state-acknowledgment response from status alone before reading the body.
pub(crate) fn classify_state_status(status: StatusCode) -> StateResponseClass {
    if status == StatusCode::NO_CONTENT {
        StateResponseClass::Success
    } else {
        StateResponseClass::Failure
    }
}

/// Classify a fully read state-acknowledgment response. Success requires exact status
/// 204 and an empty body.
#[cfg(test)]
pub(crate) fn classify_state_response(status: StatusCode, body: &[u8]) -> StateResponseClass {
    if classify_state_status(status) != StateResponseClass::Success {
        return StateResponseClass::Failure;
    }
    if body.is_empty() {
        StateResponseClass::Success
    } else {
        StateResponseClass::Failure
    }
}

/// Classify a state-response body without collecting an unbounded payload.
///
/// Non-204 responses fail immediately without reading the body. Success requires
/// exact status 204 with an already-ended body (no data frames). A body-bearing
/// or still-open 204 is rejected after observing the first frame, without
/// draining remaining bytes.
pub(crate) async fn classify_state_incoming(
    status: StatusCode,
    mut body: Incoming,
) -> Result<StateResponseClass, hyper::Error> {
    if classify_state_status(status) != StateResponseClass::Success {
        drop(body);
        return Ok(StateResponseClass::Failure);
    }

    match body.frame().await {
        None => Ok(StateResponseClass::Success),
        Some(Ok(_)) => {
            // Any data or trailer frame means the body was not already ended empty.
            drop(body);
            Ok(StateResponseClass::Failure)
        }
        Some(Err(error)) => Err(error),
    }
}

fn content_type_is_event_stream(headers: &HeaderMap) -> bool {
    let Some(value) = headers.get(header::CONTENT_TYPE) else {
        return false;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    let media_type = value
        .split(';')
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase();
    media_type == "text/event-stream"
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, StatusCode, header};

    use super::{
        SseResponseClass, StateResponseClass, classify_sse_response, classify_state_response,
    };

    fn headers_with_content_type(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn accepts_exact_200_with_event_stream_media_type() {
        assert_eq!(
            classify_sse_response(
                StatusCode::OK,
                &headers_with_content_type("text/event-stream")
            ),
            SseResponseClass::Success
        );
        assert_eq!(
            classify_sse_response(
                StatusCode::OK,
                &headers_with_content_type("text/event-stream; charset=utf-8")
            ),
            SseResponseClass::Success
        );
    }

    #[test]
    fn rejects_redirects_as_retryable_failures() {
        assert_eq!(
            classify_sse_response(
                StatusCode::TEMPORARY_REDIRECT,
                &headers_with_content_type("text/event-stream")
            ),
            SseResponseClass::RetryableFailure
        );
    }

    #[test]
    fn rejects_204_and_other_non_success_statuses() {
        assert_eq!(
            classify_sse_response(
                StatusCode::NO_CONTENT,
                &headers_with_content_type("text/event-stream")
            ),
            SseResponseClass::RetryableFailure
        );
        assert_eq!(
            classify_sse_response(
                StatusCode::UNAUTHORIZED,
                &headers_with_content_type("text/event-stream")
            ),
            SseResponseClass::RetryableFailure
        );
        assert_eq!(
            classify_sse_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &headers_with_content_type("text/event-stream")
            ),
            SseResponseClass::RetryableFailure
        );
    }

    #[test]
    fn rejects_wrong_or_missing_media_types() {
        assert_eq!(
            classify_sse_response(
                StatusCode::OK,
                &headers_with_content_type("application/json")
            ),
            SseResponseClass::RetryableFailure
        );
        assert_eq!(
            classify_sse_response(StatusCode::OK, &HeaderMap::new()),
            SseResponseClass::RetryableFailure
        );
    }

    #[test]
    fn state_write_succeeds_only_for_exact_204_with_empty_body() {
        assert_eq!(
            classify_state_response(StatusCode::NO_CONTENT, b""),
            StateResponseClass::Success
        );
        assert_eq!(
            classify_state_response(StatusCode::NO_CONTENT, b"{}"),
            StateResponseClass::Failure
        );
        assert_eq!(
            classify_state_response(StatusCode::OK, b""),
            StateResponseClass::Failure
        );
        assert_eq!(
            classify_state_response(StatusCode::INTERNAL_SERVER_ERROR, b""),
            StateResponseClass::Failure
        );
    }
}
