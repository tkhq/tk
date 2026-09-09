//! Error taxonomy and classification.
//!
//! This module is the single home for tk's machine-readable error taxonomy:
//! the [`ErrorCode`] enum and its stable snake_case wire names and the
//! [`classify`] logic that walks an [`anyhow::Error`] chain and maps
//! recognized causes (the typed [`MissingResource`] and `TurnkeyClientError`)
//! to a [`Classification`] `(code, http_status)`. It also owns
//! [`render_error_chain`], the shared human/JSON renderer that preserves the
//! full source chain and caps messages before they cross the CLI output
//! boundary.

use serde::Serialize;
use serde_json::Value;
use std::fmt::{self, Display, Formatter};
pub use turnkey_auth::errors::MissingResource;
use turnkey_client::TurnkeyClientError;

/// A locally detectable input problem that clap cannot express: semantic
/// validation of values, files, and environment that failed before any request.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct InvalidInput(pub String);

/// A raw API request that returned a non-success HTTP status. The response
/// body is kept because Turnkey's error `message` is the user's only diagnostic.
#[derive(Debug, thiserror::Error)]
#[error("HTTP response was not successful: {status} ({body})")]
pub struct UnexpectedHttpStatus {
    /// The HTTP status code.
    pub status: u16,
    /// The response body, or a placeholder when it could not be read.
    pub body: String,
}

/// How a submitted or awaited activity failed to reach a usable terminal state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivityErrorKind {
    /// A mutation was sent but its outcome could not be observed. Callers must
    /// inspect activities before resubmitting.
    SubmissionUnknown,
    /// `activity wait` ran out of time while the activity was still pending.
    WaitTimeout,
    /// The activity reached a terminal state other than completed.
    NotCompleted,
    /// The server responded, but the response did not carry the expected
    /// activity fields.
    MalformedResponse,
}

/// A failure concerning one activity. Carries the last observed activity
/// identity so machine consumers can resume or inspect it.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct ActivityError {
    kind: ActivityErrorKind,
    activity: Option<Value>,
    message: String,
    #[source]
    source: Option<reqwest::Error>,
}

impl ActivityError {
    /// Builds the error for `kind` with a human message.
    pub fn new(kind: ActivityErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            activity: None,
            message: message.into(),
            source: None,
        }
    }

    /// Attaches the last observed activity identity (`{"id", "status"}`).
    pub fn with_activity(mut self, activity: Value) -> Self {
        self.activity = Some(activity);
        self
    }

    /// Keeps the transport error that made the outcome unknown.
    pub fn with_source(mut self, source: reqwest::Error) -> Self {
        self.source = Some(source);
        self
    }

    /// The failure kind.
    pub fn kind(&self) -> ActivityErrorKind {
        self.kind
    }

    /// The last observed activity identity, when known.
    pub fn activity(&self) -> Option<&Value> {
        self.activity.as_ref()
    }
}

/// Machine-readable recovery details attached to an error as anyhow context:
/// the human chain shows `summary`, and the JSON envelope carries `data`
/// (state file paths, phases, fingerprints) so an agent can recover.
#[derive(Debug)]
pub struct Details {
    summary: String,
    data: Value,
}

impl Details {
    /// Builds details whose `data` must be a JSON object.
    pub fn new(summary: impl Into<String>, data: Value) -> Self {
        debug_assert!(data.is_object(), "error details must be a JSON object");
        Self {
            summary: summary.into(),
            data,
        }
    }
}

impl Display for Details {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.summary)
    }
}

/// The recovery details for an error: [`Details`] data merged with the
/// activity identity of an [`ActivityError`] under `"activity"`.
pub fn error_details(error: &anyhow::Error) -> Option<Value> {
    let mut details = error
        .downcast_ref::<Details>()
        .map(|details| details.data.clone())
        .unwrap_or(Value::Null);
    let activity = error
        .downcast_ref::<ActivityError>()
        .and_then(ActivityError::activity);
    if let Some(activity) = activity {
        if !details.is_object() {
            details = Value::Object(Default::default());
        }
        details["activity"] = activity.clone();
    }
    details.is_object().then_some(details)
}

/// Cap on rendered error messages, in bytes. Large enough for any real API
/// error body (typical Turnkey error JSON is < 1 KB); small enough that a
/// runaway body (HTML error page, proxy dump) cannot bloat a single NDJSON line.
const MAX_ERROR_MESSAGE_BYTES: usize = 8 * 1024;

/// The stable, machine-readable classification of a runtime error, carried in
/// the `code` field of a `command_error` (or `missing_required_input`) message.
///
/// `code` is the taxonomy axis; the message `reason` stays stable
/// (`command_error` for all runtime errors) so the outcome registry is
/// unaffected. Serde derives each variant's stable snake_case wire name
/// directly from the enum.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// A required value was absent in non-interactive mode.
    MissingRequiredInput,
    /// Bad flags/args, a clap parse failure.
    UsageError,
    /// Semantic validation failure in command code.
    InvalidInput,
    /// HTTP 401/403.
    Unauthorized,
    /// HTTP 404, or an OK response with an empty resource.
    NotFound,
    /// Any other non-success HTTP status, or a failed/unexpected activity.
    ApiError,
    /// An activity needs more approvals.
    ApprovalRequired,
    /// A connect/timeout/DNS failure — the request never reached the server.
    NetworkError,
    /// A mutation was sent but its outcome is unknown; inspect before retrying.
    SubmissionUnknown,
    /// `activity wait` timed out while the activity was still pending.
    WaitTimeout,
    /// Fallback for everything else.
    CommandError,
}

/// The result of classifying an error: its taxonomy [`ErrorCode`] and, when the
/// cause is an HTTP failure, the numeric status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Classification {
    /// The taxonomy code.
    pub code: ErrorCode,
    /// The HTTP status, when the cause is an HTTP failure.
    pub http_status: Option<u16>,
}

impl Classification {
    pub(crate) fn new(code: ErrorCode, http_status: Option<u16>) -> Self {
        Self { code, http_status }
    }
}

/// Walk the cause chain and classify the first typed error we recognize.
///
/// Classification does not alter the original error or its rendered cause
/// chain. Unrecognized errors use [`ErrorCode::CommandError`] with no HTTP
/// status; callers still render the complete original chain.
pub fn classify(error: &anyhow::Error) -> Classification {
    for cause in error.chain() {
        if cause.downcast_ref::<InvalidInput>().is_some() {
            return Classification::new(ErrorCode::InvalidInput, None);
        }
        if cause.downcast_ref::<MissingResource>().is_some() {
            return Classification::new(ErrorCode::NotFound, None);
        }
        if let Some(http) = cause.downcast_ref::<UnexpectedHttpStatus>() {
            return classify_http_status(http.status);
        }
        if let Some(activity) = cause.downcast_ref::<ActivityError>() {
            let code = match activity.kind() {
                ActivityErrorKind::SubmissionUnknown => ErrorCode::SubmissionUnknown,
                ActivityErrorKind::WaitTimeout => ErrorCode::WaitTimeout,
                ActivityErrorKind::NotCompleted | ActivityErrorKind::MalformedResponse => {
                    ErrorCode::ApiError
                }
            };
            return Classification::new(code, None);
        }
        if let Some(reqwest_error) = cause.downcast_ref::<reqwest::Error>() {
            return classify_reqwest_error(reqwest_error);
        }
        if let Some(client_error) = cause.downcast_ref::<TurnkeyClientError>() {
            return classify_turnkey_client_error(client_error);
        }
    }
    Classification::new(ErrorCode::CommandError, None)
}

fn classify_http_status(status: u16) -> Classification {
    let code = match status {
        401 | 403 => ErrorCode::Unauthorized,
        404 => ErrorCode::NotFound,
        _ => ErrorCode::ApiError,
    };
    Classification::new(code, Some(status))
}

/// A connect/timeout/DNS failure means the request never reached the server.
/// Any other reqwest failure is a local command failure.
fn classify_reqwest_error(error: &reqwest::Error) -> Classification {
    if error.is_connect() || error.is_timeout() || error.is_request() {
        Classification::new(ErrorCode::NetworkError, None)
    } else {
        Classification::new(ErrorCode::CommandError, None)
    }
}

/// Render an error's complete cause chain (anyhow's alternate `{error:#}`
/// display, links joined with `": "`), then truncate the result to
/// [`MAX_ERROR_MESSAGE_BYTES`].
pub(crate) fn render_error_chain(error: &anyhow::Error) -> String {
    truncate_message(format!("{error:#}"))
}

fn truncate_message(message: String) -> String {
    if message.len() <= MAX_ERROR_MESSAGE_BYTES {
        return message;
    }

    let total = message.len();
    // Truncate on a char boundary so we never split a UTF-8 sequence.
    let mut cut = MAX_ERROR_MESSAGE_BYTES;
    while !message.is_char_boundary(cut) {
        cut -= 1;
    }
    format!(
        "{}… [error message truncated; {total} bytes total]",
        &message[..cut]
    )
}

/// Map a [`TurnkeyClientError`] to its taxonomy code and optional HTTP status.
///
/// NOTE: this may fail to compile when new errors are introduced in upstream Turnkey code, which is good.
/// We should explicitly decide what kind of error it is here.
fn classify_turnkey_client_error(error: &TurnkeyClientError) -> Classification {
    match error {
        TurnkeyClientError::UnexpectedHttpStatus(status, _) => classify_http_status(*status),
        TurnkeyClientError::Http(reqwest_error) => classify_reqwest_error(reqwest_error),
        TurnkeyClientError::ActivityRequiresApproval(_) => {
            Classification::new(ErrorCode::ApprovalRequired, None)
        }
        // The server responded, but its response violated the expected API
        // protocol or the activity did not complete successfully.
        TurnkeyClientError::MissingContentTypeHeader
        | TurnkeyClientError::HeaderToStrError(_)
        | TurnkeyClientError::HeaderFromStrError(_)
        | TurnkeyClientError::UnexpectedMimeType(_)
        | TurnkeyClientError::Decode(_, _)
        | TurnkeyClientError::ActivityFailed(_)
        | TurnkeyClientError::UnexpectedActivityStatus(_)
        | TurnkeyClientError::UnexpectedInnerActivityResult(_)
        | TurnkeyClientError::MissingActivity
        | TurnkeyClientError::MissingResult
        | TurnkeyClientError::MissingInnerResult
        | TurnkeyClientError::ExceededRetries(_) => Classification::new(ErrorCode::ApiError, None),
        // These failures happen while configuring the client or constructing
        // and signing the request, before a usable API response is available.
        TurnkeyClientError::BuilderMissingApiKey
        | TurnkeyClientError::ReqwestBuilder(_)
        | TurnkeyClientError::SerdeJsonFailure(_)
        | TurnkeyClientError::StamperError(_) => Classification::new(ErrorCode::CommandError, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    fn client_error(error: TurnkeyClientError) -> anyhow::Error {
        anyhow::Error::new(error)
    }

    #[test]
    fn unexpected_http_404_is_not_found_with_status() {
        let error = client_error(TurnkeyClientError::UnexpectedHttpStatus(
            404,
            r#"{"message":"missing activity"}"#.to_string(),
        ))
        .context("failed to fetch activity abc-123");

        assert_eq!(
            classify(&error),
            Classification::new(ErrorCode::NotFound, Some(404))
        );
    }

    #[test]
    fn empty_response_not_found_maps_to_not_found_without_status() {
        let error = anyhow::Error::new(MissingResource::new("activity", "abc-123"))
            .context("failed to fetch activity abc-123");

        assert_eq!(
            classify(&error),
            Classification::new(ErrorCode::NotFound, None)
        );
    }

    #[test]
    fn http_401_and_403_map_to_unauthorized() {
        for status in [401u16, 403] {
            let error = client_error(TurnkeyClientError::UnexpectedHttpStatus(
                status,
                "denied".to_string(),
            ));
            assert_eq!(
                classify(&error),
                Classification::new(ErrorCode::Unauthorized, Some(status)),
                "status {status}"
            );
        }
    }

    #[test]
    fn other_http_status_maps_to_api_error() {
        let error = client_error(TurnkeyClientError::UnexpectedHttpStatus(
            500,
            "boom".to_string(),
        ));
        assert_eq!(
            classify(&error),
            Classification::new(ErrorCode::ApiError, Some(500))
        );
    }

    #[test]
    fn response_protocol_and_activity_failures_map_to_api_error() {
        let decode_error = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
        let errors = [
            TurnkeyClientError::MissingContentTypeHeader,
            TurnkeyClientError::HeaderToStrError("invalid header".to_string()),
            TurnkeyClientError::HeaderFromStrError("invalid MIME type".to_string()),
            TurnkeyClientError::UnexpectedMimeType("text/plain".to_string()),
            TurnkeyClientError::Decode("invalid JSON".to_string(), decode_error),
            TurnkeyClientError::MissingActivity,
            TurnkeyClientError::MissingResult,
            TurnkeyClientError::MissingInnerResult,
            TurnkeyClientError::UnexpectedActivityStatus("REJECTED".to_string()),
            TurnkeyClientError::UnexpectedInnerActivityResult("unexpected result".to_string()),
            TurnkeyClientError::ActivityFailed(None),
            TurnkeyClientError::ExceededRetries(3),
        ];

        for error in errors {
            let error = client_error(error);
            assert_eq!(
                classify(&error),
                Classification::new(ErrorCode::ApiError, None)
            );
        }
    }

    #[test]
    fn activity_requires_approval_maps_to_approval_required() {
        let error = client_error(TurnkeyClientError::ActivityRequiresApproval(
            "act-1".to_string(),
        ));
        assert_eq!(
            classify(&error),
            Classification::new(ErrorCode::ApprovalRequired, None)
        );
    }

    #[test]
    fn local_client_failures_map_to_command_error() {
        let serialization_error = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
        let errors = [
            TurnkeyClientError::BuilderMissingApiKey,
            TurnkeyClientError::SerdeJsonFailure(serialization_error),
            TurnkeyClientError::StamperError(turnkey_api_key_stamper::StamperError::HexDecode(
                "invalid hex".to_string(),
            )),
        ];

        for error in errors {
            let error = client_error(error);
            assert_eq!(
                classify(&error),
                Classification::new(ErrorCode::CommandError, None)
            );
        }
    }

    #[test]
    fn unrecognized_error_falls_back_to_command_error() {
        let error = anyhow!("some other failure").context("while doing a thing");
        assert_eq!(
            classify(&error),
            Classification::new(ErrorCode::CommandError, None)
        );
    }

    #[test]
    fn short_chain_renders_every_link() {
        let error = anyhow!("root cause").context("mid").context("top");

        assert_eq!(render_error_chain(&error), "top: mid: root cause");
    }

    #[test]
    fn truncated_message_is_capped_and_labeled() {
        let message = format!("failed: {}", "x".repeat(20_000));
        let error = anyhow!("{message}");
        let rendered = render_error_chain(&error);
        let expected = format!(
            "{}… [error message truncated; 20008 bytes total]",
            &message[..MAX_ERROR_MESSAGE_BYTES]
        );

        assert_eq!(rendered, expected);
    }

    #[test]
    fn truncated_message_preserves_utf8_char_boundaries() {
        let message = format!("a{}", "é".repeat(10_000));
        let error = anyhow!("{message}");
        let rendered = render_error_chain(&error);
        let expected = format!(
            "{}… [error message truncated; 20001 bytes total]",
            &message[..MAX_ERROR_MESSAGE_BYTES - 1]
        );

        assert_eq!(rendered, expected);
    }
}
