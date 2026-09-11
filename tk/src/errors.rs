use serde::Serialize;
use serde_json::Value;
pub use turnkey_auth::errors::MissingResource;
use turnkey_client::TurnkeyClientError;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct InvalidInput(pub String);

#[derive(Debug, thiserror::Error)]
#[error("HTTP response was not successful: {status} ({body})")]
pub struct UnexpectedHttpStatus {
    pub status: u16,
    pub body: String,
}

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
    pub fn new(kind: ActivityErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            activity: None,
            message: message.into(),
            source: None,
        }
    }

    pub fn with_activity(mut self, activity: Value) -> Self {
        self.activity = Some(activity);
        self
    }

    pub fn with_source(mut self, source: reqwest::Error) -> Self {
        self.source = Some(source);
        self
    }

    pub fn kind(&self) -> ActivityErrorKind {
        self.kind
    }

    pub fn activity(&self) -> Option<&Value> {
        self.activity.as_ref()
    }
}

pub fn activity_identity(error: &anyhow::Error) -> Option<&Value> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<ActivityError>())
        .and_then(ActivityError::activity)
}

const MAX_ERROR_MESSAGE_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[cfg_attr(test, derive(strum::EnumIter))]
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
    /// A connection failure that proves the request never reached the server.
    NetworkError,
    /// A transport failure where request delivery cannot be ruled out.
    NetworkUncertain,
    /// A mutation was sent but its outcome is unknown; inspect before retrying.
    SubmissionUnknown,
    /// `activity wait` timed out while the activity was still pending.
    WaitTimeout,
    /// Fallback for everything else.
    CommandError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Classification {
    pub code: ErrorCode,
    pub http_status: Option<u16>,
}

impl Classification {
    pub(crate) fn new(code: ErrorCode, http_status: Option<u16>) -> Self {
        Self { code, http_status }
    }
}

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

fn classify_reqwest_error(error: &reqwest::Error) -> Classification {
    if error.is_connect() {
        Classification::new(ErrorCode::NetworkError, None)
    } else if error.is_timeout() || error.is_request() || error.is_body() {
        Classification::new(ErrorCode::NetworkUncertain, None)
    } else {
        Classification::new(ErrorCode::CommandError, None)
    }
}

pub(crate) fn render_error_chain(error: &anyhow::Error) -> String {
    truncate_message(format!("{error:#}"))
}

fn truncate_message(message: String) -> String {
    if message.len() <= MAX_ERROR_MESSAGE_BYTES {
        return message;
    }

    let total = message.len();
    let mut cut = MAX_ERROR_MESSAGE_BYTES;
    while !message.is_char_boundary(cut) {
        cut -= 1;
    }
    format!(
        "{}… [error message truncated; {total} bytes total]",
        &message[..cut]
    )
}

fn classify_turnkey_client_error(error: &TurnkeyClientError) -> Classification {
    match error {
        TurnkeyClientError::UnexpectedHttpStatus(status, _)
        | TurnkeyClientError::RefusedRedirect(status, _) => classify_http_status(*status),
        TurnkeyClientError::Http(reqwest_error) => classify_reqwest_error(reqwest_error),
        TurnkeyClientError::ActivityRequiresApproval(_) => {
            Classification::new(ErrorCode::ApprovalRequired, None)
        }
        TurnkeyClientError::MissingContentTypeHeader
        | TurnkeyClientError::HeaderToStrError(_)
        | TurnkeyClientError::HeaderFromStrError(_)
        | TurnkeyClientError::UnexpectedMimeType(_)
        | TurnkeyClientError::Decode(_, _)
        | TurnkeyClientError::ActivityFailed(_)
        | TurnkeyClientError::UnexpectedActivityStatus(_)
        | TurnkeyClientError::UnexpectedInnerActivityResult(_)
        | TurnkeyClientError::UnexpectedSingletonCount(_, _)
        | TurnkeyClientError::UnexpectedResultCount(_, _, _)
        | TurnkeyClientError::MissingActivity
        | TurnkeyClientError::MissingResult
        | TurnkeyClientError::MissingInnerResult
        | TurnkeyClientError::ExceededRetries(_) => Classification::new(ErrorCode::ApiError, None),
        TurnkeyClientError::BuilderMissingApiKey
        | TurnkeyClientError::ReqwestBuilder(_)
        | TurnkeyClientError::SerdeJsonFailure(_)
        | TurnkeyClientError::StamperError(_)
        | TurnkeyClientError::EnclaveEncrypt(_) => {
            Classification::new(ErrorCode::CommandError, None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use std::collections::BTreeSet;
    use strum::IntoEnumIterator;

    fn wire_name(code: ErrorCode) -> String {
        serde_json::to_value(code)
            .expect("every error code must serialize")
            .as_str()
            .expect("every error code must serialize as a JSON string")
            .to_string()
    }

    fn documented_codes() -> BTreeSet<String> {
        crate::cli::LONG_ABOUT
            .lines()
            .filter_map(|line| {
                let rest = line.strip_prefix("        ")?;
                if rest.starts_with(' ') {
                    return None;
                }
                let (token, _) = rest.split_once("  ")?;
                token
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_')
                    .then(|| token.to_string())
            })
            .collect()
    }

    #[test]
    fn error_code_wire_names_are_unique() {
        let mut seen = BTreeSet::new();
        for code in ErrorCode::iter() {
            let name = wire_name(code);
            assert!(
                seen.insert(name.clone()),
                "wire name `{name}` is used by more than one ErrorCode variant"
            );
        }
    }

    #[test]
    fn help_documents_every_error_code() {
        let declared: BTreeSet<String> = ErrorCode::iter().map(wire_name).collect();
        let documented = documented_codes();
        assert_eq!(documented, declared);
    }

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
