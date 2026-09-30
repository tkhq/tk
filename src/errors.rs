// This module defines ErrorCode and owns its classification.
#![allow(clippy::disallowed_types)]
use std::error::Error;

use serde::Serialize;
use serde_json::{Value, json};
use turnkey_client::TurnkeyClientError;
use uuid::Uuid;

use crate::{auth::SelectedIdentity, sessions::public_key::CompressedPublicKey};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct InvalidInput(pub String);

#[derive(Debug, thiserror::Error)]
#[error("{resource} not found: {id}")]
pub struct MissingResource {
    resource: &'static str,
    id: String,
}

impl MissingResource {
    pub fn new(resource: &'static str, id: impl Into<String>) -> Self {
        Self {
            resource,
            id: id.into(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{summary}")]
pub struct Malformed {
    summary: String,
    #[source]
    source: Box<dyn Error + Send + Sync>,
}

impl Malformed {
    pub fn new(summary: impl Into<String>, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            summary: summary.into(),
            source: Box::new(source),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("the selected identity ({identity}) belongs to organization {actual}, not {expected}")]
pub struct OrganizationMismatch {
    pub expected: Uuid,
    pub actual: Uuid,
    pub identity: SelectedIdentity,
}

#[cfg(test)]
pub(crate) fn assert_malformed_response(error: &anyhow::Error, chain: &[&str]) {
    let activity = error
        .downcast_ref::<ActivityError>()
        .expect("the error should be an ActivityError");
    assert_eq!(activity.kind(), ActivityErrorKind::MalformedResponse);
    let rendered: Vec<String> = error.chain().map(ToString::to_string).collect();
    assert_eq!(rendered, chain);
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct PendingApprovals {
    pub message: String,
    pub pending: Value,
}

#[derive(Debug, thiserror::Error)]
#[error(
    "credential for profile {profile} expires in {seconds_left}s (at unix ms {expires_at_unix_ms}), inside the {warn_before_seconds}s warning window; request a new session"
)]
pub struct SessionExpiring {
    pub profile: String,
    pub public_key: CompressedPublicKey,
    pub expires_at_unix_ms: u64,
    pub seconds_left: u64,
    pub warn_before_seconds: u64,
}

#[derive(Debug, thiserror::Error)]
#[error("HTTP response was not successful: {status} ({body})")]
pub struct UnexpectedHttpStatus {
    pub status: u16,
    pub body: String,
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
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
    source: Option<Box<dyn Error + Send + Sync>>,
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

    pub fn with_source(mut self, source: impl Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    pub fn kind(&self) -> ActivityErrorKind {
        self.kind
    }

    pub fn activity(&self) -> Option<&Value> {
        self.activity.as_ref()
    }
}

pub fn error_details(error: &anyhow::Error) -> Option<Value> {
    if let Some(pending) = error.downcast_ref::<PendingApprovals>() {
        return Some(json!({"pending": pending.pending}));
    }
    if let Some(expiring) = error.downcast_ref::<SessionExpiring>() {
        return Some(json!({
            "profile": expiring.profile,
            "publicKey": expiring.public_key,
            "expiresAt": expiring.expires_at_unix_ms.to_string(),
            "secondsLeft": expiring.seconds_left,
            "warnBeforeSeconds": expiring.warn_before_seconds,
        }));
    }
    error
        .downcast_ref::<ActivityError>()
        .and_then(ActivityError::activity)
        .map(|activity| json!({"activity": activity}))
}

const MAX_ERROR_MESSAGE_BYTES: usize = 8 * 1024;

#[derive(Serialize)]
#[cfg_attr(test, derive(Debug, Eq, PartialEq, strum::EnumIter))]
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
    /// A session credential ends within the requested warning window.
    SessionExpiring,
    /// Fallback for everything else.
    CommandError,
}

#[cfg_attr(test, derive(Debug, Eq, PartialEq))]
pub struct Classification {
    pub code: ErrorCode,
    pub http_status: Option<u16>,
}

impl Classification {
    fn new(code: ErrorCode, http_status: Option<u16>) -> Self {
        Self { code, http_status }
    }
}

pub fn classify(error: &anyhow::Error) -> Classification {
    for cause in error.chain() {
        if cause.downcast_ref::<InvalidInput>().is_some()
            || cause.downcast_ref::<Malformed>().is_some()
            || cause.downcast_ref::<OrganizationMismatch>().is_some()
        {
            return Classification::new(ErrorCode::InvalidInput, None);
        }
        if cause.downcast_ref::<MissingResource>().is_some() {
            return Classification::new(ErrorCode::NotFound, None);
        }
        if cause.downcast_ref::<SessionExpiring>().is_some() {
            return Classification::new(ErrorCode::SessionExpiring, None);
        }
        if cause.downcast_ref::<PendingApprovals>().is_some() {
            return Classification::new(ErrorCode::ApprovalRequired, None);
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

pub(crate) fn is_unauthorized(error: &anyhow::Error) -> bool {
    matches!(classify(error).code, ErrorCode::Unauthorized)
}

pub(crate) fn transient_status(status: u16) -> bool {
    status == 429 || status >= 500
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
    let message = format!("{error:#}");
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use anyhow::anyhow;
    use strum::IntoEnumIterator;

    use super::*;

    #[test]
    fn error_code_wire_names_are_unique() {
        let mut seen = BTreeSet::new();
        for code in ErrorCode::iter() {
            let name = serde_json::to_value(code)
                .expect("every error code must serialize")
                .as_str()
                .expect("every error code must serialize as a JSON string")
                .to_string();
            assert!(
                seen.insert(name.clone()),
                "wire name `{name}` is used by more than one ErrorCode variant"
            );
        }
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
            Classification {
                code: ErrorCode::NotFound,
                http_status: Some(404),
            }
        );
    }

    #[test]
    fn empty_response_not_found_maps_to_not_found_without_status() {
        let error = anyhow::Error::new(MissingResource::new("activity", "abc-123"))
            .context("failed to fetch activity abc-123");

        assert_eq!(
            classify(&error),
            Classification {
                code: ErrorCode::NotFound,
                http_status: None,
            }
        );
    }

    #[test]
    fn other_http_status_maps_to_api_error() {
        let error = client_error(TurnkeyClientError::UnexpectedHttpStatus(
            500,
            "boom".to_string(),
        ));
        assert_eq!(
            classify(&error),
            Classification {
                code: ErrorCode::ApiError,
                http_status: Some(500),
            }
        );
    }

    #[test]
    fn response_protocol_and_activity_failures_map_to_api_error() {
        let decode_error = serde_json::from_str::<Value>("{").unwrap_err();
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
                Classification {
                    code: ErrorCode::ApiError,
                    http_status: None,
                }
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
            Classification {
                code: ErrorCode::ApprovalRequired,
                http_status: None,
            }
        );
    }

    #[test]
    fn local_client_failures_map_to_command_error() {
        let serialization_error = serde_json::from_str::<Value>("{").unwrap_err();
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
                Classification {
                    code: ErrorCode::CommandError,
                    http_status: None,
                }
            );
        }
    }

    #[test]
    fn malformed_json_classifies_as_invalid_input_and_keeps_the_parse_error_as_source() {
        let parse_error = serde_json::from_str::<Value>("{").unwrap_err();
        let parse_message = parse_error.to_string();
        let error = anyhow::Error::new(Malformed::new("state is malformed", parse_error));

        assert_eq!(
            classify(&error),
            Classification {
                code: ErrorCode::InvalidInput,
                http_status: None,
            }
        );
        let malformed = error.downcast_ref::<Malformed>().unwrap();
        assert_eq!(malformed.source().unwrap().to_string(), parse_message);
    }

    #[test]
    fn activity_error_keeps_a_non_reqwest_source_in_the_chain() {
        let parse_error = serde_json::from_str::<Value>("{").unwrap_err();
        let parse_message = parse_error.to_string();
        let error = anyhow::Error::new(
            ActivityError::new(ActivityErrorKind::MalformedResponse, "bad response")
                .with_source(parse_error),
        );

        assert_eq!(
            classify(&error),
            Classification {
                code: ErrorCode::ApiError,
                http_status: None,
            }
        );
        let activity_error = error.downcast_ref::<ActivityError>().unwrap();
        assert_eq!(activity_error.source().unwrap().to_string(), parse_message);
    }

    #[test]
    fn unrecognized_error_falls_back_to_command_error() {
        let error = anyhow!("some other failure").context("while doing a thing");
        assert_eq!(
            classify(&error),
            Classification {
                code: ErrorCode::CommandError,
                http_status: None,
            }
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
