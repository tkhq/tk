use serde::Serialize;
pub use turnkey_auth::errors::MissingResource;
use turnkey_client::TurnkeyClientError;

// Bounds untrusted upstream bodies in one NDJSON record.
const MAX_ERROR_MESSAGE_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[cfg_attr(test, derive(strum::EnumIter))]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    MissingRequiredInput,
    UsageError,
    #[allow(dead_code, reason = "no command produces this code yet")]
    InvalidInput,
    Unauthorized,
    NotFound,
    ApiError,
    ApprovalRequired,
    NetworkError,
    NetworkUncertain,
    CommandError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
        if cause.downcast_ref::<MissingResource>().is_some() {
            return Classification::new(ErrorCode::NotFound, None);
        }
        if let Some(client_error) = cause.downcast_ref::<TurnkeyClientError>() {
            return classify_turnkey_client_error(client_error);
        }
    }
    Classification::new(ErrorCode::CommandError, None)
}

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

// Exhaustive by design: new upstream variants require an explicit classification.
fn classify_turnkey_client_error(error: &TurnkeyClientError) -> Classification {
    match error {
        TurnkeyClientError::UnexpectedHttpStatus(status, _)
        | TurnkeyClientError::RefusedRedirect(status, _) => {
            let code = match status {
                401 | 403 => ErrorCode::Unauthorized,
                404 => ErrorCode::NotFound,
                _ => ErrorCode::ApiError,
            };

            Classification::new(code, Some(*status))
        }
        // A connect error proves non-delivery and must precede the broader
        // request classification.
        TurnkeyClientError::Http(reqwest_error) if reqwest_error.is_connect() => {
            Classification::new(ErrorCode::NetworkError, None)
        }
        // Other transport-window failures cannot prove non-delivery; classify
        // conservatively to prevent unsafe mutation retries.
        TurnkeyClientError::Http(reqwest_error)
            if reqwest_error.is_timeout()
                || reqwest_error.is_request()
                || reqwest_error.is_body() =>
        {
            Classification::new(ErrorCode::NetworkUncertain, None)
        }
        TurnkeyClientError::ActivityRequiresApproval(_) => {
            Classification::new(ErrorCode::ApprovalRequired, None)
        }
        // Failures after an API response was available.
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
        // Failures before a usable API response was available.
        TurnkeyClientError::BuilderMissingApiKey
        | TurnkeyClientError::ReqwestBuilder(_)
        | TurnkeyClientError::Http(_)
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

    // More-indented taxonomy lines are continuations.
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
    fn every_error_code_is_documented_in_help() {
        let declared: BTreeSet<String> = ErrorCode::iter().map(wire_name).collect();
        let documented = documented_codes();

        let undocumented: Vec<_> = declared.difference(&documented).collect();
        assert!(
            undocumented.is_empty(),
            "these ErrorCode variants are missing from the --help taxonomy in cli.rs: {undocumented:?}"
        );

        let stale: Vec<_> = documented.difference(&declared).collect();
        assert!(
            stale.is_empty(),
            "the --help taxonomy in cli.rs documents codes that no longer exist: {stale:?}"
        );
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
