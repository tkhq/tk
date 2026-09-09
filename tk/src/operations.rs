//! Signed requests and resumable activity operations.
use std::fmt::{self, Display, Formatter};
use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use reqwest::{Client, Url, redirect::Policy};
use serde::Serialize;
use serde_json::{Value, json};
use turnkey_api_key_stamper::{Stamp, TurnkeyP256ApiKey};
use turnkey_client::generated::{
    GetActivitiesRequest, GetActivityRequest, external::options::v1::Pagination,
};

use crate::errors::{ActivityError, ActivityErrorKind, InvalidInput, UnexpectedHttpStatus};

/// Cap on the response body kept in an HTTP status error; the full chain is
/// capped again at the output boundary.
const MAX_ERROR_BODY_BYTES: usize = 4 * 1024;

#[derive(Debug, Args)]
pub struct RequestArgs {
    #[arg(long, value_parser = request_path)]
    path: String,
    #[arg(
        long,
        required_unless_present = "body_file",
        conflicts_with = "body_file"
    )]
    body: Option<String>,
    /// Read exact UTF-8 request bytes from a file, or - for stdin.
    #[arg(long, required_unless_present = "body", conflicts_with = "body")]
    body_file: Option<PathBuf>,
    /// Produce a stamp without submitting the request.
    #[arg(long)]
    stamp_only: bool,
}

#[derive(Debug, Subcommand)]
pub enum ActivityCommand {
    /// List activities, one page at a time.
    List {
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..))]
        limit: u32,
        /// API after cursor (activity ID); pagination is explicitly caller-driven.
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Fetch one activity by ID.
    Get { id: String },
    /// Approve a pending activity by ID.
    Approve { id: String },
    /// Reject a pending activity by ID.
    Reject { id: String },
    /// Poll one activity until it reaches a terminal status.
    Wait {
        id: String,
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..))]
        timeout: u64,
    },
}

/// A successful command record. Failures are typed errors rendered by the
/// output boundary, so a record's presence means the operation itself worked;
/// an inspected resource may still be in a rejected or pending state.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationOutput {
    schema_version: u32,
    reason: &'static str,
    command: &'static str,
    status: &'static str,
    data: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    activity: Option<Value>,
}

impl OperationOutput {
    pub fn result(command: &'static str, data: Value) -> Self {
        let activity = data
            .get("activity")
            .filter(|v| v.is_object())
            .map(|v| json!({"id":v.get("id"),"status":v.get("status")}));
        let status = activity
            .as_ref()
            .map(activity_status)
            .unwrap_or("completed");
        Self {
            schema_version: 1,
            reason: "command_result",
            command,
            status,
            data,
            activity,
        }
    }

    /// The activity identity this record observed, or a null identity.
    fn identity(&self) -> Value {
        self.activity
            .clone()
            .unwrap_or_else(|| json!({"id": null, "status": null}))
    }
}

impl Display for OperationOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            serde_json::to_string_pretty(self).map_err(|_| fmt::Error)?
        )
    }
}

fn activity_status(activity: &Value) -> &'static str {
    match activity.get("status").and_then(Value::as_str) {
        Some("ACTIVITY_STATUS_COMPLETED") => "completed",
        Some("ACTIVITY_STATUS_REJECTED") => "rejected",
        Some("ACTIVITY_STATUS_FAILED") => "failed",
        Some(
            "ACTIVITY_STATUS_CREATED"
            | "ACTIVITY_STATUS_PENDING"
            | "ACTIVITY_STATUS_CONSENSUS_NEEDED"
            | "ACTIVITY_STATUS_AUTHENTICATORS_NEEDED",
        ) => "pending",
        _ => "unknown",
    }
}

fn request_path(value: &str) -> Result<String, String> {
    if !value.starts_with("/public/v1/")
        || value.contains(['?', '#', '\\', '%'])
        || value.split('/').any(|s| s == ".." || s == ".")
    {
        return Err(
            "path must be an absolute /public/v1/ API path without query, fragment, or traversal"
                .into(),
        );
    }
    Ok(value.into())
}

/// Joins an API path onto the base URL by concatenation, exactly like the
/// typed client, so a base URL with a path prefix behaves the same everywhere.
fn url(base: &str, path: &str) -> Result<Url> {
    Url::parse(&format!("{}{path}", base.trim_end_matches('/')))
        .map_err(|_| InvalidInput("invalid request URL".into()).into())
}

fn client() -> Result<Client> {
    Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .context("could not initialize HTTP client")
}

/// Sends one stamped request. A `mutation` whose outcome cannot be observed is
/// reported as an unknown submission rather than a plain transport failure.
async fn post(
    http: &Client,
    endpoint: Url,
    body: String,
    stamper: &TurnkeyP256ApiKey,
    mutation: bool,
) -> Result<Value> {
    let stamp = stamper
        .stamp(body.as_bytes())
        .context("could not stamp request")?;
    let response = http
        .post(endpoint)
        .header(stamp.name, stamp.value)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|error| {
            if mutation {
                ActivityError::new(
                    ActivityErrorKind::SubmissionUnknown,
                    "request outcome is unknown; inspect activities before resubmitting",
                )
                .with_source(error)
                .into()
            } else {
                anyhow::Error::new(error).context("API request failed")
            }
        })?;
    let status = response.status();
    if !status.is_success() {
        let mut body = response
            .text()
            .await
            .unwrap_or_else(|_| "unreadable response body".into());
        if body.len() > MAX_ERROR_BODY_BYTES {
            let mut cut = MAX_ERROR_BODY_BYTES;
            while !body.is_char_boundary(cut) {
                cut -= 1;
            }
            body.truncate(cut);
            body.push('…');
        }
        return Err(UnexpectedHttpStatus {
            status: status.as_u16(),
            body,
        }
        .into());
    }
    response.json().await.map_err(|error| {
        let kind = if mutation {
            ActivityErrorKind::SubmissionUnknown
        } else {
            ActivityErrorKind::MalformedResponse
        };
        ActivityError::new(kind, "API returned an unreadable response")
            .with_source(error)
            .into()
    })
}

fn encode<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).context("could not encode request")
}

/// Wraps typed, locally validated parameters in the versioned activity
/// envelope used by every mutation.
pub fn envelope<T: Serialize>(kind: &str, organization_id: &str, parameters: &T) -> Result<Value> {
    Ok(json!({
        "type": kind,
        "timestampMs": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock precedes Unix epoch")?
            .as_millis()
            .to_string(),
        "organizationId": organization_id,
        "parameters": parameters,
        "generateAppProofs": null,
    }))
}

fn validate_body(body: &str, org: &str) -> Result<(), InvalidInput> {
    let value: Value =
        serde_json::from_str(body).map_err(|_| InvalidInput("body must be valid JSON".into()))?;
    if !value.is_object() {
        return Err(InvalidInput("body must be a JSON object".into()));
    }
    if value.get("organizationId").and_then(Value::as_str) != Some(org) {
        return Err(InvalidInput(
            "body organizationId must match selected organization".into(),
        ));
    }
    Ok(())
}

/// A raw request whose local body has been read and parsed before authentication.
pub struct PreparedRequest {
    path: String,
    body: String,
    stamp_only: bool,
}

impl RequestArgs {
    pub fn prepare(self) -> Result<PreparedRequest> {
        let body = match (self.body, self.body_file) {
            (Some(body), _) => body,
            (None, Some(path)) if path.as_os_str() == "-" => {
                let mut body = String::new();
                std::io::stdin()
                    .read_to_string(&mut body)
                    .map_err(|_| InvalidInput("could not read UTF-8 request body".into()))?;
                body
            }
            (None, Some(path)) => std::fs::read_to_string(path)
                .map_err(|_| InvalidInput("could not read UTF-8 request body".into()))?,
            (None, None) => unreachable!("clap requires exactly one body source"),
        };
        let value: Value = serde_json::from_str(&body)
            .map_err(|_| InvalidInput("body must be valid JSON".into()))?;
        if !value.is_object() {
            return Err(InvalidInput("body must be a JSON object".into()).into());
        }
        Ok(PreparedRequest {
            path: self.path,
            body,
            stamp_only: self.stamp_only,
        })
    }
}

impl PreparedRequest {
    pub async fn run(
        self,
        org_id: &str,
        api_base_url: &str,
        stamper: &TurnkeyP256ApiKey,
    ) -> Result<OperationOutput> {
        let command = "request";
        let body = self.body;
        validate_body(&body, org_id)?;
        let endpoint = url(api_base_url, &self.path)?;
        if self.stamp_only {
            let stamp = stamper
                .stamp(body.as_bytes())
                .context("could not stamp request")?;
            return Ok(OperationOutput::result(
                command,
                json!({"url":endpoint.as_str(),"method":"POST","header":{"name":stamp.name,"value":stamp.value},"body":body}),
            ));
        }
        let query = self.path.starts_with("/public/v1/query/");
        let value = post(&client()?, endpoint, body, stamper, !query).await?;
        if query {
            Ok(OperationOutput::result(command, value))
        } else {
            submission_result(command, value)
        }
    }
}

/// Interprets a submission response: the activity identity must be present so
/// the caller can recover, and terminal failures are errors.
fn submission_result(command: &'static str, data: Value) -> Result<OperationOutput> {
    if data
        .pointer("/activity/id")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(ActivityError::new(
            ActivityErrorKind::SubmissionUnknown,
            "response omitted activity identity; inspect activities before resubmitting",
        )
        .into());
    }
    terminal(OperationOutput::result(command, data), true)
}

/// Turns a rejected, failed, or unrecognized terminal status into an error
/// carrying the observed identity. `submitted` says whether this record came
/// from a mutation, which makes an unrecognized status an unknown submission.
fn terminal(output: OperationOutput, submitted: bool) -> Result<OperationOutput> {
    let failure = match output.status {
        "rejected" => (ActivityErrorKind::NotCompleted, "activity rejected"),
        "failed" => (ActivityErrorKind::NotCompleted, "activity failed"),
        "unknown" if submitted => (
            ActivityErrorKind::SubmissionUnknown,
            "unknown activity status; inspect activity before resubmitting",
        ),
        "unknown" => (
            ActivityErrorKind::MalformedResponse,
            "unknown activity status",
        ),
        _ => return Ok(output),
    };
    Err(ActivityError::new(failure.0, failure.1)
        .with_activity(output.identity())
        .into())
}

/// Attaches `target` to an activity error that has no identity yet.
fn with_target(error: anyhow::Error, target: &Value) -> anyhow::Error {
    match error.downcast::<ActivityError>() {
        Ok(activity) if activity.activity().is_none() => {
            activity.with_activity(target.clone()).into()
        }
        Ok(activity) => activity.into(),
        Err(error) => error,
    }
}

async fn query_activity(
    http: &Client,
    base: &str,
    org: &str,
    id: &str,
    stamper: &TurnkeyP256ApiKey,
) -> Result<Value> {
    let body = encode(&GetActivityRequest {
        organization_id: org.into(),
        activity_id: id.into(),
    })?;
    let endpoint = url(base, "/public/v1/query/get_activity")?;
    let value = post(http, endpoint, body, stamper, false).await?;
    let matches = value
        .pointer("/activity/id")
        .and_then(Value::as_str)
        .is_some_and(|returned| returned.eq_ignore_ascii_case(id));
    if !matches {
        return Err(ActivityError::new(
            ActivityErrorKind::MalformedResponse,
            "response omitted or mismatched requested activity",
        )
        .into());
    }
    Ok(value)
}

pub async fn run_activity(
    args: ActivityCommand,
    org_id: &str,
    api_base_url: &str,
    stamper: &TurnkeyP256ApiKey,
) -> Result<OperationOutput> {
    run_activity_with(&client()?, args, org_id, api_base_url, stamper).await
}

async fn run_activity_with(
    http: &Client,
    args: ActivityCommand,
    org: &str,
    base: &str,
    stamper: &TurnkeyP256ApiKey,
) -> Result<OperationOutput> {
    match args {
        ActivityCommand::List { limit, cursor } => {
            list(http, org, base, stamper, limit, cursor).await
        }
        ActivityCommand::Get { id } => {
            let value = query_activity(http, base, org, &id, stamper).await?;
            Ok(OperationOutput::result("activity.get", value))
        }
        ActivityCommand::Wait { id, timeout } => wait(http, org, base, stamper, &id, timeout).await,
        ActivityCommand::Approve { id } => vote(http, org, base, stamper, &id, true).await,
        ActivityCommand::Reject { id } => vote(http, org, base, stamper, &id, false).await,
    }
}

async fn list(
    http: &Client,
    org: &str,
    base: &str,
    stamper: &TurnkeyP256ApiKey,
    limit: u32,
    cursor: Option<String>,
) -> Result<OperationOutput> {
    let request = GetActivitiesRequest {
        organization_id: org.into(),
        filter_by_status: vec![],
        filter_by_type: vec![],
        pagination_options: Some(Pagination {
            limit: limit.to_string(),
            before: String::new(),
            after: cursor.unwrap_or_default(),
        }),
    };
    let endpoint = url(base, "/public/v1/query/list_activities")?;
    let response = post(http, endpoint, encode(&request)?, stamper, false).await?;
    let items = response
        .get("activities")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ActivityError::new(
                ActivityErrorKind::MalformedResponse,
                "response omitted activities",
            )
        })?;
    // The API exposes no hasNextPage. Return a continuation candidate rather
    // than claim a full page proves more results exist.
    let next = if items.len() == limit as usize {
        items.last().and_then(|item| item.get("id")).cloned()
    } else {
        None
    };
    Ok(OperationOutput::result(
        "activity.list",
        json!({"items":items,"nextCursor":next}),
    ))
}

async fn wait(
    http: &Client,
    org: &str,
    base: &str,
    stamper: &TurnkeyP256ApiKey,
    id: &str,
    seconds: u64,
) -> Result<OperationOutput> {
    let command = "activity.wait";
    let mut last = None;
    let result = tokio::time::timeout(Duration::from_secs(seconds), async {
        loop {
            let value = query_activity(http, base, org, id, stamper).await?;
            let output = OperationOutput::result(command, value);
            if output.status != "pending" {
                return terminal(output, false);
            }
            last = output.activity;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await;
    match result {
        Ok(result) => result,
        Err(_) => Err(ActivityError::new(
            ActivityErrorKind::WaitTimeout,
            "wait timed out; resume with activity wait and the same ID",
        )
        .with_activity(last.unwrap_or_else(|| json!({"id": id, "status": null})))
        .into()),
    }
}

/// Fetches the activity's fingerprint by ID and submits exactly one vote.
async fn vote(
    http: &Client,
    org: &str,
    base: &str,
    stamper: &TurnkeyP256ApiKey,
    id: &str,
    approve: bool,
) -> Result<OperationOutput> {
    let command = if approve {
        "activity.approve"
    } else {
        "activity.reject"
    };
    let value = query_activity(http, base, org, id, stamper).await?;
    // This is the last observed target state, not proof of the vote's outcome.
    // Failures carry it so callers have an identity to inspect.
    let target = json!({"id": id, "status": value.pointer("/activity/status")});
    let submitted = async {
        let fingerprint = value
            .pointer("/activity/fingerprint")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                ActivityError::new(
                    ActivityErrorKind::MalformedResponse,
                    "activity omitted fingerprint",
                )
            })?
            .to_owned();
        let (path, kind) = if approve {
            (
                "/public/v1/submit/approve_activity",
                "ACTIVITY_TYPE_APPROVE_ACTIVITY",
            )
        } else {
            (
                "/public/v1/submit/reject_activity",
                "ACTIVITY_TYPE_REJECT_ACTIVITY",
            )
        };
        let body = encode(&envelope(
            kind,
            org,
            &json!({ "fingerprint": fingerprint }),
        )?)?;
        let response = post(http, url(base, path)?, body, stamper, true).await?;
        if response
            .pointer("/activity/id")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(ActivityError::new(
                ActivityErrorKind::SubmissionUnknown,
                "response omitted activity; inspect activity before resubmitting",
            )
            .into());
        }
        let output = OperationOutput::result(command, response);
        // A rejected target is the successful outcome of an explicit rejection.
        if !approve && output.status == "rejected" {
            Ok(output)
        } else {
            terminal(output, true)
        }
    }
    .await;
    submitted.map_err(|error| with_target(error, &target))
}

/// Submit one typed activity envelope without implicit retries or result unwrapping.
pub async fn submit<T: Serialize>(
    command: &'static str,
    path: &str,
    request: &T,
    api_base_url: &str,
    stamper: &TurnkeyP256ApiKey,
) -> Result<OperationOutput> {
    let body = encode(request)?;
    let endpoint = url(api_base_url, path)?;
    let value = post(&client()?, endpoint, body, stamper, true).await?;
    submission_result(command, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use turnkey_client::generated::external::activity::v1::ApproveActivityRequest;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string, header_exists, method, path},
    };
    #[derive(Parser)]
    struct RequestCli {
        #[command(flatten)]
        request: RequestArgs,
    }
    #[derive(Parser)]
    struct ActivityCli {
        #[command(subcommand)]
        activity: ActivityCommand,
    }
    fn activity(id: &str, status: &str) -> Value {
        json!({"activity":{"id":id,"status":status,"fingerprint":"sha256:example"}})
    }
    async fn run_request(
        args: RequestArgs,
        org: &str,
        base: &str,
        stamper: &TurnkeyP256ApiKey,
    ) -> Result<OperationOutput> {
        args.prepare()?.run(org, base, stamper).await
    }
    fn activity_error(error: &anyhow::Error) -> &ActivityError {
        error.downcast_ref::<ActivityError>().unwrap()
    }
    #[test]
    fn result_serialization_preserves_the_machine_contract() {
        let data = json!({"activity":{"id":"a","status":"ACTIVITY_STATUS_COMPLETED"}});
        let output = OperationOutput::result("test", data);
        assert_eq!(
            serde_json::to_value(output).unwrap(),
            json!({
                "schemaVersion":1,"reason":"command_result","command":"test","status":"completed",
                "data":{"activity":{"id":"a","status":"ACTIVITY_STATUS_COMPLETED"}},
                "activity":{"id":"a","status":"ACTIVITY_STATUS_COMPLETED"}
            })
        );
    }
    #[test]
    fn submission_requires_recoverable_activity_identity() {
        let error = submission_result(
            "test",
            json!({"activity":{"status":"ACTIVITY_STATUS_COMPLETED"}}),
        )
        .unwrap_err();
        assert_eq!(
            activity_error(&error).kind(),
            ActivityErrorKind::SubmissionUnknown
        );
    }
    #[test]
    fn url_keeps_a_base_path_prefix() {
        assert_eq!(
            url("http://host/prefix/", "/public/v1/query/whoami")
                .unwrap()
                .as_str(),
            "http://host/prefix/public/v1/query/whoami"
        );
    }
    #[test]
    fn parser_enforces_body_source_and_safe_path() {
        assert!(RequestCli::try_parse_from(["tk", "--path", "/public/v1/query/whoami"]).is_err());
        assert!(
            RequestCli::try_parse_from([
                "tk",
                "--path",
                "/public/v1/query/whoami",
                "--body",
                "{}",
                "--body-file",
                "-"
            ])
            .is_err()
        );
        assert!(
            RequestCli::try_parse_from(["tk", "--path", "https://other.test", "--body", "{}"])
                .is_err()
        );
        assert!(ActivityCli::try_parse_from(["tk", "wait", "a", "--timeout", "0"]).is_err());
    }
    #[tokio::test]
    async fn raw_request_preserves_signed_bytes() {
        let server = MockServer::start().await;
        let body = "{\n  \"organizationId\": \"org\"\n}\n";
        let key = TurnkeyP256ApiKey::generate();
        let stamp = key.stamp(body.as_bytes()).unwrap();
        Mock::given(method("POST"))
            .and(path("/public/v1/query/whoami"))
            .and(body_string(body))
            .and(wiremock::matchers::header(
                stamp.name.as_str(),
                stamp.value.as_str(),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"userId":"user"})))
            .expect(1)
            .mount(&server)
            .await;
        let output = run_request(
            RequestArgs {
                path: "/public/v1/query/whoami".into(),
                body: Some(body.into()),
                body_file: None,
                stamp_only: false,
            },
            "org",
            &server.uri(),
            &key,
        )
        .await
        .unwrap();
        assert_eq!(output.data, json!({"userId":"user"}));
        server.verify().await;
    }
    #[tokio::test]
    async fn stamp_only_and_mismatch_make_no_requests() {
        let server = MockServer::start().await;
        let key = TurnkeyP256ApiKey::generate();
        let args = |org: &str| RequestArgs {
            path: "/public/v1/query/whoami".into(),
            body: Some(json!({"organizationId":org}).to_string()),
            body_file: None,
            stamp_only: true,
        };
        run_request(args("org"), "org", &server.uri(), &key)
            .await
            .unwrap();
        let error = run_request(args("other"), "org", &server.uri(), &key)
            .await
            .unwrap_err();
        assert!(error.downcast_ref::<InvalidInput>().is_some());
        assert!(server.received_requests().await.unwrap().is_empty());
    }
    #[tokio::test]
    async fn redirect_is_not_followed_and_body_is_kept() {
        let server = MockServer::start().await;
        Mock::given(path("/public/v1/submit/test"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("Location", "/leaked")
                    .set_body_string("moved"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let key = TurnkeyP256ApiKey::generate();
        let error = submit(
            "test",
            "/public/v1/submit/test",
            &json!({}),
            &server.uri(),
            &key,
        )
        .await
        .unwrap_err();
        let http = error.downcast_ref::<UnexpectedHttpStatus>().unwrap();
        assert_eq!(http.status, 307);
        assert_eq!(http.body, "moved");
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
    #[tokio::test]
    async fn pending_submission_retains_activity_without_retry() {
        let server = MockServer::start().await;
        Mock::given(path("/public/v1/submit/test"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(activity("a", "ACTIVITY_STATUS_CONSENSUS_NEEDED")),
            )
            .expect(1)
            .mount(&server)
            .await;
        let output = submit(
            "test",
            "/public/v1/submit/test",
            &json!({}),
            &server.uri(),
            &TurnkeyP256ApiKey::generate(),
        )
        .await
        .unwrap();
        assert_eq!(output.status, "pending");
        assert_eq!(
            output.activity,
            Some(json!({"id":"a","status":"ACTIVITY_STATUS_CONSENSUS_NEEDED"}))
        );
        server.verify().await;
    }
    #[tokio::test]
    async fn wait_timeout_retains_identity_and_get_rejection_is_success() {
        let server = MockServer::start().await;
        let key = TurnkeyP256ApiKey::generate();
        Mock::given(path("/public/v1/query/get_activity"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(activity("a", "ACTIVITY_STATUS_CONSENSUS_NEEDED")),
            )
            .mount(&server)
            .await;
        let error = run_activity(
            ActivityCommand::Wait {
                id: "a".into(),
                timeout: 1,
            },
            "org",
            &server.uri(),
            &key,
        )
        .await
        .unwrap_err();
        let timed_out = activity_error(&error);
        assert_eq!(timed_out.kind(), ActivityErrorKind::WaitTimeout);
        assert_eq!(
            timed_out.activity(),
            Some(&json!({"id":"a","status":"ACTIVITY_STATUS_CONSENSUS_NEEDED"}))
        );
        server.reset().await;
        Mock::given(path("/public/v1/query/get_activity"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(activity("a", "ACTIVITY_STATUS_REJECTED")),
            )
            .mount(&server)
            .await;
        let output = run_activity(
            ActivityCommand::Get { id: "A".into() },
            "org",
            &server.uri(),
            &key,
        )
        .await
        .unwrap();
        assert_eq!(output.status, "rejected");
        let waited = run_activity(
            ActivityCommand::Wait {
                id: "a".into(),
                timeout: 1,
            },
            "org",
            &server.uri(),
            &key,
        )
        .await
        .unwrap_err();
        assert_eq!(
            activity_error(&waited).kind(),
            ActivityErrorKind::NotCompleted
        );
    }
    #[tokio::test]
    async fn reject_success_and_malformed_submission_are_distinct() {
        let server = MockServer::start().await;
        let key = TurnkeyP256ApiKey::generate();
        Mock::given(path("/public/v1/query/get_activity"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(activity("a", "ACTIVITY_STATUS_CONSENSUS_NEEDED")),
            )
            .mount(&server)
            .await;
        Mock::given(path("/public/v1/submit/reject_activity"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(activity("a", "ACTIVITY_STATUS_REJECTED")),
            )
            .expect(1)
            .mount(&server)
            .await;
        let output = run_activity(
            ActivityCommand::Reject { id: "a".into() },
            "org",
            &server.uri(),
            &key,
        )
        .await
        .unwrap();
        assert_eq!(output.status, "rejected");
        Mock::given(path("/public/v1/submit/test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(1)
            .mount(&server)
            .await;
        let error = submit(
            "test",
            "/public/v1/submit/test",
            &json!({}),
            &server.uri(),
            &key,
        )
        .await
        .unwrap_err();
        assert_eq!(
            activity_error(&error).kind(),
            ActivityErrorKind::SubmissionUnknown
        );
        server.verify().await;
    }
    #[tokio::test]
    async fn list_preserves_api_cursor_and_does_not_fetch_extra_pages() {
        let server = MockServer::start().await;
        Mock::given(path("/public/v1/query/list_activities"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"activities":[{"id":"b"}]})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let output = run_activity(
            ActivityCommand::List {
                limit: 1,
                cursor: Some("a".into()),
            },
            "org",
            &server.uri(),
            &TurnkeyP256ApiKey::generate(),
        )
        .await
        .unwrap();
        assert_eq!(output.data, json!({"items":[{"id":"b"}],"nextCursor":"b"}));
        let requests = server.received_requests().await.unwrap();
        let request: GetActivitiesRequest = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(
            request.pagination_options,
            Some(Pagination {
                limit: "1".into(),
                before: String::new(),
                after: "a".into()
            })
        );
        server.verify().await;
    }
    #[tokio::test]
    async fn mutation_timeout_is_unknown_and_does_not_leak_body() {
        let server = MockServer::start().await;
        Mock::given(path("/public/v1/submit/test"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(100))
                    .set_body_json(json!({})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let http = Client::builder()
            .timeout(Duration::from_millis(10))
            .build()
            .unwrap();
        let error = post(
            &http,
            url(&server.uri(), "/public/v1/submit/test").unwrap(),
            "secret-marker".into(),
            &TurnkeyP256ApiKey::generate(),
            true,
        )
        .await
        .unwrap_err();
        assert_eq!(
            activity_error(&error).kind(),
            ActivityErrorKind::SubmissionUnknown
        );
        assert!(!format!("{error:#}").contains("secret-marker"));
        assert!(error.chain().any(|cause| cause.is::<reqwest::Error>()));
        server.verify().await;
    }
    #[tokio::test]
    async fn vote_submission_failures_retain_last_observed_target() {
        for approve in [true, false] {
            for timeout in [true, false] {
                let server = MockServer::start().await;
                let key = TurnkeyP256ApiKey::generate();
                Mock::given(path("/public/v1/query/get_activity"))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(activity("target", "ACTIVITY_STATUS_CONSENSUS_NEEDED")),
                    )
                    .expect(1)
                    .mount(&server)
                    .await;
                let vote_path = if approve {
                    "/public/v1/submit/approve_activity"
                } else {
                    "/public/v1/submit/reject_activity"
                };
                let response = ResponseTemplate::new(200).set_body_json(json!({}));
                Mock::given(path(vote_path))
                    .respond_with(if timeout {
                        response.set_delay(Duration::from_millis(500))
                    } else {
                        response
                    })
                    .expect(1)
                    .mount(&server)
                    .await;
                let http = Client::builder()
                    .timeout(Duration::from_millis(100))
                    .build()
                    .unwrap();
                let args = if approve {
                    ActivityCommand::Approve {
                        id: "target".into(),
                    }
                } else {
                    ActivityCommand::Reject {
                        id: "target".into(),
                    }
                };
                let error = run_activity_with(&http, args, "org", &server.uri(), &key)
                    .await
                    .unwrap_err();
                let failure = activity_error(&error);
                assert_eq!(failure.kind(), ActivityErrorKind::SubmissionUnknown);
                assert_eq!(
                    failure.activity(),
                    Some(&json!({"id":"target", "status":"ACTIVITY_STATUS_CONSENSUS_NEEDED"}))
                );
                server.verify().await;
            }
        }
    }
    #[tokio::test]
    async fn approve_fetches_fingerprint_then_submits_once() {
        let server = MockServer::start().await;
        Mock::given(path("/public/v1/query/get_activity"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(activity("a", "ACTIVITY_STATUS_CONSENSUS_NEEDED")),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path("/public/v1/submit/approve_activity"))
            .and(header_exists("X-Stamp"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(activity("vote", "ACTIVITY_STATUS_COMPLETED")),
            )
            .expect(1)
            .mount(&server)
            .await;
        run_activity(
            ActivityCommand::Approve { id: "a".into() },
            "org",
            &server.uri(),
            &TurnkeyP256ApiKey::generate(),
        )
        .await
        .unwrap();
        let requests = server.received_requests().await.unwrap();
        let body: ApproveActivityRequest = serde_json::from_slice(&requests[1].body).unwrap();
        assert_eq!(body.parameters.unwrap().fingerprint, "sha256:example");
        assert_eq!(body.organization_id, "org");
        server.verify().await;
    }
}
