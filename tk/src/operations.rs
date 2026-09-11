use std::fmt::{self, Display, Formatter};
use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use reqwest::{Client, Url};
use serde::Serialize;
use serde_json::{Value, json};
use turnkey_api_key_stamper::{Stamp, TurnkeyP256ApiKey};
use turnkey_client::generated::{
    ActivityStatus, GetActivitiesRequest, GetActivityRequest, external::options::v1::Pagination,
};
use uuid::Uuid;

use crate::auth::{ResolvedAuth, transport};
use crate::errors::{ActivityError, ActivityErrorKind, InvalidInput, UnexpectedHttpStatus};

const POLL_INTERVAL: Duration = Duration::from_millis(500);

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
    let Some(status) = activity
        .get("status")
        .and_then(Value::as_str)
        .and_then(ActivityStatus::from_str_name)
    else {
        return "unknown";
    };
    match status {
        ActivityStatus::Completed => "completed",
        ActivityStatus::Rejected => "rejected",
        ActivityStatus::Failed => "failed",
        ActivityStatus::Created
        | ActivityStatus::Pending
        | ActivityStatus::ConsensusNeeded
        | ActivityStatus::AuthenticatorsNeeded => "pending",
        ActivityStatus::Unspecified => "unknown",
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

fn url(base: &str, path: &str) -> Result<Url> {
    Url::parse(&format!("{}{path}", base.trim_end_matches('/')))
        .map_err(|_| InvalidInput("invalid request URL".into()).into())
}

fn client() -> Result<Client> {
    transport(Client::builder())
        .build()
        .context("could not initialize HTTP client")
}

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
            if mutation && !error.is_connect() {
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

fn envelope<T: Serialize>(kind: &str, organization_id: &str, parameters: &T) -> Result<Value> {
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
    let body_org = value
        .get("organizationId")
        .and_then(Value::as_str)
        .and_then(|id| Uuid::parse_str(id).ok());
    if body_org.is_none_or(|id| Uuid::parse_str(org) != Ok(id)) {
        return Err(InvalidInput(
            "body organizationId must match selected organization".into(),
        ));
    }
    Ok(())
}

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
    pub async fn run(self, auth: &ResolvedAuth) -> Result<OperationOutput> {
        let command = "request";
        let body = self.body;
        validate_body(&body, &auth.org_id)?;
        let endpoint = url(&auth.api_base_url, &self.path)?;
        if self.stamp_only {
            let stamp = auth
                .stamper
                .stamp(body.as_bytes())
                .context("could not stamp request")?;
            return Ok(OperationOutput::result(
                command,
                json!({"url":endpoint.as_str(),"method":"POST","header":{"name":stamp.name,"value":stamp.value},"body":body}),
            ));
        }
        let query = self.path.starts_with("/public/v1/query/");
        let value = post(&client()?, endpoint, body, &auth.stamper, !query).await?;
        if query {
            Ok(OperationOutput::result(command, value))
        } else {
            submission_result(command, value)
        }
    }
}

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

fn with_target(error: anyhow::Error, target: Value) -> anyhow::Error {
    match error.downcast::<ActivityError>() {
        Ok(activity) if activity.activity().is_none() => activity.with_activity(target).into(),
        Ok(activity) => activity.into(),
        Err(error) => error,
    }
}

async fn query_activity(http: &Client, auth: &ResolvedAuth, id: &str) -> Result<Value> {
    let body = encode(&GetActivityRequest {
        organization_id: auth.org_id.clone(),
        activity_id: id.into(),
    })?;
    let endpoint = url(&auth.api_base_url, "/public/v1/query/get_activity")?;
    let value = post(http, endpoint, body, &auth.stamper, false).await?;
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

pub async fn run_activity(args: ActivityCommand, auth: &ResolvedAuth) -> Result<OperationOutput> {
    run_activity_with(&client()?, args, auth).await
}

async fn run_activity_with(
    http: &Client,
    args: ActivityCommand,
    auth: &ResolvedAuth,
) -> Result<OperationOutput> {
    match args {
        ActivityCommand::List { limit, cursor } => list(http, auth, limit, cursor).await,
        ActivityCommand::Get { id } => {
            let value = query_activity(http, auth, &id).await?;
            Ok(OperationOutput::result("activity.get", value))
        }
        ActivityCommand::Wait { id, timeout } => wait(http, auth, &id, timeout).await,
        ActivityCommand::Approve { id } => vote(http, auth, &id, true).await,
        ActivityCommand::Reject { id } => vote(http, auth, &id, false).await,
    }
}

async fn list(
    http: &Client,
    auth: &ResolvedAuth,
    limit: u32,
    cursor: Option<String>,
) -> Result<OperationOutput> {
    let request = GetActivitiesRequest {
        organization_id: auth.org_id.clone(),
        filter_by_status: vec![],
        filter_by_type: vec![],
        pagination_options: Some(Pagination {
            limit: limit.to_string(),
            before: String::new(),
            after: cursor.unwrap_or_default(),
        }),
    };
    let endpoint = url(&auth.api_base_url, "/public/v1/query/list_activities")?;
    let response = post(http, endpoint, encode(&request)?, &auth.stamper, false).await?;
    let items = response
        .get("activities")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ActivityError::new(
                ActivityErrorKind::MalformedResponse,
                "response omitted activities",
            )
        })?;
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
    auth: &ResolvedAuth,
    id: &str,
    seconds: u64,
) -> Result<OperationOutput> {
    let command = "activity.wait";
    let mut last: Option<Value> = None;
    let result = tokio::time::timeout(Duration::from_secs(seconds), async {
        loop {
            match query_activity(http, auth, id).await {
                Ok(value) => {
                    let output = OperationOutput::result(command, value);
                    if output.status != "pending" {
                        return terminal(output, false);
                    }
                    last = output.activity;
                }
                Err(error) if transient(&error) => {}
                Err(error) => {
                    let target = last
                        .take()
                        .unwrap_or_else(|| json!({"id": id, "status": null}));
                    return Err(with_target(error, target));
                }
            }
            tokio::time::sleep(POLL_INTERVAL).await;
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

fn transient(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<UnexpectedHttpStatus>()
            .is_some_and(|http| http.status >= 500 || http.status == 429)
            || cause.downcast_ref::<reqwest::Error>().is_some()
    })
}

async fn vote(
    http: &Client,
    auth: &ResolvedAuth,
    id: &str,
    approve: bool,
) -> Result<OperationOutput> {
    let command = if approve {
        "activity.approve"
    } else {
        "activity.reject"
    };
    let value = query_activity(http, auth, id).await?;
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
            &auth.org_id,
            &json!({ "fingerprint": fingerprint }),
        )?)?;
        let response = post(
            http,
            url(&auth.api_base_url, path)?,
            body,
            &auth.stamper,
            true,
        )
        .await?;
        let returned = response
            .pointer("/activity/id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                ActivityError::new(
                    ActivityErrorKind::SubmissionUnknown,
                    "response omitted activity; inspect activity before resubmitting",
                )
            })?;
        let data = if returned.eq_ignore_ascii_case(id) {
            response
        } else {
            terminal(OperationOutput::result(command, response), true)?;
            query_activity(http, auth, id).await?
        };
        let output = OperationOutput::result(command, data);
        if !approve && output.status == "rejected" {
            Ok(output)
        } else {
            terminal(output, true)
        }
    }
    .await;
    submitted.map_err(|error| with_target(error, target))
}

pub async fn submit_activity<T: Serialize>(
    auth: &ResolvedAuth,
    command: &'static str,
    endpoint: &str,
    kind: &str,
    parameters: &T,
) -> Result<OperationOutput> {
    let body = encode(&envelope(kind, &auth.org_id, parameters)?)?;
    let endpoint = url(&auth.api_base_url, &format!("/public/v1/submit/{endpoint}"))?;
    let value = post(&client()?, endpoint, body, &auth.stamper, true).await?;
    submission_result(command, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::{Classification, ErrorCode, classify};
    use clap::Parser;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::path};
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

    const ORG: &str = "00000000-0000-4000-8000-000000000001";
    fn activity(id: &str, status: &str) -> Value {
        json!({"activity":{"id":id,"status":status,"fingerprint":"sha256:example"}})
    }

    fn auth(server: &MockServer, key: TurnkeyP256ApiKey) -> ResolvedAuth {
        ResolvedAuth::for_tests(ORG, &server.uri(), key)
    }

    fn json(route: &str, body: Value) -> Mock {
        Mock::given(path(format!("/public/v1/{route}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
    }

    fn get_activity(id: &str, status: &str) -> Mock {
        json("query/get_activity", activity(id, status))
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
    async fn reject_success_and_malformed_submission_are_distinct() {
        let server = MockServer::start().await;
        let auth = auth(&server, TurnkeyP256ApiKey::generate());
        get_activity("a", "ACTIVITY_STATUS_CONSENSUS_NEEDED")
            .mount(&server)
            .await;
        json(
            "submit/reject_activity",
            activity("a", "ACTIVITY_STATUS_REJECTED"),
        )
        .expect(1)
        .mount(&server)
        .await;
        let output = run_activity(ActivityCommand::Reject { id: "a".into() }, &auth)
            .await
            .unwrap();
        assert_eq!(output.status, "rejected");
        json("submit/test", json!({}))
            .expect(1)
            .mount(&server)
            .await;
        let error = submit_activity(&auth, "test", "test", "ACTIVITY_TYPE_TEST", &json!({}))
            .await
            .unwrap_err();
        assert_eq!(
            activity_error(&error).kind(),
            ActivityErrorKind::SubmissionUnknown
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn rejected_reject_proposal_is_not_a_rejected_target() {
        let server = MockServer::start().await;
        let auth = auth(&server, TurnkeyP256ApiKey::generate());
        get_activity("target", "ACTIVITY_STATUS_CONSENSUS_NEEDED")
            .expect(1)
            .mount(&server)
            .await;
        json(
            "submit/reject_activity",
            activity("decision", "ACTIVITY_STATUS_REJECTED"),
        )
        .expect(1)
        .mount(&server)
        .await;
        let error = run_activity(
            ActivityCommand::Reject {
                id: "target".into(),
            },
            &auth,
        )
        .await
        .unwrap_err();
        let error = activity_error(&error);
        assert_eq!(error.kind(), ActivityErrorKind::NotCompleted);
        assert_eq!(
            error.activity(),
            Some(&json!({"id": "decision", "status": "ACTIVITY_STATUS_REJECTED"}))
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn completed_vote_proposal_reports_the_target_status() {
        let server = MockServer::start().await;
        let auth = auth(&server, TurnkeyP256ApiKey::generate());
        get_activity("target", "ACTIVITY_STATUS_CONSENSUS_NEEDED")
            .expect(2)
            .mount(&server)
            .await;
        json(
            "submit/approve_activity",
            activity("decision", "ACTIVITY_STATUS_COMPLETED"),
        )
        .expect(1)
        .mount(&server)
        .await;
        let output = run_activity(
            ActivityCommand::Approve {
                id: "target".into(),
            },
            &auth,
        )
        .await
        .unwrap();
        assert_eq!(output.status, "pending");
        assert_eq!(
            output.activity,
            Some(json!({"id": "target", "status": "ACTIVITY_STATUS_CONSENSUS_NEEDED"}))
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
    async fn mutation_connection_failure_is_safe_to_retry() {
        let base = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}", listener.local_addr().unwrap())
        };
        let error = post(
            &client().unwrap(),
            url(&base, "/public/v1/submit/test").unwrap(),
            "{}".into(),
            &TurnkeyP256ApiKey::generate(),
            true,
        )
        .await
        .unwrap_err();

        assert!(error.downcast_ref::<ActivityError>().is_none());
        assert_eq!(
            classify(&error),
            Classification::new(ErrorCode::NetworkError, None)
        );
    }

    #[tokio::test]
    async fn vote_submission_failures_retain_last_observed_target() {
        for approve in [true, false] {
            for timeout in [true, false] {
                let server = MockServer::start().await;
                let auth = auth(&server, TurnkeyP256ApiKey::generate());
                get_activity("target", "ACTIVITY_STATUS_CONSENSUS_NEEDED")
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
                let error = run_activity_with(&http, args, &auth).await.unwrap_err();
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
    async fn wait_survives_transient_failures_and_fails_fast_on_client_errors() {
        let server = MockServer::start().await;
        let auth = auth(&server, TurnkeyP256ApiKey::generate());
        Mock::given(path("/public/v1/query/get_activity"))
            .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        get_activity("a", "ACTIVITY_STATUS_COMPLETED")
            .expect(1)
            .mount(&server)
            .await;
        let output = run_activity(
            ActivityCommand::Wait {
                id: "a".into(),
                timeout: 5,
            },
            &auth,
        )
        .await
        .unwrap();
        assert_eq!(output.status, "completed");
        server.verify().await;

        server.reset().await;
        Mock::given(path("/public/v1/query/get_activity"))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
            .expect(1)
            .mount(&server)
            .await;
        let error = run_activity(
            ActivityCommand::Wait {
                id: "a".into(),
                timeout: 5,
            },
            &auth,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<UnexpectedHttpStatus>().unwrap().status,
            400
        );
        server.verify().await;
    }
}
