use std::{
    fmt::{self, Display, Formatter},
    fs,
    io::{self, Read},
    mem::take,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Error, Result};
use clap::{Args, Subcommand, ValueEnum};
use reqwest::Url;
use serde::{Serialize, Serializer, de::DeserializeOwned, ser::SerializeStruct};
use serde_json::{Value, error::Category, from_slice, json};
use tokio::time::{sleep, timeout};
use turnkey_api_key_stamper::Stamp;
use turnkey_client::generated::{
    ActivityStatus, ActivityType, GetActivitiesRequest, GetActivityRequest,
    external::options::v1::Pagination,
};
use uuid::Uuid;

use crate::{
    auth::ResolvedAuth,
    errors::{
        ActivityError, ActivityErrorKind, InvalidInput, Malformed, UnexpectedHttpStatus,
        transient_status,
    },
    sessions::duration::ExpiresIn,
};

const WALK_PAGE_SIZE: usize = 100;

const POLL_INTERVAL: Duration = Duration::from_millis(500);

const MAX_ERROR_BODY_BYTES: usize = 4 * 1024;

#[derive(Debug, Args)]
pub struct RequestArgs {
    /// Absolute API path under /public/v1/, such as /public/v1/query/whoami.
    #[arg(long, value_parser = RequestPath::parse)]
    path: RequestPath,
    /// Exact request body.
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
    List(ListArgs),
    /// Fetch one activity by ID.
    Get {
        /// Activity ID.
        #[arg(long)]
        id: Uuid,
    },
    /// Approve a `pending` activity by ID.
    Approve {
        /// Activity ID.
        #[arg(long)]
        id: Uuid,
    },
    /// Reject a `pending` activity by ID.
    Reject {
        /// Activity ID.
        #[arg(long)]
        id: Uuid,
    },
    /// Poll one activity until it reaches a terminal status.
    Wait {
        /// Activity ID.
        #[arg(long)]
        id: Uuid,
        /// Seconds to poll before failing with `wait_timeout`.
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..))]
        timeout: u64,
    },
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// Page size.
    #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..))]
    limit: u32,
    /// Activity ID to continue after.
    #[arg(long)]
    cursor: Option<String>,
    /// Keep only these statuses, filtered by the server; repeatable. pending matches created, pending, consensus-needed, and authenticators-needed activities.
    #[arg(long, value_enum)]
    status: Vec<StatusFilter>,
    /// Keep only these activity types, filtered by the server, such as `ACTIVITY_TYPE_CREATE_USER_TAG`; repeatable.
    #[arg(long = "type", value_name = "ACTIVITY_TYPE", value_parser = parse_activity_type)]
    types: Vec<ActivityType>,
    /// Keep only activities created within this window, such as 24h, filtered here: walks pages newest first from --cursor until one is older; --limit caps the matches and sets nextCursor so the same command with --cursor resumes.
    #[arg(long, value_name = "DURATION")]
    since: Option<ExpiresIn>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
#[cfg_attr(test, derive(PartialEq))]
enum StatusFilter {
    Pending,
    Completed,
    Rejected,
    Failed,
}

impl StatusFilter {
    fn statuses(self) -> &'static [ActivityStatus] {
        match self {
            Self::Pending => &[
                ActivityStatus::Created,
                ActivityStatus::Pending,
                ActivityStatus::ConsensusNeeded,
                ActivityStatus::AuthenticatorsNeeded,
            ],
            Self::Completed => &[ActivityStatus::Completed],
            Self::Rejected => &[ActivityStatus::Rejected],
            Self::Failed => &[ActivityStatus::Failed],
        }
    }
}

fn parse_activity_type(value: &str) -> Result<ActivityType, String> {
    ActivityType::from_str_name(value)
        .filter(|kind| *kind != ActivityType::Unspecified)
        .ok_or_else(|| format!("unknown activity type {value:?}; expected an ACTIVITY_TYPE_ name"))
}

#[cfg_attr(test, derive(Debug))]
pub struct OperationOutput {
    command: &'static str,
    data: Value,
    activity: Option<Value>,
}

/// Record status. A record without an activity is complete; every other
/// status is read from the activity the record carries.
#[derive(Serialize)]
#[cfg_attr(test, derive(Debug, PartialEq))]
#[serde(rename_all = "lowercase")]
enum Status {
    Completed,
    Rejected,
    Failed,
    Pending,
    Unknown,
}

impl OperationOutput {
    pub fn result(command: &'static str, data: Value) -> Self {
        let activity = data
            .get("activity")
            .filter(|v| v.is_object())
            .map(|v| json!({"id":v.get("id"),"status":v.get("status")}));
        Self {
            command,
            data,
            activity,
        }
    }

    pub(crate) fn data(&self) -> &Value {
        &self.data
    }

    pub(crate) fn into_data(self) -> Value {
        self.data
    }

    fn status(&self) -> Status {
        self.activity.as_ref().map_or(Status::Completed, Status::of)
    }

    pub(crate) fn is_pending(&self) -> bool {
        matches!(self.status(), Status::Pending)
    }

    pub(crate) fn pending_activity_id(&self) -> Option<&str> {
        if !self.is_pending() {
            return None;
        }
        self.activity.as_ref()?["id"].as_str()
    }
}

impl Status {
    fn of(activity: &Value) -> Self {
        match activity
            .get("status")
            .and_then(Value::as_str)
            .and_then(ActivityStatus::from_str_name)
        {
            Some(ActivityStatus::Completed) => Self::Completed,
            Some(ActivityStatus::Rejected) => Self::Rejected,
            Some(ActivityStatus::Failed) => Self::Failed,
            Some(
                ActivityStatus::Created
                | ActivityStatus::Pending
                | ActivityStatus::ConsensusNeeded
                | ActivityStatus::AuthenticatorsNeeded,
            ) => Self::Pending,
            Some(ActivityStatus::Unspecified) | None => Self::Unknown,
        }
    }
}

impl Serialize for OperationOutput {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut record = serializer
            .serialize_struct("OperationOutput", 5 + usize::from(self.activity.is_some()))?;
        record.serialize_field("schemaVersion", &1u32)?;
        record.serialize_field("reason", "command_result")?;
        record.serialize_field("command", self.command)?;
        record.serialize_field("status", &self.status())?;
        record.serialize_field("data", &self.data)?;
        if let Some(activity) = &self.activity {
            record.serialize_field("activity", activity)?;
        }
        record.end()
    }
}

impl Display for OperationOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // fmt::Error carries no payload.
        #[allow(clippy::map_err_ignore)]
        let rendered = serde_json::to_string_pretty(self).map_err(|_| fmt::Error)?;
        f.write_str(&rendered)
    }
}

/// An absolute `/public/v1/` API path with no query, fragment, or traversal,
/// classified as a read-only query or an activity submission.
#[derive(Clone, Debug)]
struct RequestPath {
    raw: String,
    kind: RequestKind,
}

#[derive(Clone, Debug)]
enum RequestKind {
    Query,
    Submit,
}

impl RequestPath {
    fn parse(value: &str) -> Result<Self, String> {
        if !value.starts_with("/public/v1/")
            || value.contains(['?', '#', '\\', '%'])
            || value.split('/').any(|s| s == ".." || s == ".")
        {
            return Err(
                "path must be an absolute /public/v1/ API path without query, fragment, or traversal"
                    .into(),
            );
        }
        let kind = if value.starts_with("/public/v1/query/") {
            RequestKind::Query
        } else {
            RequestKind::Submit
        };
        Ok(Self {
            raw: value.into(),
            kind,
        })
    }
}

fn url(base: &str, path: &str) -> Result<Url> {
    Url::parse(&format!("{}{path}", base.trim_end_matches('/')))
        .map_err(|error| Malformed::new("invalid request URL", error).into())
}

async fn post<R: DeserializeOwned>(
    auth: &ResolvedAuth,
    endpoint: Url,
    body: String,
    mutation: bool,
) -> Result<R> {
    let stamp = auth
        .stamper
        .stamp(body.as_bytes())
        .context("could not stamp request")?;
    let name = endpoint
        .path()
        .rsplit_once('/')
        .map_or(endpoint.path(), |(_, end)| end)
        .to_owned();
    let response = auth
        .http()?
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
                Error::new(error).context("API request failed")
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
    let kind = if mutation {
        ActivityErrorKind::SubmissionUnknown
    } else {
        ActivityErrorKind::MalformedResponse
    };
    let bytes = response.bytes().await.map_err(|error| {
        ActivityError::new(kind, "API returned an unreadable response").with_source(error)
    })?;
    from_slice(&bytes).map_err(|error| match error.classify() {
        Category::Data => ActivityError::new(
            ActivityErrorKind::MalformedResponse,
            format!("{name} response was malformed"),
        )
        .with_source(error)
        .into(),
        Category::Io | Category::Syntax | Category::Eof => {
            ActivityError::new(kind, "API returned an unreadable response")
                .with_source(error)
                .into()
        }
    })
}

fn encode<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).context("could not encode request")
}

pub(crate) fn unix_now() -> Result<Duration> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch")
}

fn envelope<T: Serialize>(kind: &str, organization_id: Uuid, parameters: &T) -> Result<Value> {
    let timestamp_ms = unix_now()?.as_millis().to_string();
    Ok(json!({
        "type": kind,
        "timestampMs": timestamp_ms,
        "organizationId": organization_id,
        "parameters": parameters,
        "generateAppProofs": null,
    }))
}

pub struct PreparedRequest {
    path: RequestPath,
    body: String,
    organization_id: Option<Uuid>,
    stamp_only: bool,
}

impl RequestArgs {
    pub fn prepare(self) -> Result<PreparedRequest> {
        let body = match (self.body, self.body_file) {
            (Some(body), _) => body,
            (None, Some(path)) if path.as_os_str() == "-" => {
                let mut body = String::new();
                io::stdin()
                    .read_to_string(&mut body)
                    .map_err(|error| Malformed::new("could not read UTF-8 request body", error))?;
                body
            }
            (None, Some(path)) => fs::read_to_string(path)
                .map_err(|error| Malformed::new("could not read UTF-8 request body", error))?,
            (None, None) => unreachable!("clap requires exactly one body source"),
        };
        let value: Value = serde_json::from_str(&body)
            .map_err(|error| Malformed::new("body must be valid JSON", error))?;
        if !value.is_object() {
            return Err(InvalidInput("body must be a JSON object".into()).into());
        }
        let organization_id = value
            .get("organizationId")
            .and_then(Value::as_str)
            .and_then(|id| Uuid::parse_str(id).ok());
        Ok(PreparedRequest {
            path: self.path,
            body,
            organization_id,
            stamp_only: self.stamp_only,
        })
    }
}

impl PreparedRequest {
    pub async fn run(self, auth: &ResolvedAuth) -> Result<OperationOutput> {
        let command = "request";
        let body = self.body;
        if self.organization_id != Some(auth.org_id) {
            return Err(InvalidInput(
                "body organizationId must match selected organization".into(),
            )
            .into());
        }
        let RequestPath { raw, kind } = self.path;
        let endpoint = url(auth.api_base_url.as_str(), &raw)?;
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
        let mutation = matches!(kind, RequestKind::Submit);
        let value = post::<Value>(auth, endpoint, body, mutation).await?;
        match kind {
            RequestKind::Query => Ok(OperationOutput::result(command, value)),
            RequestKind::Submit => submission_result(command, value),
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
    let Some(activity) = output.activity else {
        return Ok(output);
    };
    let (kind, message) = match Status::of(&activity) {
        Status::Completed | Status::Pending => {
            return Ok(OperationOutput {
                activity: Some(activity),
                ..output
            });
        }
        Status::Rejected => (ActivityErrorKind::NotCompleted, "activity rejected"),
        Status::Failed => (ActivityErrorKind::NotCompleted, "activity failed"),
        Status::Unknown if submitted => (
            ActivityErrorKind::SubmissionUnknown,
            "unknown activity status; inspect activity before resubmitting",
        ),
        Status::Unknown => (
            ActivityErrorKind::MalformedResponse,
            "unknown activity status",
        ),
    };
    Err(ActivityError::new(kind, message)
        .with_activity(activity)
        .into())
}

pub(crate) fn observed(command: &'static str, data: Value) -> Result<OperationOutput> {
    terminal(OperationOutput::result(command, data), false)
}

fn with_target(error: Error, target: Value) -> Error {
    match error.downcast::<ActivityError>() {
        Ok(activity) if activity.activity().is_none() => activity.with_activity(target).into(),
        Ok(activity) => activity.into(),
        Err(error) => error,
    }
}

pub(crate) async fn query_activity(auth: &ResolvedAuth, id: &str) -> Result<Value> {
    let body = encode(&GetActivityRequest {
        organization_id: auth.org_id.to_string(),
        activity_id: id.into(),
    })?;
    let endpoint = url(auth.api_base_url.as_str(), "/public/v1/query/get_activity")?;
    let value = post::<Value>(auth, endpoint, body, false).await?;
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
    match args {
        ActivityCommand::List(args) => list(auth, args).await,
        ActivityCommand::Get { id } => {
            let value = query_activity(auth, &id.to_string()).await?;
            Ok(OperationOutput::result("activity.get", value))
        }
        ActivityCommand::Wait { id, timeout } => wait(auth, id, timeout).await,
        ActivityCommand::Approve { id } => vote(auth, id, true).await,
        ActivityCommand::Reject { id } => vote(auth, id, false).await,
    }
}

async fn list(auth: &ResolvedAuth, args: ListArgs) -> Result<OperationOutput> {
    let ListArgs {
        limit,
        cursor,
        status,
        types,
        since,
    } = args;
    let limit = limit as usize;
    let cutoff = since
        .map(|since| Ok::<_, Error>(unix_now()?.as_secs().saturating_sub(since.seconds())))
        .transpose()?;
    let filter_by_status: Vec<ActivityStatus> = status
        .iter()
        .flat_map(|filter| filter.statuses().iter().copied())
        .collect();
    let endpoint = url(
        auth.api_base_url.as_str(),
        "/public/v1/query/list_activities",
    )?;
    let page_size = if cutoff.is_some() {
        limit.min(WALK_PAGE_SIZE)
    } else {
        limit
    };
    let mut request = GetActivitiesRequest {
        organization_id: auth.org_id.to_string(),
        filter_by_status,
        filter_by_type: types,
        pagination_options: Some(Pagination {
            limit: page_size.to_string(),
            before: String::new(),
            after: cursor.unwrap_or_default(),
        }),
    };
    let mut items = Vec::new();
    let mut capped = false;
    'pages: loop {
        let mut response = post::<Value>(auth, endpoint.clone(), encode(&request)?, false).await?;
        let page = response
            .get_mut("activities")
            .and_then(Value::as_array_mut)
            .map(take)
            .ok_or_else(|| {
                ActivityError::new(
                    ActivityErrorKind::MalformedResponse,
                    "response omitted activities",
                )
            })?;
        let full = page.len() == page_size;
        let Some(cutoff) = cutoff else {
            capped = full;
            items = page;
            break;
        };
        for item in page {
            if created_at_seconds(&item)? < cutoff {
                break 'pages;
            }
            items.push(item);
            if items.len() == limit {
                capped = true;
                break 'pages;
            }
        }
        if !full {
            break;
        }
        if let Some(pagination) = &mut request.pagination_options
            && let Some(last) = items.last()
        {
            pagination.after = activity_id(last)?.to_owned();
        }
    }
    let next = if capped {
        items.last().map(activity_id).transpose()?.map(Value::from)
    } else {
        None
    };
    Ok(OperationOutput::result(
        "activity.list",
        json!({"items":items,"nextCursor":next}),
    ))
}

fn activity_id(item: &Value) -> Result<&str> {
    item.get("id").and_then(Value::as_str).ok_or_else(|| {
        ActivityError::new(ActivityErrorKind::MalformedResponse, "activity omitted id").into()
    })
}

fn created_at_seconds(item: &Value) -> Result<u64> {
    item.pointer("/createdAt/seconds")
        .and_then(Value::as_str)
        .and_then(|seconds| seconds.parse().ok())
        .ok_or_else(|| {
            ActivityError::new(
                ActivityErrorKind::MalformedResponse,
                format!(
                    "activity {} omitted or malformed createdAt.seconds",
                    activity_id(item).unwrap_or("?")
                ),
            )
            .into()
        })
}

async fn wait(auth: &ResolvedAuth, id: Uuid, seconds: u64) -> Result<OperationOutput> {
    let command = "activity.wait";
    let wire_id = id.to_string();
    let mut last: Option<Value> = None;
    let result = timeout(Duration::from_secs(seconds), async {
        loop {
            match query_activity(auth, &wire_id).await {
                Ok(value) => {
                    let output = OperationOutput::result(command, value);
                    if !output.is_pending() {
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
            sleep(POLL_INTERVAL).await;
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

fn transient(error: &Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<UnexpectedHttpStatus>()
            .is_some_and(|http| transient_status(http.status))
            || cause.downcast_ref::<reqwest::Error>().is_some()
    })
}

async fn vote(auth: &ResolvedAuth, id: Uuid, approve: bool) -> Result<OperationOutput> {
    let command = if approve {
        "activity.approve"
    } else {
        "activity.reject"
    };
    let wire_id = id.to_string();
    let value = query_activity(auth, &wire_id).await?;
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
            auth.org_id,
            &json!({ "fingerprint": fingerprint }),
        )?)?;
        let response =
            post::<Value>(auth, url(auth.api_base_url.as_str(), path)?, body, true).await?;
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
        let data = if Uuid::parse_str(returned).is_ok_and(|returned| returned == id) {
            response
        } else {
            terminal(OperationOutput::result(command, response), true)?;
            query_activity(auth, &wire_id).await?
        };
        let output = OperationOutput::result(command, data);
        if !approve && matches!(output.status(), Status::Rejected) {
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
    let body = encode(&envelope(kind, auth.org_id, parameters)?)?;
    let endpoint = url(
        auth.api_base_url.as_str(),
        &format!("/public/v1/submit/{endpoint}"),
    )?;
    let value = post::<Value>(auth, endpoint, body, true).await?;
    submission_result(command, value)
}

pub(crate) async fn query<T: Serialize, R: DeserializeOwned>(
    path: &str,
    request: &T,
    auth: &ResolvedAuth,
) -> Result<R> {
    post::<R>(
        auth,
        url(auth.api_base_url.as_str(), path)?,
        encode(request)?,
        false,
    )
    .await
}

#[cfg(test)]
mod tests;
