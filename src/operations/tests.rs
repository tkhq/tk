// Asserts on the classified error code.
#![allow(clippy::disallowed_types)]
use std::{net::TcpListener, sync::OnceLock};

use clap::{Parser, error::ErrorKind};
use reqwest::Client;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, path},
};

use super::*;
use crate::errors::{Classification, ErrorCode, classify};

#[derive(Debug, Parser)]
struct RequestCli {
    #[command(flatten)]
    request: RequestArgs,
}

#[derive(Debug, Parser)]
struct ActivityCli {
    #[command(subcommand)]
    activity: ActivityCommand,
}

const ORG: &str = "00000000-0000-4000-8000-000000000001";
const TARGET: Uuid = Uuid::from_u128(0x00000000_0000_4000_8000_000000000002);
const DECISION: &str = "00000000-0000-4000-8000-000000000003";
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

fn activity_error(error: &Error) -> &ActivityError {
    error.downcast_ref::<ActivityError>().unwrap()
}

async fn consensus_target(queries: u64) -> (MockServer, ResolvedAuth) {
    let server = MockServer::start().await;
    let auth = auth(&server, TurnkeyP256ApiKey::generate());
    get_activity(&TARGET.to_string(), "ACTIVITY_STATUS_CONSENSUS_NEEDED")
        .expect(queries)
        .mount(&server)
        .await;
    (server, auth)
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

#[tokio::test]
async fn query_names_the_endpoint_when_the_response_shape_mismatches() {
    let server = MockServer::start().await;
    json("query/get_activity", json!({"organizationId": 1}))
        .expect(1)
        .mount(&server)
        .await;
    let auth = auth(&server, TurnkeyP256ApiKey::generate());
    let error =
        query::<Value, GetActivityRequest>("/public/v1/query/get_activity", &json!({}), &auth)
            .await
            .unwrap_err();
    let error = activity_error(&error);
    assert_eq!(error.kind(), ActivityErrorKind::MalformedResponse);
    assert_eq!(error.to_string(), "get_activity response was malformed");
    server.verify().await;
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
    assert_eq!(
        RequestCli::try_parse_from(["tk", "--path", "/public/v1/query/whoami"])
            .unwrap_err()
            .kind(),
        ErrorKind::MissingRequiredArgument
    );
    assert_eq!(
        RequestCli::try_parse_from([
            "tk",
            "--path",
            "/public/v1/query/whoami",
            "--body",
            "{}",
            "--body-file",
            "-"
        ])
        .unwrap_err()
        .kind(),
        ErrorKind::ArgumentConflict
    );
    assert_eq!(
        RequestCli::try_parse_from(["tk", "--path", "https://other.test", "--body", "{}"])
            .unwrap_err()
            .kind(),
        ErrorKind::ValueValidation
    );
    assert_eq!(
        ActivityCli::try_parse_from(["tk", "wait", "--id", &TARGET.to_string(), "--timeout", "0",])
            .unwrap_err()
            .kind(),
        ErrorKind::ValueValidation
    );
}

#[test]
fn list_parser_accepts_repeated_filters_and_rejects_unknown_types() {
    let ActivityCommand::List(args) = ActivityCli::try_parse_from([
        "tk",
        "list",
        "--status",
        "pending",
        "--status",
        "failed",
        "--type",
        "ACTIVITY_TYPE_CREATE_USER_TAG",
        "--type",
        "ACTIVITY_TYPE_CREATE_POLICY_V3",
        "--since",
        "36h",
    ])
    .unwrap()
    .activity
    else {
        panic!("expected list");
    };
    assert_eq!(args.limit, 50);
    assert_eq!(args.cursor, None);
    assert_eq!(args.status, [StatusFilter::Pending, StatusFilter::Failed]);
    assert_eq!(
        args.types,
        [ActivityType::CreateUserTag, ActivityType::CreatePolicyV3]
    );
    assert_eq!(args.since.map(ExpiresIn::seconds), Some(36 * 3_600));
    for bad in [
        ["tk", "list", "--type", "ACTIVITY_TYPE_UNSPECIFIED"],
        ["tk", "list", "--type", "CREATE_USER_TAG"],
        ["tk", "list", "--since", "1w"],
        ["tk", "list", "--status", "created"],
    ] {
        let error = ActivityCli::try_parse_from(bad).unwrap_err();
        assert!(
            matches!(
                error.kind(),
                ErrorKind::ValueValidation | ErrorKind::InvalidValue
            ),
            "{bad:?}: {error}"
        );
    }
}

#[test]
fn parser_requires_uuid_activity_ids() {
    for subcommand in ["get", "approve", "reject", "wait"] {
        for id in ["", "not-a-uuid"] {
            assert_eq!(
                ActivityCli::try_parse_from(["tk", subcommand, "--id", id])
                    .unwrap_err()
                    .kind(),
                ErrorKind::ValueValidation,
                "{subcommand} --id {id:?}"
            );
        }
    }
}

fn listed(seconds: u64, ids: impl IntoIterator<Item = u32>) -> Value {
    let items: Vec<Value> = ids
        .into_iter()
        .map(|n| {
            json!({
                "id": format!("id-{n}"),
                "status": "ACTIVITY_STATUS_COMPLETED",
                "createdAt": {"seconds": seconds.to_string(), "nanos": "0"},
                "votes": [],
            })
        })
        .collect();
    json!({"activities": items})
}

async fn list_since(auth: &ResolvedAuth, limit: u32, cursor: Option<&str>) -> Value {
    list(
        auth,
        ListArgs {
            limit,
            cursor: cursor.map(str::to_owned),
            status: vec![StatusFilter::Completed],
            types: vec![],
            since: Some("1h".parse().unwrap()),
        },
    )
    .await
    .unwrap()
    .into_data()
}

#[tokio::test]
async fn since_walks_full_pages_and_stops_at_the_window_or_the_cap() {
    let server = MockServer::start().await;
    let now = unix_now().unwrap().as_secs();
    let page = |limit: &str, after: &str, body: Value| {
        Mock::given(path("/public/v1/query/list_activities"))
            .and(body_partial_json(json!({
                "filterByStatus": ["ACTIVITY_STATUS_COMPLETED"],
                "paginationOptions": {"limit": limit, "after": after},
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
    };
    page("100", "", listed(now, 1..=100)).mount(&server).await;
    page("99", "", listed(now, 1..=99)).mount(&server).await;
    let mut tail = listed(now - 60, 101..=102);
    let mut old = listed(now - 7_200, 103..=103);
    tail["activities"]
        .as_array_mut()
        .unwrap()
        .append(old["activities"].as_array_mut().unwrap());
    page("100", "id-100", tail).mount(&server).await;
    page("100", "id-99", listed(now - 60, 100..=101))
        .mount(&server)
        .await;
    let auth = auth(&server, TurnkeyP256ApiKey::generate());

    let all = list_since(&auth, 500, None).await;
    let ids: Vec<String> = all["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        ids,
        (1..=102).map(|n| format!("id-{n}")).collect::<Vec<_>>()
    );
    assert_eq!(all["nextCursor"], Value::Null);
    assert_eq!(all["items"][0]["votes"], json!([]));

    let capped = list_since(&auth, 99, None).await;
    assert_eq!(capped["items"].as_array().unwrap().len(), 99);
    assert_eq!(capped["nextCursor"], "id-99");

    let resumed = list_since(&auth, 500, Some("id-99")).await;
    assert_eq!(
        resumed["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["id-100", "id-101"]
    );
    assert_eq!(resumed["nextCursor"], Value::Null);
}

#[tokio::test]
async fn reject_success_and_malformed_submission_are_distinct() {
    let server = MockServer::start().await;
    let auth = auth(&server, TurnkeyP256ApiKey::generate());
    get_activity(&TARGET.to_string(), "ACTIVITY_STATUS_CONSENSUS_NEEDED")
        .mount(&server)
        .await;
    json(
        "submit/reject_activity",
        activity(&TARGET.to_string(), "ACTIVITY_STATUS_REJECTED"),
    )
    .expect(1)
    .mount(&server)
    .await;
    let output = run_activity(ActivityCommand::Reject { id: TARGET }, &auth)
        .await
        .unwrap();
    assert_eq!(output.status(), Status::Rejected);
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
    let (server, auth) = consensus_target(1).await;
    json(
        "submit/reject_activity",
        activity(DECISION, "ACTIVITY_STATUS_REJECTED"),
    )
    .expect(1)
    .mount(&server)
    .await;
    let error = run_activity(ActivityCommand::Reject { id: TARGET }, &auth)
        .await
        .unwrap_err();
    let error = activity_error(&error);
    assert_eq!(error.kind(), ActivityErrorKind::NotCompleted);
    assert_eq!(
        error.activity(),
        Some(&json!({"id": DECISION, "status": "ACTIVITY_STATUS_REJECTED"}))
    );
    server.verify().await;
}

#[tokio::test]
async fn completed_vote_proposal_reports_the_target_status() {
    let (server, auth) = consensus_target(2).await;
    json(
        "submit/approve_activity",
        activity(DECISION, "ACTIVITY_STATUS_COMPLETED"),
    )
    .expect(1)
    .mount(&server)
    .await;
    let output = run_activity(ActivityCommand::Approve { id: TARGET }, &auth)
        .await
        .unwrap();
    assert_eq!(output.status(), Status::Pending);
    assert_eq!(
        output.activity,
        Some(json!({"id": TARGET, "status": "ACTIVITY_STATUS_CONSENSUS_NEEDED"}))
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
    let mut auth = auth(&server, TurnkeyP256ApiKey::generate());
    auth.http = OnceLock::from(
        Client::builder()
            .timeout(Duration::from_millis(10))
            .build()
            .unwrap(),
    );
    let error = post::<Value>(
        &auth,
        url(&server.uri(), "/public/v1/submit/test").unwrap(),
        "secret-marker".into(),
        true,
    )
    .await
    .unwrap_err();
    assert_eq!(
        activity_error(&error).kind(),
        ActivityErrorKind::SubmissionUnknown
    );
    assert!(!format!("{error:#}").contains("secret-marker"));
    assert!(
        error
            .chain()
            .any(<dyn std::error::Error>::is::<reqwest::Error>)
    );
    server.verify().await;
}

#[tokio::test]
async fn mutation_connection_failure_is_safe_to_retry() {
    let base = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    };
    let auth = ResolvedAuth::for_tests(ORG, &base, TurnkeyP256ApiKey::generate());
    let error = post::<Value>(
        &auth,
        url(&base, "/public/v1/submit/test").unwrap(),
        "{}".into(),
        true,
    )
    .await
    .unwrap_err();

    assert!(error.downcast_ref::<ActivityError>().is_none());
    assert_eq!(
        classify(&error),
        Classification {
            code: ErrorCode::NetworkError,
            http_status: None,
        }
    );
}

#[tokio::test]
async fn vote_submission_failures_retain_last_observed_target() {
    for approve in [true, false] {
        for timeout in [true, false] {
            let (server, mut auth) = consensus_target(1).await;
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
            auth.http = OnceLock::from(
                Client::builder()
                    .timeout(Duration::from_millis(100))
                    .build()
                    .unwrap(),
            );
            let args = if approve {
                ActivityCommand::Approve { id: TARGET }
            } else {
                ActivityCommand::Reject { id: TARGET }
            };
            let error = run_activity(args, &auth).await.unwrap_err();
            let failure = activity_error(&error);
            assert_eq!(failure.kind(), ActivityErrorKind::SubmissionUnknown);
            assert_eq!(
                failure.activity(),
                Some(&json!({"id": TARGET, "status":"ACTIVITY_STATUS_CONSENSUS_NEEDED"}))
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
    get_activity(&TARGET.to_string(), "ACTIVITY_STATUS_COMPLETED")
        .expect(1)
        .mount(&server)
        .await;
    let output = run_activity(
        ActivityCommand::Wait {
            id: TARGET,
            timeout: 5,
        },
        &auth,
    )
    .await
    .unwrap();
    assert_eq!(output.status(), Status::Completed);
    server.verify().await;

    server.reset().await;
    Mock::given(path("/public/v1/query/get_activity"))
        .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
        .expect(1)
        .mount(&server)
        .await;
    let error = run_activity(
        ActivityCommand::Wait {
            id: TARGET,
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
