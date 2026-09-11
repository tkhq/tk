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
fn observed_activity_is_pending_or_terminal() {
    let pending = observed(
        "secret.export",
        activity("a1", "ACTIVITY_STATUS_CONSENSUS_NEEDED"),
    )
    .unwrap();
    assert!(pending.is_pending());
    assert_eq!(pending.data()["activity"]["id"], "a1");

    let completed = observed("secret.export", activity("a2", "ACTIVITY_STATUS_COMPLETED")).unwrap();
    assert!(!completed.is_pending());

    let rejected =
        observed("secret.export", activity("a3", "ACTIVITY_STATUS_REJECTED")).unwrap_err();
    let error = activity_error(&rejected);
    assert_eq!(error.kind(), ActivityErrorKind::NotCompleted);
    assert_eq!(error.activity().unwrap()["id"], "a3");
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
        RequestCli::try_parse_from(["tk", "--path", "https://other.test", "--body", "{}"]).is_err()
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
