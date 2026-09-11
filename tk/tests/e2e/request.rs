use crate::run::Run;
use serde_json::json;
use uuid::Uuid;

#[test]
#[ignore]
fn request_stamp_only_returns_url_header_and_identical_body() {
    let run = Run::new();
    let body = format!(
        r#"{{
  "organizationId": "{}"
}}
"#,
        run.org()
    );
    let record = run.ok(run.admin().args([
        "request",
        "--path",
        "/public/v1/query/whoami",
        "--body",
        &body,
        "--stamp-only",
    ]));
    assert_eq!(record["command"], "request");
    assert_eq!(record["status"], "completed");
    let stamp = record["data"]["header"]["value"].as_str().unwrap();
    assert!(!stamp.is_empty());
    assert_eq!(
        record["data"],
        json!({
            "url": format!("{}/public/v1/query/whoami", run.config.api_base_url.trim_end_matches('/')),
            "method": "POST",
            "header": {"name": "X-Stamp", "value": stamp},
            "body": body,
        })
    );
}

#[test]
#[ignore]
fn request_whoami_succeeds_and_org_mismatch_is_local() {
    let run = Run::new();
    let whoami = run.ok(run.admin().args([
        "request",
        "--path",
        "/public/v1/query/whoami",
        "--body",
        &json!({"organizationId": run.org()}).to_string(),
    ]));
    assert_eq!(whoami["command"], "request");
    assert_eq!(whoami["data"]["organizationId"], run.org());

    let upper = run.ok(run.admin().args([
        "request",
        "--path",
        "/public/v1/query/whoami",
        "--body",
        &json!({"organizationId": run.org().to_uppercase()}).to_string(),
    ]));
    assert_eq!(upper["data"]["organizationId"], run.org());

    let mismatch = run.err(run.admin_offline().args([
        "request",
        "--path",
        "/public/v1/query/whoami",
        "--body",
        &json!({"organizationId": Uuid::new_v4()}).to_string(),
    ]));
    assert_eq!(mismatch["reason"], "command_error");
    assert_eq!(mismatch["code"], "invalid_input");
    assert_eq!(mismatch.get("httpStatus"), None);
}
