use crate::policy_helpers::{allow_once, tag_consensus};
use crate::run::{AGENT_TAG, HUMAN_TAG, Run};
use serde_json::{Value, json};
use std::fs::{self, File};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

#[test]
#[ignore]
fn secret_import_list_and_export_round_trip() {
    let run = Run::new();
    let name = run.name("api-token");
    let value = "hunter2-😀-multi\nline";

    let imported = run.submit(
        run.admin()
            .args([
                "secret",
                "import",
                "--name",
                &name,
                "--property",
                "env=prod",
                "--property",
                "team=payments",
            ])
            .write_stdin(format!("{value}\n")),
        "secret.import",
    );
    assert_eq!(imported["data"]["name"], name);
    let secret_id = imported["data"]["secretId"].as_str().unwrap().to_string();
    assert!(Uuid::parse_str(&secret_id).is_ok(), "{imported}");

    let listed = run.ok(run.admin().args(["secret", "list", "--limit", "100"]));
    assert_eq!(listed["command"], "secret.list");
    assert_eq!(listed["data"]["nextCursor"], json!(null));
    let entry = listed["data"]["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["secretId"] == secret_id)
        .unwrap_or_else(|| panic!("imported secret missing from list: {listed}"));
    assert_eq!(entry["name"], name);
    assert_eq!(
        entry["staticProperties"],
        json!([{"key": "env", "value": "prod"}, {"key": "team", "value": "payments"}])
    );
    assert!(entry["createdAtUnixMs"].is_string(), "{entry}");
    assert!(entry.get("value").is_none() && entry.get("secretPayload").is_none());

    let by_name = run.export(run.admin().args(["secret", "export", "--name", &name]));
    assert_eq!(by_name["data"]["secretId"], secret_id);
    assert_eq!(by_name["data"]["value"], value);
    assert_eq!(
        by_name["data"]["activity"]["type"],
        "ACTIVITY_TYPE_EXPORT_SECRETS"
    );
    assert!(by_name["data"].get("nextStep").is_none(), "{by_name}");
    assert!(
        !run.export_state(run.admin_public_key(), &secret_id)
            .exists()
    );

    // Human mode prints only the bare value, nothing else on stdout or stderr.
    let human = run.human_stdout(run.admin().args([
        "secret",
        "export",
        "--name",
        &name,
        "--message-format",
        "human",
    ]));
    assert_eq!(human, format!("{value}\n"));

    let by_id = run.export(run.admin().args([
        "secret",
        "export",
        "--id",
        &secret_id,
        "--context",
        "purpose=e2e",
    ]));
    assert_eq!(by_id["data"]["value"], value);

    let out = run.home().join("exported.txt");
    let to_file = run.export(
        run.admin()
            .args(["secret", "export", "--name", &name, "--out"])
            .arg(&out),
    );
    assert_eq!(to_file["data"]["out"], out.to_str().unwrap());
    assert!(to_file["data"].get("value").is_none(), "{to_file}");
    assert_eq!(fs::read_to_string(&out).unwrap(), value);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let refused = run.err(
        run.admin()
            .args(["secret", "export", "--name", &name, "--out"])
            .arg(&out),
    );
    assert_eq!(refused["code"], "invalid_input", "{refused}");

    let missing = run.err(
        run.admin()
            .args(["secret", "export", "--name", &run.name("nope")]),
    );
    assert_eq!(missing["code"], "not_found", "{missing}");

    // Any command sweeps pending export state older than 8 hours.
    let pending_dir = run
        .home()
        .join(".config/turnkey/tk/secrets/pending")
        .join(run.org());
    fs::create_dir_all(&pending_dir).unwrap();
    let stale = pending_dir.join(format!("{}.json", Uuid::new_v4()));
    let fresh = pending_dir.join(format!("{}.json", Uuid::new_v4()));
    fs::write(&stale, b"{}").unwrap();
    fs::write(&fresh, b"{}").unwrap();
    File::options()
        .write(true)
        .open(&stale)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(9 * 3600))
        .unwrap();
    run.ok(run.admin().args(["secret", "list"]));
    assert!(!stale.exists(), "stale pending state must be swept");
    assert!(fresh.exists(), "fresh pending state must be kept");

    let duplicate = run.err(
        run.admin()
            .args(["secret", "import", "--name", &name])
            .write_stdin("other"),
    );
    assert_eq!(duplicate["reason"], "command_error");
    assert_eq!(duplicate["code"], "api_error", "{duplicate}");
}

#[test]
#[ignore]
fn an_export_denied_by_policy_writes_no_recovery_key() {
    let run = Run::new();
    // No policy names this user, so it can read metadata but not export.
    let (_, unauthorized) = run.create_user("unauthorized");

    let name = run.name("locked-secret");
    let secret_id = run.import_secret(&name, "not yours");
    let state = run.export_state(
        &hex::encode(unauthorized.compressed_public_key()),
        &secret_id,
    );

    let denied = run.err_unauthorized(
        run.as_user(&unauthorized)
            .args(["secret", "export", "--name", &name]),
    );
    assert_eq!(denied["reason"], "command_error", "{denied}");
    assert!(denied.get("data").is_none(), "{denied}");
    assert!(
        !state.exists(),
        "a denied export must not leave a recovery key at {}",
        state.display()
    );

    // The admin is allowed, and its own export is unaffected by the denial.
    let exported = run.export(run.admin().args(["secret", "export", "--name", &name]));
    assert_eq!(exported["data"]["value"], "not yours");
    assert!(
        !run.export_state(run.admin_public_key(), &secret_id)
            .exists(),
        "an export that needs no approval must leave no recovery key"
    );
}

#[test]
#[ignore]
fn secret_export_with_consensus_finishes_by_rerunning_the_command() {
    let run = Run::new();
    let (submitter_id, submitter) = run.create_user("submitter");
    let (approver_id, approver) = run.create_user("approver");
    run.create_policy(json!({
        "policyName": run.name("export-consensus"),
        "effect": "EFFECT_ALLOW",
        "condition": "activity.type == 'ACTIVITY_TYPE_EXPORT_SECRETS'",
        "consensus": format!(
            "approvers.any(user, user.id == '{submitter_id}') && approvers.any(user, user.id == '{approver_id}')"
        ),
        "notes": "tk e2e secret export consensus",
    }));

    let name = run.name("db-password");
    let value = "correct horse battery staple";
    let secret_id = run.import_secret(&name, value);
    let state = run.export_state(&hex::encode(submitter.compressed_public_key()), &secret_id);

    let pending = run.ok(run
        .as_user(&submitter)
        .args(["secret", "export", "--name", &name]));
    assert_eq!(pending["command"], "secret.export");
    assert_eq!(pending["status"], "pending");
    assert_eq!(pending["data"]["secretId"], secret_id);
    assert_eq!(
        pending["data"]["nextStep"],
        "After approval, run the same export command again."
    );
    assert!(pending["data"].get("value").is_none(), "{pending}");
    let activity = pending["activity"]["id"].as_str().unwrap().to_string();
    assert!(
        state.exists(),
        "pending state should exist at {}",
        state.display()
    );

    let still_pending = run.ok(run
        .as_user(&submitter)
        .args(["secret", "export", "--id", &secret_id]));
    assert_eq!(still_pending["status"], "pending");
    assert_eq!(
        still_pending["activity"]["id"], activity,
        "re-run must not create a second activity"
    );

    let approved = run.approve(&approver, &activity);
    assert_eq!(approved["activity"]["id"], activity);
    run.wait(&activity);

    let finished = run.ok(run
        .as_user(&submitter)
        .args(["secret", "export", "--name", &name]));
    assert_eq!(finished["status"], "completed", "{finished}");
    assert_eq!(finished["activity"]["id"], activity);
    assert_eq!(finished["data"]["value"], value);
    assert!(!state.exists(), "state must be removed after delivery");

    // An unwanted export is abandoned by rejecting its activity. There is no
    // abort subcommand: the next run reports the rejection and clears the key,
    // and the run after that submits a new export.
    let pending = run.ok(run
        .as_user(&submitter)
        .args(["secret", "export", "--name", &name]));
    assert_eq!(
        pending["status"], "pending",
        "a finished export must not be replayed: {pending}"
    );
    let rejected_activity = pending["activity"]["id"].as_str().unwrap().to_string();
    assert_ne!(rejected_activity, activity);
    assert!(state.exists(), "a pending export keeps its recovery key");
    let rejected = run.reject(&approver, &rejected_activity);
    assert_eq!(rejected["status"], "rejected");

    let failed = run.err(
        run.as_user(&submitter)
            .args(["secret", "export", "--name", &name]),
    );
    assert_eq!(failed["code"], "api_error", "{failed}");
    assert_eq!(failed["details"]["activity"]["id"], rejected_activity);
    assert!(!state.exists(), "rejected export must clear its state");

    let fresh = run.ok(run
        .as_user(&submitter)
        .args(["secret", "export", "--name", &name]));
    assert_eq!(fresh["status"], "pending");
    let fresh_activity = fresh["activity"]["id"].as_str().unwrap().to_string();
    assert_ne!(fresh_activity, rejected_activity);
    assert!(state.exists(), "the retry keeps its own recovery key");

    // The retry is a complete export in its own right: approved, it delivers.
    run.approve_and_wait(&approver, &fresh_activity);
    let retried = run.ok(run
        .as_user(&submitter)
        .args(["secret", "export", "--name", &name]));
    assert_eq!(retried["status"], "completed", "{retried}");
    assert_eq!(retried["activity"]["id"], fresh_activity);
    assert_eq!(retried["data"]["value"], value);
    assert!(
        !state.exists(),
        "the retried export clears its state on delivery"
    );
}

#[test]
#[ignore]
fn a_pending_export_belongs_to_the_credential_that_started_it() {
    let run = Run::new();
    let (owner_id, owner) = run.create_user("owner");
    let (other_id, other) = run.create_user("other");
    let (approver_id, approver) = run.create_user("approver");
    run.create_policy(json!({
        "policyName": run.name("export-per-credential"),
        "effect": "EFFECT_ALLOW",
        "condition": "activity.type == 'ACTIVITY_TYPE_EXPORT_SECRETS'",
        // Either submitter plus the approver, so an export submitted
        // by either credential needs one more approval.
        "consensus": format!(
            "(approvers.any(user, user.id == '{owner_id}') || approvers.any(user, user.id == '{other_id}')) && approvers.any(user, user.id == '{approver_id}')"
        ),
        "notes": "tk e2e per-credential export state",
    }));

    let name = run.name("shared-secret");
    let value = "one secret, two credentials";
    let secret_id = run.import_secret(&name, value);
    let owner_state = run.export_state(&hex::encode(owner.compressed_public_key()), &secret_id);
    let other_state = run.export_state(&hex::encode(other.compressed_public_key()), &secret_id);

    let first = run.ok(run
        .as_user(&owner)
        .args(["secret", "export", "--name", &name]));
    assert_eq!(first["status"], "pending");
    let first_activity = first["activity"]["id"].as_str().unwrap().to_string();
    assert!(owner_state.exists(), "the owner's key must be persisted");
    assert!(
        !other_state.exists(),
        "another credential must not share the owner's state"
    );

    let second = run.ok(run
        .as_user(&other)
        .args(["secret", "export", "--name", &name]));
    assert_eq!(second["status"], "pending");
    let second_activity = second["activity"]["id"].as_str().unwrap().to_string();
    assert_ne!(
        second_activity, first_activity,
        "a second credential must not resume another credential's export"
    );
    assert!(other_state.exists());

    assert_eq!(
        run.ok(run
            .as_user(&owner)
            .args(["secret", "export", "--name", &name]))["activity"]["id"],
        first_activity
    );
    assert_eq!(
        run.ok(run
            .as_user(&other)
            .args(["secret", "export", "--name", &name]))["activity"]["id"],
        second_activity
    );

    run.approve_and_wait(&approver, &first_activity);
    let delivered = run.ok(run
        .as_user(&owner)
        .args(["secret", "export", "--name", &name]));
    assert_eq!(delivered["status"], "completed", "{delivered}");
    assert_eq!(delivered["activity"]["id"], first_activity);
    assert_eq!(delivered["data"]["value"], value);
    assert!(!owner_state.exists(), "a delivered export clears its state");
    assert!(
        other_state.exists(),
        "the other credential's export must be untouched"
    );
    assert_eq!(
        run.ok(run
            .as_user(&other)
            .args(["secret", "export", "--name", &name]))["activity"]["id"],
        second_activity
    );
}

#[test]
#[ignore]
fn secret_env_exports_matching_secrets_as_dotenv() {
    let run = Run::new();
    let prefix = run.name("svc");
    for (var, value) in [
        ("API_TOKEN", "tok-1"),
        ("DB_URL", "postgres://u:p@h/db?x=1 y"),
    ] {
        run.submit(
            run.admin()
                .args([
                    "secret",
                    "import",
                    "--name",
                    &format!("{prefix}/{var}"),
                    "--property",
                    "consensus=unilateral",
                ])
                .write_stdin(value),
            "secret.import",
        );
    }
    run.submit(
        run.admin()
            .args([
                "secret",
                "import",
                "--name",
                &format!("{prefix}/OTHER"),
                "--property",
                "consensus=approval",
            ])
            .write_stdin("nope"),
        "secret.import",
    );

    let human = run.human_stdout(run.admin().args([
        "secret",
        "env",
        "--name-prefix",
        &format!("{prefix}/"),
        "--property",
        "consensus=unilateral",
        "--message-format",
        "human",
    ]));
    assert_eq!(
        human,
        r#"API_TOKEN=tok-1
DB_URL='postgres://u:p@h/db?x=1 y'
"#
    );

    let record = run.ok(run.admin().args([
        "secret",
        "env",
        "--name-prefix",
        &format!("{prefix}/"),
        "--property",
        "consensus=unilateral",
    ]));
    assert_eq!(record["command"], "secret.env");
    assert_eq!(record["status"], "completed");
    assert_eq!(
        record["data"]["env"],
        json!({"API_TOKEN": "tok-1", "DB_URL": "postgres://u:p@h/db?x=1 y"})
    );
    assert_eq!(record["data"]["pending"], json!([]));
    let exported: Vec<&str> = record["data"]["exported"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["var"].as_str().unwrap())
        .collect();
    assert_eq!(exported, ["API_TOKEN", "DB_URL"]);

    let all = run.ok(run
        .admin()
        .args(["secret", "env", "--name-prefix", &format!("{prefix}/")]));
    assert_eq!(all["data"]["env"]["OTHER"], "nope");

    let nothing =
        run.err(
            run.admin()
                .args(["secret", "env", "--name-prefix", &run.name("absent/")]),
        );
    assert_eq!(nothing["code"], "invalid_input", "{nothing}");
}

#[test]
#[ignore]
fn secret_list_filters_by_property_and_name_prefix() {
    let run = Run::new();
    let svc = run.name("svc");
    let other = run.name("other");
    let api_token = format!("{svc}/API_TOKEN");
    let db_url = format!("{svc}/DB_URL");
    let api_token_id = run.import_secret_from_file(&api_token, "unilateral", "tok-1");
    let db_url_id = run.import_secret_from_file(&db_url, "unilateral", "postgres://h/db");
    let other_id = run.import_secret_from_file(&format!("{other}/TOKEN"), "approval", "tok-2");

    let field = |record: &Value, field: &str| -> Vec<String> {
        let mut values: Vec<String> = record["data"]["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry[field].as_str().unwrap().to_owned())
            .collect();
        values.sort();
        values
    };
    let mut svc_names = vec![api_token, db_url];
    svc_names.sort();
    let mut svc_ids = vec![api_token_id, db_url_id];
    svc_ids.sort();

    let by_prefix =
        run.ok(run
            .admin()
            .args(["secret", "list", "--name-prefix", &format!("{svc}/")]));
    assert_eq!(by_prefix["command"], "secret.list");
    assert_eq!(by_prefix["data"]["nextCursor"], json!(null));
    assert_eq!(field(&by_prefix, "name"), svc_names, "{by_prefix}");
    assert_eq!(field(&by_prefix, "secretId"), svc_ids, "{by_prefix}");

    let both = run.ok(run.admin().args([
        "secret",
        "list",
        "--property",
        "consensus=unilateral",
        "--name-prefix",
        &format!("{svc}/"),
    ]));
    assert_eq!(field(&both, "name"), svc_names, "{both}");

    let approval = run.ok(run
        .admin()
        .args(["secret", "list", "--property", "consensus=approval"]));
    assert_eq!(field(&approval, "secretId"), [other_id], "{approval}");

    let none = run.ok(run.admin().args([
        "secret",
        "list",
        "--property",
        "consensus=none",
        "--name-prefix",
        &format!("{svc}/"),
    ]));
    assert_eq!(none["data"], json!({"secrets": [], "nextCursor": null}));

    let capped = run.ok(run.admin().args([
        "secret",
        "list",
        "--limit",
        "1",
        "--name-prefix",
        &format!("{svc}/"),
    ]));
    let listed = field(&capped, "secretId");
    assert_eq!(listed.len(), 1, "{capped}");
    assert!(svc_ids.contains(&listed[0]), "{capped}");
    assert_eq!(capped["data"]["nextCursor"], listed[0], "{capped}");

    let resumed = run.ok(run.admin().args([
        "secret",
        "list",
        "--cursor",
        &listed[0],
        "--name-prefix",
        &format!("{svc}/"),
    ]));
    assert_eq!(resumed["data"]["nextCursor"], json!(null), "{resumed}");
    let mut walked = listed;
    walked.extend(field(&resumed, "secretId"));
    walked.sort();
    assert_eq!(walked, svc_ids, "{resumed}");
}

#[test]
#[ignore]
fn secret_delete_removes_it_from_listing_and_export() {
    let run = Run::new();
    let name = run.name("rotate-me");
    let secret_id = run.import_secret(&name, "old-value");

    let deleted = run.submit(
        run.admin().args(["secret", "delete", "--name", &name]),
        "secret.delete",
    );
    assert_eq!(deleted["data"]["secretId"], secret_id);
    assert_eq!(
        deleted["data"]["activity"]["type"],
        "ACTIVITY_TYPE_DELETE_SECRETS"
    );

    let listed = run.ok(run.admin().args(["secret", "list", "--limit", "100"]));
    assert!(
        listed["data"]["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["secretId"] != secret_id),
        "{listed}"
    );
    let missing = run.err(run.admin().args(["secret", "export", "--name", &name]));
    assert_eq!(missing["code"], "not_found", "{missing}");

    // The name is free again, so rotation is delete + import.
    let replaced = run.import_secret(&name, "new-value");
    assert_ne!(replaced, secret_id);
    let exported = run.export(run.admin().args(["secret", "export", "--name", &name]));
    assert_eq!(exported["data"]["value"], "new-value");
}

#[test]
#[ignore]
fn managing_secrets_env_and_rotation() {
    let run = Run::new();
    let agent_tag = run.create_tag(AGENT_TAG);
    let human_tag = run.create_tag(HUMAN_TAG);
    let (agent_id, agent) = run.create_tagged_user("agent", AGENT_TAG);
    let (_, human) = run.create_tagged_user("human", HUMAN_TAG);
    run.allow_agent_export(&tag_consensus(&agent_tag), "unilateral");
    run.allow_agent_export(&allow_once(&agent_tag, &human_tag), "approval");
    run.deny_agent_credentials(&agent_tag);

    let prefix = run.name("service");
    let token_id =
        run.import_secret_from_file(&format!("{prefix}/API_TOKEN"), "unilateral", "tok-1");
    run.import_secret_from_file(
        &format!("{prefix}/DB_URL"),
        "unilateral",
        "postgres://u:p@h/db",
    );
    let deploy_id =
        run.import_secret_from_file(&format!("{prefix}/DEPLOY_KEY"), "approval", "deploy-1");

    let listed = run.ok(run
        .as_user(&agent)
        .args(["secret", "list", "--limit", "100"]));
    let entry = listed["data"]["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["secretId"] == deploy_id)
        .unwrap_or_else(|| panic!("{listed}"));
    assert_eq!(
        entry["staticProperties"],
        json!([{"key": "consensus", "value": "approval"}])
    );
    assert!(entry.get("value").is_none());

    let env_args = ["secret", "env", "--name-prefix", &format!("{prefix}/")];
    let unilateral = run.ok(run
        .as_user(&agent)
        .args(env_args)
        .args(["--property", "consensus=unilateral"]));
    assert_eq!(unilateral["command"], "secret.env");
    assert_eq!(
        unilateral["data"]["env"],
        json!({"API_TOKEN": "tok-1", "DB_URL": "postgres://u:p@h/db"})
    );
    assert_eq!(unilateral["data"]["pending"], json!([]));

    let gated = run.err(run.as_user(&agent).args(env_args));
    assert_eq!(gated["code"], "approval_required", "{gated}");
    let pending = gated["details"]["pending"].as_array().unwrap();
    assert_eq!(pending.len(), 1, "{gated}");
    assert_eq!(pending[0]["name"], format!("{prefix}/DEPLOY_KEY"));
    assert_eq!(pending[0]["secretId"], deploy_id);
    assert_eq!(pending[0]["var"], "DEPLOY_KEY");
    let activity = pending[0]["activityId"].as_str().unwrap().to_string();
    assert!(gated.get("data").is_none(), "{gated}");

    run.approve_and_wait(&human, &activity);
    let complete = run.ok(run.as_user(&agent).args(env_args));
    assert_eq!(
        complete["data"]["env"],
        json!({
            "API_TOKEN": "tok-1",
            "DB_URL": "postgres://u:p@h/db",
            "DEPLOY_KEY": "deploy-1",
        })
    );

    run.assert_api_key_register_denied(&mut run.as_user(&agent), &agent_id);

    let deleted = run.submit(
        run.admin()
            .args(["secret", "delete", "--name", &format!("{prefix}/API_TOKEN")]),
        "secret.delete",
    );
    assert_eq!(deleted["data"]["secretId"], token_id);
    let rotated_id =
        run.import_secret_from_file(&format!("{prefix}/API_TOKEN"), "unilateral", "tok-2");
    assert_ne!(rotated_id, token_id);
    let rotated = run.ok(run
        .as_user(&agent)
        .args(env_args)
        .args(["--property", "consensus=unilateral"]));
    assert_eq!(rotated["data"]["env"]["API_TOKEN"], "tok-2");
}
