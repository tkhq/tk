use crate::run::Run;
use serde_json::json;

#[test]
#[ignore]
fn secret_import_list_and_export_round_trip() {
    let run = Run::new();
    let name = run.name("api-token");
    let value = "hunter2-😀-multi\nline";

    let imported = run.ok(run
        .admin()
        .args([
            "secret",
            "import",
            &name,
            "--property",
            "env=prod",
            "--property",
            "team=payments",
        ])
        .write_stdin(format!("{value}\n")));
    assert_eq!(imported["command"], "secret.import");
    assert_eq!(imported["status"], "completed", "{imported}");
    assert_eq!(imported["data"]["name"], name);
    let secret_id = imported["data"]["secretId"].as_str().unwrap().to_string();
    assert!(uuid::Uuid::parse_str(&secret_id).is_ok(), "{imported}");
    assert_eq!(imported["activity"]["status"], "ACTIVITY_STATUS_COMPLETED");

    let listed = run.ok(run.admin().args(["secret", "list", "--limit", "100"]));
    assert_eq!(listed["command"], "secret.list");
    assert_eq!(listed["data"]["nextCursor"], json!(null));
    let entry = listed["data"]["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["secretId"] == secret_id)
        .unwrap_or_else(|| panic!("imported secret missing from list: {listed}"))
        .clone();
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
    assert_eq!(std::fs::read_to_string(&out).unwrap(), value);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
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
    std::fs::create_dir_all(&pending_dir).unwrap();
    let stale = pending_dir.join(format!("{}.json", uuid::Uuid::new_v4()));
    let fresh = pending_dir.join(format!("{}.json", uuid::Uuid::new_v4()));
    std::fs::write(&stale, b"{}").unwrap();
    std::fs::write(&fresh, b"{}").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&stale)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(9 * 3600))
        .unwrap();
    run.ok(run.admin().args(["secret", "list"]));
    assert!(!stale.exists(), "stale pending state must be swept");
    assert!(fresh.exists(), "fresh pending state must be kept");

    let duplicate = run.err(
        run.admin()
            .args(["secret", "import", &name])
            .write_stdin("other"),
    );
    assert_eq!(duplicate["reason"], "command_error");
    assert_eq!(duplicate["code"], "api_error", "{duplicate}");
}

/// A policy-denied export leaves no recovery key.
#[test]
#[ignore]
fn an_export_denied_by_policy_writes_no_recovery_key() {
    let run = Run::new();
    // No policy names this user, so it can read metadata but not export.
    let (_, unauthorized) = run.create_user("unauthorized");

    let name = run.name("locked-secret");
    let imported = run.submit(
        run.admin()
            .args(["secret", "import", &name])
            .write_stdin("not yours"),
        "secret.import",
    );
    let secret_id = imported["data"]["secretId"].as_str().unwrap().to_string();
    let state = run.export_state(
        &hex::encode(unauthorized.compressed_public_key()),
        &secret_id,
    );

    let denied = run.err(
        run.as_user(&unauthorized)
            .args(["secret", "export", "--name", &name]),
    );
    assert_eq!(denied["reason"], "command_error", "{denied}");
    assert_eq!(denied["code"], "unauthorized", "{denied}");
    assert_eq!(denied["httpStatus"], 403, "{denied}");
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
    run.submit(
        run.admin().args([
            "policy",
            "create",
            "--input-json",
            &json!({
                "policyName": run.name("export-consensus"),
                "effect": "EFFECT_ALLOW",
                "condition": "activity.type == 'ACTIVITY_TYPE_EXPORT_SECRETS'",
                "consensus": format!(
                    "approvers.any(user, user.id == '{submitter_id}') && approvers.any(user, user.id == '{approver_id}')"
                ),
                "notes": "tk e2e secret export consensus",
            })
            .to_string(),
        ]),
        "policy.create",
    );

    let name = run.name("db-password");
    let value = "correct horse battery staple";
    let imported = run.submit(
        run.admin()
            .args(["secret", "import", &name])
            .write_stdin(value),
        "secret.import",
    );
    let secret_id = imported["data"]["secretId"].as_str().unwrap().to_string();
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

    let approved = run.ok(run
        .as_user(&approver)
        .args(["activity", "approve", &activity]));
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
    let rejected = run.ok(run
        .as_user(&approver)
        .args(["activity", "reject", &rejected_activity]));
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
    run.ok(run
        .as_user(&approver)
        .args(["activity", "approve", &fresh_activity]));
    run.wait(&fresh_activity);
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

/// Pending export state belongs to the submitting credential.
#[test]
#[ignore]
fn a_pending_export_belongs_to_the_credential_that_started_it() {
    let run = Run::new();
    let (owner_id, owner) = run.create_user("owner");
    let (other_id, other) = run.create_user("other");
    let (approver_id, approver) = run.create_user("approver");
    run.submit(
        run.admin().args([
            "policy",
            "create",
            "--input-json",
            &json!({
                "policyName": run.name("export-per-credential"),
                "effect": "EFFECT_ALLOW",
                "condition": "activity.type == 'ACTIVITY_TYPE_EXPORT_SECRETS'",
                // Either submitter plus the approver, so an export submitted
                // by either credential needs one more approval.
                "consensus": format!(
                    "(approvers.any(user, user.id == '{owner_id}') || approvers.any(user, user.id == '{other_id}')) && approvers.any(user, user.id == '{approver_id}')"
                ),
                "notes": "tk e2e per-credential export state",
            })
            .to_string(),
        ]),
        "policy.create",
    );

    let name = run.name("shared-secret");
    let value = "one secret, two credentials";
    let imported = run.submit(
        run.admin()
            .args(["secret", "import", &name])
            .write_stdin(value),
        "secret.import",
    );
    let secret_id = imported["data"]["secretId"].as_str().unwrap().to_string();
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

    // The second credential starts its own export rather than resuming.
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

    // Each credential resumes only its own activity.
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

    // Approving one export delivers to its owner and leaves the other alone.
    run.ok(run
        .as_user(&approver)
        .args(["activity", "approve", &first_activity]));
    run.wait(&first_activity);
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
