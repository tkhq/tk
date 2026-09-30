use std::{fs, io::ErrorKind};

use serde_json::{Value, json};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;

use crate::{
    policy_helpers::{allow_once, tag_consensus},
    run::{AGENT_TAG, HUMAN_TAG, Run, created_user_id, id_of, user_params},
};

#[test]
#[ignore]
fn session_request_generates_a_pending_credential() {
    let run = Run::new();
    let admin = run.login_admin();

    let requested = run.ok(run
        .cli()
        .args(["session", "request", "--profile-name", &admin.name]));
    assert_eq!(requested["command"], "session.request");
    assert_eq!(requested["status"], "completed");
    let public_key = requested["data"]["publicKey"].as_str().unwrap();
    assert!(public_key.starts_with("02") || public_key.starts_with("03"));
    assert_eq!(public_key.len(), 66);
    assert_eq!(requested["data"]["organizationId"], run.org());
    assert_eq!(
        requested["data"]["userId"], admin.record["data"]["identity"]["userId"],
        "{requested}"
    );
    assert_eq!(requested["data"]["curve"], "p256");
    let key_file = requested["data"]["keyFile"].as_str().unwrap().to_string();
    assert_eq!(
        key_file,
        fs::canonicalize(
            run.home()
                .join(".config/turnkey/tk/api-keys")
                .join(format!("{public_key}.json"))
        )
        .unwrap()
        .to_str()
        .unwrap()
    );
    let pending = run
        .home()
        .join(".config/turnkey/tk/sessions/pending")
        .join(format!("{}.json", admin.name));
    assert!(pending.exists());

    let again = run.err(
        run.cli()
            .args(["session", "request", "--profile-name", &admin.name]),
    );
    assert_eq!(again["code"], "invalid_input", "{again}");

    let replaced = run.ok(run.cli().args([
        "session",
        "request",
        "--profile-name",
        &admin.name,
        "--replace",
    ]));
    assert_ne!(
        replaced["data"]["publicKey"],
        requested["data"]["publicKey"]
    );
    assert_eq!(
        fs::metadata(&key_file).unwrap_err().kind(),
        ErrorKind::NotFound,
        "replaced key file was not removed"
    );
    fs::metadata(replaced["data"]["keyFile"].as_str().unwrap()).unwrap();

    let unknown =
        run.err(
            run.cli()
                .args(["session", "request", "--profile-name", "no-such-profile"]),
        );
    assert_eq!(unknown["code"], "invalid_input", "{unknown}");
}

#[test]
#[ignore]
fn session_provision_registers_an_expiring_key_once() {
    let run = Run::new();
    let (agent_id, _agent_key) = run.create_user("agent");
    let provisioner_key = run.create_provisioner();
    let public_key = hex::encode(run.key().compressed_public_key());
    let provision = |label: Option<&str>| {
        let mut cmd = run.provision(&provisioner_key, &agent_id, &public_key.to_uppercase());
        if let Some(label) = label {
            cmd.args(["--label", label]);
        }
        cmd
    };

    let provisioned = run.submit(&mut provision(Some("first-session")), "session.provision");
    assert_eq!(provisioned["data"]["expirationSeconds"], "7200");
    assert_eq!(provisioned["data"]["expiresIn"], "2h");
    assert_eq!(provisioned["data"]["userId"], agent_id);
    assert_eq!(provisioned["data"]["publicKey"], public_key);
    assert_eq!(provisioned["data"]["apiKeyName"], "first-session");
    assert_eq!(
        provisioned["data"]["activity"]["type"],
        "ACTIVITY_TYPE_CREATE_API_KEYS_V2"
    );

    let again = run.ok(&mut provision(None));
    assert_eq!(again["command"], "session.provision");
    assert_eq!(again["status"], "completed");
    assert_eq!(again["data"]["alreadyRegistered"], true);
    assert_eq!(again["data"]["apiKeyName"], "first-session");
    assert_eq!(again["data"]["expirationSeconds"], "7200");
    assert_eq!(again["data"]["expiresIn"], "2h");
    assert_eq!(
        again["data"]["apiKeyId"], provisioned["data"]["apiKeyId"],
        "{again}"
    );
    assert_eq!(again["data"].get("activity"), None, "{again}");

    let listed = run.ok(run
        .admin()
        .args(["api-key", "list", "--user-id", &agent_id]));
    let matching: Vec<_> = listed["data"]["apiKeys"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|key| key["credential"]["publicKey"] == public_key)
        .collect();
    assert_eq!(matching.len(), 1, "{listed}");
    assert_eq!(matching[0]["expirationSeconds"], "7200");
    assert_eq!(matching[0]["apiKeyId"], again["data"]["apiKeyId"]);
}

#[test]
#[ignore]
fn session_loop_rotates_an_agent_profile_and_reports_status() {
    let run = Run::new();
    let provisioner_key = run.create_provisioner();

    let first_key_file = run.home().join("agent-first.json");
    let first_public = run.generate_key(&first_key_file)["data"]["publicKey"]
        .as_str()
        .unwrap()
        .to_string();
    let agent_name = run.name("agent");
    let created = run.submit(
        run.admin().args([
            "user",
            "create",
            "--input-json",
            &user_params(
                &agent_name,
                json!([{"apiKeyName": "first", "publicKey": first_public, "curveType": "API_KEY_CURVE_P256"}]),
            ),
        ]),
        "user.create",
    );
    let agent_id = created_user_id(&created);
    let agent_profile = run.name("agent-profile");
    run.ok(run
        .cli()
        .args([
            "profile",
            "create",
            "--profile-name",
            &agent_profile,
            "--organization-id",
            run.org(),
            "--api-key-file",
        ])
        .arg(&first_key_file));
    run.ok(run.cli().args(["login", "--profile-name", &agent_profile]));

    let no_expiry = run.ok(run
        .cli()
        .args(["session", "status", "--profile-name", &agent_profile]));
    assert_eq!(no_expiry["command"], "session.status");
    assert_eq!(no_expiry["data"]["userId"], agent_id);
    assert_eq!(no_expiry["data"]["publicKey"], first_public);
    assert_eq!(no_expiry["data"]["secondsLeft"], Value::Null, "{no_expiry}");
    assert_eq!(no_expiry["data"]["expiresAt"], Value::Null, "{no_expiry}");

    let nothing_pending =
        run.err(
            run.cli()
                .args(["session", "activate", "--profile-name", &agent_profile]),
        );
    assert_eq!(
        nothing_pending["code"], "invalid_input",
        "{nothing_pending}"
    );

    let requested =
        run.ok(run
            .cli()
            .args(["session", "request", "--profile-name", &agent_profile]));
    assert_eq!(requested["data"]["userId"], agent_id);
    let public_key = requested["data"]["publicKey"].as_str().unwrap().to_string();
    let new_key_file = requested["data"]["keyFile"].as_str().unwrap().to_string();

    let not_yet =
        run.err(
            run.cli()
                .args(["session", "activate", "--profile-name", &agent_profile]),
        );
    assert_eq!(not_yet["code"], "unauthorized", "{not_yet}");
    assert_eq!(
        run.ok(run
            .cli()
            .args(["profile", "show", "--profile-name", &agent_profile]))["data"]["profile"]["api_key_file"],
        fs::canonicalize(&first_key_file).unwrap().to_str().unwrap()
    );

    run.submit(
        &mut run.provision(&provisioner_key, &agent_id, &public_key),
        "session.provision",
    );

    let activated =
        run.ok(run
            .cli()
            .args(["session", "activate", "--profile-name", &agent_profile]));
    assert_eq!(activated["command"], "session.activate");
    assert_eq!(activated["data"]["publicKey"], public_key);
    assert_eq!(activated["data"]["previousPublicKey"], first_public);
    assert_eq!(activated["data"]["previousKeyFileRemoved"], false);
    assert_eq!(activated["data"]["identity"]["userId"], agent_id);
    assert!(first_key_file.exists());
    assert_eq!(
        run.ok(run
            .cli()
            .args(["profile", "show", "--profile-name", &agent_profile]))["data"]["profile"]["api_key_file"],
        new_key_file
    );
    assert!(
        !run.home()
            .join(".config/turnkey/tk/sessions/pending")
            .join(format!("{agent_profile}.json"))
            .exists()
    );
    let identity = run.ok(run.cli().args(["--profile", &agent_profile, "whoami"]));
    assert_eq!(identity["data"]["userId"], agent_id);

    let status = run.ok(run.cli().args([
        "session",
        "status",
        "--profile-name",
        &agent_profile,
        "--warn-before",
        "1h",
    ]));
    assert_eq!(status["data"]["publicKey"], public_key);
    assert_eq!(status["data"]["expirationSeconds"], "7200");
    let seconds_left = status["data"]["secondsLeft"].as_u64().unwrap();
    assert!((7000..=7200).contains(&seconds_left), "{status}");
    let created: u64 = status["data"]["createdAt"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        status["data"]["expiresAt"],
        ((created + 7200) * 1000).to_string(),
        "{status}"
    );
    assert_eq!(status["data"]["warnBefore"], "1h");

    // The default window is 48h, so a 2h key is already expiring.
    let expiring = run.err(
        run.cli()
            .args(["session", "status", "--profile-name", &agent_profile]),
    );
    assert_eq!(expiring["code"], "session_expiring", "{expiring}");
    assert_eq!(expiring["details"]["profile"], agent_profile);
    assert_eq!(expiring["details"]["warnBeforeSeconds"], 172_800);
    assert_eq!(expiring["details"]["publicKey"], public_key);

    let second = run.ok(run
        .cli()
        .args(["session", "request", "--profile-name", &agent_profile]));
    run.submit(
        &mut run.provision(
            &provisioner_key,
            &agent_id,
            second["data"]["publicKey"].as_str().unwrap(),
        ),
        "session.provision",
    );
    let rotated = run.ok(run
        .cli()
        .args(["session", "activate", "--profile-name", &agent_profile]));
    assert_eq!(rotated["data"]["previousKeyFileRemoved"], true);
    assert_eq!(
        fs::metadata(&new_key_file).unwrap_err().kind(),
        ErrorKind::NotFound,
        "old generated key file kept"
    );
}

const PROVISIONER_TAG: &str = "provisioner";

fn approve_and_wait(run: &Run, human: &TurnkeyP256ApiKey, pending: &Value) -> String {
    assert_eq!(pending["status"], "pending", "{pending}");
    let id = id_of(pending);
    run.approve_and_wait(human, &id);
    id
}

struct Provisioners {
    provisioner_tag: String,
    human_tag: String,
    provisioner_id: String,
    provisioner: TurnkeyP256ApiKey,
    human: TurnkeyP256ApiKey,
}

fn create_provisioners(run: &Run, agent_id: &str, human_mint: bool) -> Provisioners {
    let provisioner_tag = run.create_tag(PROVISIONER_TAG);
    let human_tag = run.create_tag(HUMAN_TAG);
    let (provisioner_id, provisioner) = run.create_tagged_user("provisioner", PROVISIONER_TAG);
    let (_, human) = run.create_tagged_user("human", HUMAN_TAG);
    let mint_consensus = if human_mint {
        allow_once(&provisioner_tag, &human_tag)
    } else {
        tag_consensus(&provisioner_tag)
    };
    run.create_policy_from_flags(
        &run.name("provisioners-mint-agent-keys"),
        "allow",
        &mint_consensus,
        &format!(
            "activity.type == 'ACTIVITY_TYPE_CREATE_API_KEYS_V2' && activity.params.user_id in ['{agent_id}']"
        ),
    );
    run.create_policy_from_flags(
        &run.name("provisioners-no-self-keys"),
        "deny",
        &tag_consensus(&provisioner_tag),
        &format!(
            "activity.type == 'ACTIVITY_TYPE_CREATE_API_KEYS_V2' && activity.params.user_id == '{provisioner_id}'"
        ),
    );
    Provisioners {
        provisioner_tag,
        human_tag,
        provisioner_id,
        provisioner,
        human,
    }
}

fn provisioning_session_agent_cell(human_mint: bool, human_export: bool) {
    let run = Run::new();
    let agent_tag = run.create_tag(AGENT_TAG);
    let (created, agent_key) = run.create_session_agent("agent", "2h");
    let agent_id = created_user_id(&created);
    let Provisioners {
        provisioner_tag,
        human_tag,
        provisioner_id: _,
        provisioner,
        human,
    } = create_provisioners(&run, &agent_id, human_mint);
    run.create_policy_from_flags(
        &run.name("provisioners-nothing-else"),
        "deny",
        &tag_consensus(&provisioner_tag),
        "activity.type != 'ACTIVITY_TYPE_CREATE_API_KEYS_V2'",
    );
    run.deny_agent_credentials(&agent_tag);
    let (level, export_consensus) = if human_export {
        ("approval", allow_once(&agent_tag, &human_tag))
    } else {
        ("unilateral", tag_consensus(&agent_tag))
    };
    run.allow_agent_export(&export_consensus, level);
    let secret_name = run.name("service/TOKEN");
    run.import_secret_from_file(&secret_name, level, "tok-1");

    let profile = run.name("agent-profile");
    run.login_as(&profile, &agent_key);

    let status = run.ok(run.cli().args([
        "session",
        "status",
        "--profile-name",
        &profile,
        "--warn-before",
        "1h",
    ]));
    assert_eq!(status["command"], "session.status");
    assert_eq!(status["data"]["userId"], agent_id);
    let seconds_left = status["data"]["secondsLeft"].as_u64().unwrap();
    assert!((6600..=7200).contains(&seconds_left), "{status}");

    let requested = run.ok(run
        .cli()
        .args(["session", "request", "--profile-name", &profile]));
    assert_eq!(requested["data"]["userId"], agent_id, "{requested}");
    let public_key = requested["data"]["publicKey"].as_str().unwrap().to_string();
    assert_eq!(
        requested["data"]["keyFile"],
        fs::canonicalize(
            run.home()
                .join(".config/turnkey/tk/api-keys")
                .join(format!("{public_key}.json"))
        )
        .unwrap()
        .to_str()
        .unwrap(),
        "{requested}"
    );

    let mut provision = run.provision(&provisioner, &agent_id, &public_key);
    if human_mint {
        let pending = run.ok(&mut provision);
        assert_eq!(pending["command"], "session.provision");
        assert_eq!(pending["status"], "pending", "{pending}");
        assert_eq!(pending["data"]["userId"], agent_id);
        assert_eq!(pending["data"]["publicKey"], public_key);
        assert_eq!(pending["data"]["expiresIn"], "2h");
        assert_eq!(pending["data"]["apiKeyId"], Value::Null, "{pending}");
        let activity_id = id_of(&pending);
        assert_eq!(
            pending["data"]["nextStep"],
            format!(
                "approve activity {activity_id} (expiring key for user {agent_id}, lifetime 2h), then re-run this command or tk activity wait --id {activity_id}"
            ),
            "{pending}"
        );
        approve_and_wait(&run, &human, &pending);
    } else {
        let provisioned = run.submit(&mut provision, "session.provision");
        assert_eq!(provisioned["data"]["userId"], agent_id, "{provisioned}");
    }
    let registered = run.ok(&mut provision);
    assert_eq!(registered["status"], "completed", "{registered}");
    assert_eq!(
        registered["data"]["alreadyRegistered"], true,
        "{registered}"
    );
    assert_eq!(registered["data"]["publicKey"], public_key);
    assert_eq!(registered["data"]["expiresIn"], "2h");

    let activated = run.ok(run
        .cli()
        .args(["session", "activate", "--profile-name", &profile]));
    assert_eq!(activated["command"], "session.activate");
    assert_eq!(activated["data"]["publicKey"], public_key);
    assert_eq!(
        activated["data"]["identity"]["userId"], agent_id,
        "{activated}"
    );
    let identity = run.ok(run.cli().args(["--profile", &profile, "whoami"]));
    assert_eq!(identity["data"]["userId"], agent_id);

    let export_args = [
        "--profile",
        &profile,
        "secret",
        "export",
        "--name",
        &secret_name,
    ];
    let exported = if human_export {
        let pending = run.ok(run.cli().args(export_args));
        assert_eq!(pending["command"], "secret.export");
        assert_eq!(pending["data"]["value"], Value::Null, "{pending}");
        let id = approve_and_wait(&run, &human, &pending);
        let finished = run.ok(run.cli().args(export_args));
        assert_eq!(finished["activity"]["id"], id, "{finished}");
        finished
    } else {
        run.ok(run.cli().args(export_args))
    };
    assert_eq!(exported["status"], "completed", "{exported}");
    assert_eq!(exported["data"]["value"], "tok-1");

    run.assert_api_key_register_denied(run.cli().args(["--profile", &profile]), &agent_id);
}

#[test]
#[ignore]
fn provisioning_session_agent_human_mint_human_export() {
    provisioning_session_agent_cell(true, true);
}

#[test]
#[ignore]
fn provisioning_session_agent_human_mint_unilateral_export() {
    provisioning_session_agent_cell(true, false);
}

#[test]
#[ignore]
fn provisioning_session_agent_unilateral_mint_human_export() {
    provisioning_session_agent_cell(false, true);
}

#[test]
#[ignore]
fn provisioning_session_agent_unilateral_mint_unilateral_export() {
    provisioning_session_agent_cell(false, false);
}

#[test]
#[ignore]
fn provisioning_session_agent_provisioner_cannot_self_mint() {
    let run = Run::new();
    run.create_tag(AGENT_TAG);
    let (agent_id, agent_key) = run.create_tagged_user("agent", AGENT_TAG);
    let (other_agent_id, _) = run.create_tagged_user("agent-unapproved", AGENT_TAG);
    let Provisioners {
        provisioner_tag,
        human_tag: _,
        provisioner_id,
        provisioner,
        human: _,
    } = create_provisioners(&run, &agent_id, true);
    let (other_provisioner_id, _) = run.create_tagged_user("provisioner-2", PROVISIONER_TAG);
    run.create_policy_from_flags(
        &run.name("provisioners-nothing-else"),
        "deny",
        &tag_consensus(&provisioner_tag),
        "activity.type != 'ACTIVITY_TYPE_CREATE_API_KEYS_V2'",
    );

    let public_key = hex::encode(run.key().compressed_public_key());
    for target in [&provisioner_id, &other_agent_id, &other_provisioner_id] {
        run.err_unauthorized(&mut run.provision(&provisioner, target, &public_key));
    }
    let agent_key_id = run.api_key_id(&agent_id, &hex::encode(agent_key.compressed_public_key()));
    run.err_unauthorized(run.as_user(&provisioner).args([
        "api-key",
        "delete",
        "--user-id",
        &agent_id,
        "--id",
        &agent_key_id,
    ]));
}

#[test]
#[ignore]
fn provisioning_session_agent_unpinned_allow_leaves_self_mint_pending() {
    let run = Run::new();
    let provisioner_tag = run.create_tag(PROVISIONER_TAG);
    let human_tag = run.create_tag(HUMAN_TAG);
    let (provisioner_id, provisioner) = run.create_tagged_user("provisioner", PROVISIONER_TAG);
    run.create_tagged_user("human", HUMAN_TAG);
    run.create_policy_from_flags(
        &run.name("provisioners-mint-any-key"),
        "allow",
        &allow_once(&provisioner_tag, &human_tag),
        "activity.type == 'ACTIVITY_TYPE_CREATE_API_KEYS_V2'",
    );
    let public_key = hex::encode(run.key().compressed_public_key());
    let self_mint = run.ok(&mut run.provision(&provisioner, &provisioner_id, &public_key));
    assert_eq!(self_mint["status"], "pending", "{self_mint}");
    assert_eq!(self_mint["data"]["userId"], provisioner_id);
}

#[test]
#[ignore]
fn provisioning_session_agent_recovers_after_expiry() {
    let run = Run::new();
    let agent_tag = run.create_tag(AGENT_TAG);
    let (created, agent_key) = run.create_session_agent("agent", "1s");
    let agent_id = created_user_id(&created);
    let Provisioners {
        provisioner_tag: _,
        human_tag: _,
        provisioner_id: _,
        provisioner,
        human,
    } = create_provisioners(&run, &agent_id, true);
    run.deny_agent_credentials(&agent_tag);

    let profile = run.name("agent-profile");
    let key_file = run.home().join("agent-first.json");
    fs::write(
        &key_file,
        json!({
            "public_key": hex::encode(agent_key.compressed_public_key()),
            "private_key": hex::encode(agent_key.private_key()),
            "curve": "p256",
        })
        .to_string(),
    )
    .unwrap();
    run.ok(run
        .cli()
        .args([
            "profile",
            "create",
            "--profile-name",
            &profile,
            "--organization-id",
            run.org(),
            "--api-key-file",
        ])
        .arg(&key_file));
    // The API records the 1s key as expired at once but keeps authenticating
    // it for a while, so root revokes it to reach the same state without a
    // sleep: the profile's credential no longer identifies the agent.
    let first_key_id = run.api_key_id(&agent_id, &hex::encode(agent_key.compressed_public_key()));
    run.submit(
        run.admin().args([
            "api-key",
            "delete",
            "--user-id",
            &agent_id,
            "--id",
            &first_key_id,
        ]),
        "api-key.delete",
    );
    let expired = run.err(run.cli().args(["--profile", &profile, "whoami"]));
    assert_eq!(expired["code"], "unauthorized", "{expired}");

    let requested = run.ok(run
        .cli()
        .args(["session", "request", "--profile-name", &profile]));
    assert_eq!(requested["data"]["userId"], Value::Null, "{requested}");
    let public_key = requested["data"]["publicKey"].as_str().unwrap().to_string();
    let mut provision = run.provision(&provisioner, &agent_id, &public_key);
    let pending = run.ok(&mut provision);
    approve_and_wait(&run, &human, &pending);
    assert_eq!(run.ok(&mut provision)["data"]["alreadyRegistered"], true);
    let activated = run.ok(run
        .cli()
        .args(["session", "activate", "--profile-name", &profile]));
    assert_eq!(
        activated["data"]["identity"]["userId"], agent_id,
        "{activated}"
    );
    assert_eq!(activated["data"]["previousKeyFileRemoved"], false);
    let identity = run.ok(run.cli().args(["--profile", &profile, "whoami"]));
    assert_eq!(identity["data"]["userId"], agent_id);

    let renewal = run.ok(run
        .cli()
        .args(["session", "request", "--profile-name", &profile]));
    assert_eq!(renewal["data"]["userId"], agent_id, "{renewal}");
    let rejected_key = renewal["data"]["publicKey"].as_str().unwrap().to_string();
    let mut provision = run.provision(&provisioner, &agent_id, &rejected_key);
    let pending = run.ok(&mut provision);
    assert_eq!(pending["status"], "pending", "{pending}");
    let rejected_activity = id_of(&pending);
    let rejected = run.reject(&human, &rejected_activity);
    assert_eq!(rejected["status"], "rejected", "{rejected}");
    let resubmitted = run.ok(&mut provision);
    assert_eq!(resubmitted["status"], "pending", "{resubmitted}");
    assert_ne!(id_of(&resubmitted), rejected_activity, "{resubmitted}");
    let not_registered =
        run.err(
            run.cli()
                .args(["session", "activate", "--profile-name", &profile]),
        );
    assert_eq!(not_registered["code"], "unauthorized", "{not_registered}");

    let replaced = run.ok(run.cli().args([
        "session",
        "request",
        "--profile-name",
        &profile,
        "--replace",
    ]));
    let fresh_key = replaced["data"]["publicKey"].as_str().unwrap().to_string();
    assert_ne!(fresh_key, rejected_key);
    let mut provision = run.provision(&provisioner, &agent_id, &fresh_key);
    let pending = run.ok(&mut provision);
    approve_and_wait(&run, &human, &pending);
    let activated = run.ok(run
        .cli()
        .args(["session", "activate", "--profile-name", &profile]));
    assert_eq!(activated["data"]["publicKey"], fresh_key, "{activated}");
    assert_eq!(activated["data"]["previousPublicKey"], public_key);
    assert_eq!(activated["data"]["previousKeyFileRemoved"], true);
}
