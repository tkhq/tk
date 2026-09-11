use crate::run::Run;
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt;

#[test]
#[ignore]
fn api_key_generate_writes_0600_and_prints_only_public_key() {
    let run = Run::new();
    let path = run.home.path().join("agent-key.json");
    let record = run.ok(run
        .cli()
        .args(["api-key", "generate", "--output"])
        .arg(&path));
    let stored: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(record["schemaVersion"], 1);
    assert_eq!(record["reason"], "command_result");
    assert_eq!(record["command"], "api-key.generate");
    assert_eq!(record["status"], "completed");
    assert_eq!(
        record["data"],
        json!({"publicKey": stored["public_key"], "curve": "p256", "path": path})
    );
    assert!(
        !record
            .to_string()
            .contains(stored["private_key"].as_str().unwrap())
    );
}

#[test]
#[ignore]
fn login_creates_registry_and_profile_commands_behave() {
    let run = Run::new();
    let name = run.name("admin");
    let key_file = run.admin_key_file();
    let canonical_key_file = fs::canonicalize(&key_file).unwrap();
    let org = run.org();
    let base = run.config.api_base_url.clone();

    let login = run.ok(run
        .cli()
        .args(["login", &name, "--organization-id", &org, "--api-key-file"])
        .arg(&key_file));
    assert_eq!(login["command"], "auth.login");
    assert_eq!(login["status"], "completed");
    assert_eq!(login["data"]["profile"], name);
    assert_eq!(login["data"]["identity"]["organizationId"], org);
    assert!(run.registry_path().exists());

    let status = run.ok(run.cli().args(["auth", "status"]));
    assert_eq!(status["command"], "auth.status");
    assert_eq!(
        status["data"],
        json!({
            "ready": true,
            "profile": name,
            "organizationId": org,
            "apiBaseUrl": base,
            "publicKey": run.config.public_key,
            "credentialSource": "profile",
        })
    );

    let whoami = run.ok(run.cli().arg("whoami"));
    assert_eq!(whoami["command"], "auth.whoami");
    assert_eq!(whoami["data"], login["data"]["identity"]);

    let profile = json!({
        "organization_id": org,
        "api_base_url": base,
        "api_key_file": canonical_key_file,
    });
    let list = run.ok(run.cli().args(["profile", "list"]));
    assert_eq!(list["command"], "profile.list");
    assert_eq!(
        list["data"],
        json!({"activeProfile": name, "profiles": {name.clone(): profile}})
    );

    let show = run.ok(run.cli().args(["profile", "show", &name]));
    assert_eq!(show["command"], "profile.show");
    assert_eq!(show["data"], json!({"name": name, "profile": profile}));

    let logout = run.ok(run.cli().args(["auth", "logout"]));
    assert_eq!(logout["command"], "auth.logout");
    assert_eq!(
        logout["data"],
        json!({"activeProfile": null, "environmentCredentialsPresent": false})
    );
    let no_identity = run.err(run.cli().args(["auth", "status"]));
    assert_eq!(no_identity["code"], "invalid_input");

    let used = run.ok(run.cli().args(["profile", "use", &name]));
    assert_eq!(used["command"], "profile.use");
    assert_eq!(used["data"], json!({"activeProfile": name}));
    assert_eq!(
        run.ok(run.cli().args(["auth", "status"]))["data"]["profile"],
        name
    );

    let deleted = run.ok(run.cli().args(["profile", "delete", &name]));
    assert_eq!(deleted["command"], "profile.delete");
    assert_eq!(
        deleted["data"],
        json!({"name": name, "credentialFilesDeleted": false})
    );
    assert!(key_file.exists());
    assert_eq!(
        run.ok(run.cli().args(["profile", "list"]))["data"],
        json!({"activeProfile": null, "profiles": {}})
    );
}

#[test]
#[ignore]
fn profile_flag_beats_ambient_bundle() {
    let run = Run::new();
    let name = run.name("admin");
    let key_file = run.admin_key_file();
    run.ok(run
        .cli()
        .args([
            "login",
            &name,
            "--organization-id",
            &run.org(),
            "--api-key-file",
        ])
        .arg(&key_file));
    let status = run.ok(run.cli().env("TURNKEY_API_PRIVATE_KEY", "unused").args([
        "--profile",
        &name,
        "auth",
        "status",
    ]));
    assert_eq!(status["data"]["credentialSource"], "profile");
    assert_eq!(status["data"]["profile"], name);
    assert_eq!(status["data"]["publicKey"], run.config.public_key);
}

#[test]
#[ignore]
fn complete_bundle_works_without_home() {
    let run = Run::new();
    let whoami = run.ok(run.admin().env_remove("HOME").arg("whoami"));
    assert_eq!(whoami["command"], "auth.whoami");
    assert_eq!(whoami["data"]["organizationId"], run.org());
    assert!(!run.registry_path().exists());
    let status = run.ok(run.admin().env_remove("HOME").args(["auth", "status"]));
    assert_eq!(status["data"]["credentialSource"], "environment");
    assert_eq!(status["data"]["profile"], Value::Null);
}

#[test]
#[ignore]
fn partial_bundle_is_invalid_input_without_registry_fallback() {
    let run = Run::new();
    let name = run.name("admin");
    let key_file = run.admin_key_file();
    run.ok(run
        .cli()
        .args([
            "login",
            &name,
            "--organization-id",
            &run.org(),
            "--api-key-file",
        ])
        .arg(&key_file));
    let error = run.err(
        run.cli()
            .env("TURNKEY_API_PRIVATE_KEY", &run.config.private_key.0)
            .args(["auth", "status"]),
    );
    assert_eq!(error["reason"], "command_error");
    assert_eq!(error["code"], "invalid_input");
    assert_eq!(error.get("httpStatus"), None);
}

#[test]
#[ignore]
fn login_with_unregistered_credential_fails_and_writes_no_profile() {
    let run = Run::new();
    let key = run.key();
    let key_file = run.home.path().join("unregistered.json");
    fs::write(
        &key_file,
        json!({
            "public_key": hex::encode(key.compressed_public_key()),
            "private_key": hex::encode(key.private_key()),
            "curve": "p256",
        })
        .to_string(),
    )
    .unwrap();
    let error = run.err(
        run.cli()
            .args([
                "login",
                &run.name("nope"),
                "--organization-id",
                &run.org(),
                "--api-key-file",
            ])
            .arg(&key_file),
    );
    assert_eq!(error["reason"], "command_error");
    assert_eq!(error["code"], "unauthorized");
    assert_eq!(error["httpStatus"], 401);
    assert!(!run.registry_path().exists());
}
