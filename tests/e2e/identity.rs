use crate::run::{AGENT_TAG, AdminLogin, HUMAN_TAG, Run, assert_unauthenticated, result};
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use uuid::Uuid;

fn stored_key(path: &Path, record: &Value) -> Value {
    let stored: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(
        !record
            .to_string()
            .contains(stored["private_key"].as_str().unwrap())
    );
    stored
}

#[test]
#[ignore]
fn api_key_generate_writes_0600_and_prints_only_public_key() {
    let run = Run::new();
    let path = run.home.path().join("agent-key.json");
    let record = run.generate_key(&path);
    let stored = stored_key(&path, &record);
    assert_eq!(record["schemaVersion"], 1);
    assert_eq!(record["reason"], "command_result");
    assert_eq!(record["command"], "api-key.generate");
    assert_eq!(record["status"], "completed");
    assert_eq!(
        record["data"],
        json!({"publicKey": stored["public_key"], "curve": "p256", "path": path})
    );
}

#[test]
#[ignore]
fn api_key_generate_without_output_writes_to_the_state_directory() {
    let run = Run::new();
    let record = run.ok(run.cli().args(["api-key", "generate"]));
    let public_key = record["data"]["publicKey"].as_str().unwrap().to_owned();
    let path = fs::canonicalize(
        run.home()
            .join(".config/turnkey/tk/api-keys")
            .join(format!("{public_key}.json")),
    )
    .unwrap();
    let stored = stored_key(&path, &record);
    assert_eq!(stored["public_key"], public_key);
    assert_eq!(record["command"], "api-key.generate");
    assert_eq!(record["status"], "completed");
    assert_eq!(
        record["data"],
        json!({"publicKey": public_key, "curve": "p256", "path": path})
    );
}

#[test]
#[ignore]
fn login_creates_registry_and_profile_commands_behave() {
    let run = Run::new();
    let AdminLogin {
        name,
        key_file,
        record: login,
    } = run.login_admin();
    let canonical_key_file = fs::canonicalize(&key_file).unwrap();
    let org = run.org();
    let base = run.config.api_base_url.clone();
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

    let set = run.ok(run.cli().args([
        "profile",
        "set",
        &name,
        "--api-base-url",
        &run.config.api_base_url,
    ]));
    assert_eq!(set["command"], "profile.set");
    assert_eq!(set["data"], json!({"name": name, "profile": profile}));
    let other_org = Uuid::nil().to_string();
    let moved = run.ok(run
        .cli()
        .args(["profile", "set", &name, "--organization-id", &other_org]));
    let mut moved_profile = profile.clone();
    moved_profile["organization_id"] = json!(other_org);
    assert_eq!(
        moved["data"],
        json!({"name": name, "profile": moved_profile})
    );
    assert_eq!(
        run.ok(run.cli().args(["profile", "show", &name]))["data"],
        json!({"name": name, "profile": moved_profile})
    );
    let restored = run.ok(run.cli().args([
        "profile",
        "set",
        &name,
        "--organization-id",
        org,
        "--api-base-url",
        &run.config.api_base_url,
    ]));
    assert_eq!(restored["data"], json!({"name": name, "profile": profile}));
    let unknown = run.err(run.cli().args([
        "profile",
        "set",
        "no-such-profile",
        "--organization-id",
        org,
    ]));
    assert_eq!(unknown["code"], "invalid_input");
    assert_eq!(unknown["message"], "profile no-such-profile does not exist");
    let malformed = run.err(run.cli().args([
        "profile",
        "set",
        &name,
        "--api-base-url",
        "ftp://api.turnkey.com",
    ]));
    assert_eq!(malformed["code"], "invalid_input");
    assert_eq!(
        run.ok(run.cli().args(["profile", "show", &name]))["data"],
        json!({"name": name, "profile": profile})
    );

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
    let AdminLogin { name, .. } = run.login_admin();
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
fn complete_bundle_authenticates_without_a_profile() {
    let run = Run::new();
    let whoami = run.ok(run.admin().arg("whoami"));
    assert_eq!(whoami["command"], "auth.whoami");
    assert_eq!(whoami["data"]["organizationId"], run.org());
    let users = run.ok(run.admin().args(["user", "list"]));
    assert_eq!(users["command"], "user.list");
    assert!(!run.registry_path().exists());
    let status = run.ok(run.admin().env_remove("HOME").args(["auth", "status"]));
    assert_eq!(
        status["data"],
        json!({
            "ready": true,
            "profile": Value::Null,
            "organizationId": run.org(),
            "apiBaseUrl": run.config.api_base_url,
            "publicKey": run.config.public_key,
            "credentialSource": "environment",
        })
    );
}

#[test]
#[ignore]
fn partial_bundle_is_invalid_input_without_registry_fallback() {
    let run = Run::new();
    run.login_admin();
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
fn login_with_unregistered_credential_fails_and_selects_nothing() {
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
    let name = run.name("nope");
    run.ok(run
        .cli()
        .args([
            "profile",
            "create",
            "--profile-name",
            &name,
            "--organization-id",
            run.org(),
            "--api-key-file",
        ])
        .arg(&key_file));
    let error = run.err(run.cli().args(["login", "--profile-name", &name]));
    assert_eq!(error["reason"], "command_error");
    assert_unauthenticated(&error);
    assert_eq!(
        run.ok(run.cli().args(["profile", "list"]))["data"]["activeProfile"],
        Value::Null
    );
}

#[test]
#[ignore]
fn profile_create_generates_a_credential_that_logs_in_once_registered() {
    let run = Run::new();
    let name = run.name("fresh");
    let org = run.org();
    let created = run.ok(run.cli().args([
        "profile",
        "create",
        "--profile-name",
        &name,
        "--organization-id",
        org,
    ]));
    assert_eq!(created["command"], "profile.create");
    let public_key = created["data"]["publicKey"].as_str().unwrap().to_string();
    let key_file = fs::canonicalize(
        run.home()
            .join(".config/turnkey/tk/api-keys")
            .join(format!("{public_key}.json")),
    )
    .unwrap();
    let profile = json!({
        "organization_id": org,
        "api_base_url": run.config.api_base_url,
        "api_key_file": key_file,
    });
    assert_eq!(
        created["data"],
        json!({
            "name": name,
            "profile": profile,
            "publicKey": public_key,
            "nextStep": format!("register public key {public_key} (API_KEY_CURVE_P256) on a user in organization {org}, then run tk login --profile-name {name}"),
        })
    );
    let stored = stored_key(&key_file, &created);
    run.secrets
        .borrow_mut()
        .push(stored["private_key"].as_str().unwrap().to_owned());
    assert_eq!(stored["public_key"], public_key);
    assert_eq!(
        run.ok(run.cli().args(["profile", "show", &name]))["data"],
        json!({"name": name, "profile": profile})
    );

    let unregistered = run.err(run.cli().args(["login", "--profile-name", &name]));
    assert_unauthenticated(&unregistered);
    assert_eq!(
        run.err(run.cli().args(["auth", "status"]))["code"],
        "invalid_input"
    );

    let (user_id, _) = run.create_user("fresh-login");
    let registered = run.register_api_key(&user_id, &run.name("fresh-key"), &public_key);
    assert_eq!(
        result(&registered, "createApiKeysResult")["apiKeyIds"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let login = run.ok(run.cli().args(["login", "--profile-name", &name]));
    assert_eq!(login["command"], "auth.login");
    let whoami = run.ok(run.cli().args(["--profile", &name, "whoami"]));
    assert_eq!(whoami["command"], "auth.whoami");
    assert_eq!(whoami["data"]["userId"], user_id);
    assert_eq!(
        login["data"],
        json!({"profile": name, "identity": whoami["data"]})
    );
    let status = run.ok(run.cli().args(["auth", "status"]));
    assert_eq!(
        status["data"],
        json!({
            "ready": true,
            "profile": name,
            "organizationId": org,
            "apiBaseUrl": run.config.api_base_url,
            "publicKey": public_key,
            "credentialSource": "profile",
        })
    );
}

#[test]
#[ignore]
fn profile_set_switches_the_credential_file() {
    let run = Run::new();
    let admin = run.login_admin();
    let next_key_file = run.home().join("next-key.json");
    let next_public = run.generate_key(&next_key_file)["data"]["publicKey"].clone();

    let set = run.ok(run
        .cli()
        .args(["profile", "set", &admin.name, "--api-key-file"])
        .arg(&next_key_file));
    assert_eq!(set["command"], "profile.set");
    assert_eq!(
        set["data"]["profile"]["api_key_file"],
        fs::canonicalize(&next_key_file).unwrap().to_str().unwrap()
    );
    assert_eq!(set["data"]["publicKey"], next_public);
    assert_eq!(
        set["data"]["previousApiKeyFile"],
        fs::canonicalize(&admin.key_file).unwrap().to_str().unwrap()
    );

    // The new key is not registered, so the profile no longer authenticates.
    let denied = run.err(run.cli().args(["--profile", &admin.name, "whoami"]));
    assert_eq!(denied["code"], "unauthorized", "{denied}");

    let restored = run.ok(run
        .cli()
        .args(["profile", "set", &admin.name, "--api-key-file"])
        .arg(&admin.key_file));
    assert_eq!(
        restored["data"]["profile"]["api_key_file"],
        fs::canonicalize(&admin.key_file).unwrap().to_str().unwrap()
    );
    run.ok(run.cli().args(["--profile", &admin.name, "whoami"]));

    let missing = run.err(
        run.cli()
            .args(["profile", "set", &admin.name, "--api-key-file"])
            .arg(run.home().join("absent.json")),
    );
    assert_eq!(missing["code"], "invalid_input", "{missing}");
    assert_eq!(
        run.ok(run.cli().args(["profile", "show", &admin.name]))["data"]["profile"]["api_key_file"],
        fs::canonicalize(&admin.key_file).unwrap().to_str().unwrap()
    );
}

#[test]
#[ignore]
fn bootstrapping_organization_root_tags_and_approval_model() {
    let run = Run::new();
    let admin = run.login_admin();
    let root_user = admin.record["data"]["identity"]["userId"]
        .as_str()
        .unwrap()
        .to_string();

    let whoami = run.ok(run.cli().args(["--profile", &admin.name, "whoami"]));
    assert_eq!(whoami["command"], "auth.whoami");
    assert_eq!(whoami["data"]["userId"], root_user);
    assert_eq!(whoami["data"]["organizationId"], run.org());

    let mut tags = Vec::new();
    for name in [AGENT_TAG, "provisioner", HUMAN_TAG] {
        let created = run.submit(
            run.cli().args([
                "--profile",
                &admin.name,
                "user",
                "tag",
                "create",
                "--name",
                name,
            ]),
            "user.tag.create",
        );
        let id = result(&created, "createUserTagResult")["userTagId"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(Uuid::parse_str(&id).is_ok(), "{created}");
        tags.push((name, id));
    }
    let human_tag = &tags[2].1;

    let updated = run.submit(
        run.cli().args([
            "--profile",
            &admin.name,
            "user",
            "update",
            "--input-json",
            &json!({"userId": root_user, "userTagIds": [human_tag]}).to_string(),
        ]),
        "user.update",
    );
    assert_eq!(
        updated["data"]["activity"]["type"],
        "ACTIVITY_TYPE_UPDATE_USER"
    );

    let got = run.ok(run
        .cli()
        .args(["--profile", &admin.name, "user", "get", &root_user]));
    assert_eq!(got["data"]["user"]["userTags"], json!([human_tag]));

    let listed = run.ok(run
        .cli()
        .args(["--profile", &admin.name, "user", "tag", "list"]));
    let listed: Vec<(&str, &str)> = listed["data"]["userTags"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tag| {
            (
                tag["tagName"].as_str().unwrap(),
                tag["tagId"].as_str().unwrap(),
            )
        })
        .collect();
    for (name, id) in &tags {
        assert!(listed.contains(&(name, id.as_str())), "{listed:?}");
    }
}
