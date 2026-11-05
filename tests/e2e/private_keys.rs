//! Live `private-key` command coverage.

use serde_json::json;

use crate::run::{Run, result};

#[test]
#[ignore]
fn private_key_create_get_and_list() {
    let run = Run::new();
    let name = run.name("pk");
    let created = run.submit(
        run.admin().args([
            "private-key",
            "create",
            "--name",
            &name,
            "--curve",
            "secp256k1",
            "--address-format",
            "ethereum",
        ]),
        "private-key.create",
    );
    assert_eq!(
        created["data"]["activity"]["type"],
        "ACTIVITY_TYPE_CREATE_PRIVATE_KEYS_V2"
    );
    let private_key_id =
        result(&created, "createPrivateKeysResultV2")["privateKeys"][0]["privateKeyId"]
            .as_str()
            .unwrap()
            .to_string();

    let got = run.ok(run
        .admin()
        .args(["private-key", "get", "--id", &private_key_id]));
    assert_eq!(got["command"], "private-key.get");
    let key = &got["data"]["privateKey"];
    assert_eq!(key["privateKeyId"], private_key_id);
    assert_eq!(key["privateKeyName"], name);
    assert_eq!(key["curve"], "CURVE_SECP256K1");
    let addresses = key["addresses"].as_array().unwrap();
    assert_eq!(addresses.len(), 1);
    assert_eq!(addresses[0]["format"], "ADDRESS_FORMAT_ETHEREUM");

    let listed = run.ok(run.admin().args(["private-key", "list"]));
    assert_eq!(listed["command"], "private-key.list");
    let keys = listed["data"]["privateKeys"].as_array().unwrap();
    assert!(
        keys.iter()
            .any(|listed| listed["privateKeyId"] == private_key_id),
        "{listed}"
    );
}

#[test]
#[ignore]
fn private_key_create_from_json_makes_several_keys() {
    let run = Run::new();
    let first = run.name("pk-a");
    let second = run.name("pk-b");
    let created = run.submit(
        run.admin().args([
            "private-key",
            "create",
            "--input-json",
            &json!({"privateKeys": [
                {"privateKeyName": first, "curve": "CURVE_ED25519"},
                {"privateKeyName": second, "curve": "CURVE_SECP256K1"},
            ]})
            .to_string(),
        ]),
        "private-key.create",
    );
    assert_eq!(
        result(&created, "createPrivateKeysResultV2")["privateKeys"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let listed = run.ok(run.admin().args(["private-key", "list"]));
    let mut names: Vec<&str> = listed["data"]["privateKeys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key["privateKeyName"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(names, [first.as_str(), second.as_str()]);
}
