use crate::run::{Run, one_api_key, result, user_params};
use serde_json::{Value, json};
use std::fs;

#[test]
#[ignore]
fn api_key_register_list_delete() {
    let run = Run::new();
    let name = run.name("user-keys");
    let created = run.submit(
        run.admin().args([
            "user",
            "create",
            "--input-json",
            &user_params(&name, one_api_key(&run, &name)),
        ]),
        "user.create",
    );
    let user_id = result(&created, "createUsersResult")["userIds"][0]
        .as_str()
        .unwrap()
        .to_string();

    let key_path = run.home.path().join("registered.json");
    let generated = run.ok(run
        .cli()
        .args(["api-key", "generate", "--output"])
        .arg(&key_path));
    let public_key = generated["data"]["publicKey"].as_str().unwrap().to_string();
    let stored: Value = serde_json::from_slice(&fs::read(&key_path).unwrap()).unwrap();
    run.secrets
        .borrow_mut()
        .push(stored["private_key"].as_str().unwrap().to_string());

    let key_name = run.name("key");
    let registered = run.submit(
        run.admin().args([
            "api-key",
            "register",
            "--input-json",
            &json!({
                "userId": user_id,
                "apiKeys": [{
                    "apiKeyName": key_name,
                    "publicKey": public_key,
                    "curveType": "API_KEY_CURVE_P256",
                }],
            })
            .to_string(),
        ]),
        "api-key.register",
    );
    let api_key_id = result(&registered, "createApiKeysResult")["apiKeyIds"][0]
        .as_str()
        .unwrap()
        .to_string();

    let listed = run.ok(run.admin().args(["api-key", "list", "--user-id", &user_id]));
    assert_eq!(listed["command"], "api-key.list");
    let keys = listed["data"]["apiKeys"].as_array().unwrap();
    let ours = keys
        .iter()
        .find(|key| key["apiKeyId"] == api_key_id)
        .unwrap_or_else(|| panic!("registered key missing from list: {listed}"));
    assert_eq!(ours["apiKeyName"], key_name);
    assert_eq!(ours["credential"]["publicKey"], public_key);

    let deleted = run.submit(
        run.admin()
            .args(["api-key", "delete", "--user-id", &user_id, &api_key_id]),
        "api-key.delete",
    );
    assert_eq!(
        result(&deleted, "deleteApiKeysResult")["apiKeyIds"],
        json!([api_key_id])
    );
    let listed = run.ok(run.admin().args(["api-key", "list", "--user-id", &user_id]));
    assert!(
        listed["data"]["apiKeys"]
            .as_array()
            .unwrap()
            .iter()
            .all(|key| key["apiKeyId"] != api_key_id)
    );
}
