use crate::run::{Run, one_api_key, result, user_params};
use serde_json::json;

#[test]
#[ignore]
fn user_lifecycle_from_input_json_and_stdin() {
    let run = Run::new();

    let json_name = run.name("user-json");
    let created = run.submit(
        run.admin().args([
            "user",
            "create",
            "--input-json",
            &user_params(&json_name, one_api_key(&run, &json_name)),
        ]),
        "user.create",
    );
    assert_eq!(
        created["data"]["activity"]["type"],
        "ACTIVITY_TYPE_CREATE_USERS_V4"
    );
    let json_user = result(&created, "createUsersResult")["userIds"][0]
        .as_str()
        .unwrap()
        .to_string();

    let stdin_name = run.name("user-stdin");
    let created = run.submit(
        run.admin()
            .args(["user", "create", "--input-file", "-"])
            .write_stdin(user_params(&stdin_name, one_api_key(&run, &stdin_name))),
        "user.create",
    );
    let stdin_user = result(&created, "createUsersResult")["userIds"][0]
        .as_str()
        .unwrap()
        .to_string();

    for (id, name) in [(&json_user, &json_name), (&stdin_user, &stdin_name)] {
        let got = run.ok(run.admin().args(["user", "get", id]));
        assert_eq!(got["command"], "user.get");
        assert_eq!(got["data"]["user"]["userId"], *id);
        assert_eq!(got["data"]["user"]["userName"], *name);
    }
    let list = run.ok(run.admin().args(["user", "list"]));
    assert_eq!(list["command"], "user.list");
    let listed: Vec<&str> = list["data"]["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|user| user["userId"].as_str().unwrap())
        .collect();
    assert!(listed.contains(&json_user.as_str()));
    assert!(listed.contains(&stdin_user.as_str()));

    let deleted = run.submit(
        run.admin().args(["user", "delete", &stdin_user]),
        "user.delete",
    );
    assert_eq!(
        result(&deleted, "deleteUsersResult")["userIds"],
        json!([stdin_user])
    );
    let missing = run.err(run.admin().args(["user", "get", &stdin_user]));
    assert_eq!(missing["code"], "not_found");
}
