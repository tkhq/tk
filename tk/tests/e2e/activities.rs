use crate::run::{Run, id_of, one_api_key, result, user_params};
use serde_json::json;

#[test]
#[ignore]
fn activity_list_paginates_and_get_and_wait_inspect_a_completed_activity() {
    let run = Run::new();
    let name = run.name("user-activity");
    let created = run.submit(
        run.admin().args([
            "user",
            "create",
            "--input-json",
            &user_params(&name, one_api_key(&run, &name)),
        ]),
        "user.create",
    );
    assert!(
        result(&created, "createUsersResult")["userIds"][0].is_string(),
        "{created}"
    );
    let activity_id = id_of(&created);

    let got = run.ok(run.admin().args(["activity", "get", "--id", &activity_id]));
    assert_eq!(got["command"], "activity.get");
    assert_eq!(got["status"], "completed");
    assert_eq!(
        got["activity"],
        json!({"id": activity_id, "status": "ACTIVITY_STATUS_COMPLETED"})
    );
    assert_eq!(got["data"]["activity"]["id"], activity_id);

    let waited = run.ok(run.admin().args(["activity", "wait", "--id", &activity_id]));
    assert_eq!(waited["command"], "activity.wait");
    assert_eq!(waited["status"], "completed");
    assert_eq!(waited["activity"], got["activity"]);

    for tag in ["tag-a", "tag-b"] {
        run.submit(
            run.admin().args([
                "user",
                "tag",
                "create",
                "--input-json",
                &json!({"userTagName": run.name(tag), "userIds": []}).to_string(),
            ]),
            "user.tag.create",
        );
    }
    let first = run.ok(run.admin().args(["activity", "list", "--limit", "2"]));
    assert_eq!(first["command"], "activity.list");
    let items = first["data"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(first["data"]["nextCursor"], items[1]["id"]);
    let cursor = items[1]["id"].as_str().unwrap();
    let second = run.ok(run
        .admin()
        .args(["activity", "list", "--limit", "2", "--cursor", cursor]));
    let next_items = second["data"]["items"].as_array().unwrap();
    assert!(!next_items.is_empty());
    for item in next_items {
        assert!(!items.contains(item), "cursor page repeated {}", item["id"]);
    }
}
