use serde_json::{Value, json};

use crate::{
    policy_helpers::allow_once,
    run::{AGENT_TAG, HUMAN_TAG, Run, id_of, result},
};

#[test]
#[ignore]
fn activity_list_paginates_and_get_and_wait_inspect_a_completed_activity() {
    let run = Run::new();
    let (created, _) = run.create_user_activity("user-activity");
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

#[test]
#[ignore]
fn monitoring_activities_approve_reject_wait() {
    let run = Run::new();
    let agent_tag = run.create_tag(AGENT_TAG);
    let human_tag = run.create_tag(HUMAN_TAG);
    let (agent_id, agent) = run.create_tagged_user("agent", AGENT_TAG);
    let (human_id, human) = run.create_tagged_user("human", HUMAN_TAG);
    run.create_policy_from_flags(
        &run.name("agents-create-tags-with-approval"),
        "allow",
        &allow_once(&agent_tag, &human_tag),
        "activity.type == 'ACTIVITY_TYPE_CREATE_USER_TAG'",
    );

    let pending = run.ok(run.as_user(&agent).args([
        "user",
        "tag",
        "create",
        "--name",
        &run.name("approved"),
    ]));
    assert_eq!(pending["command"], "user.tag.create");
    assert_eq!(pending["status"], "pending");
    let activity = id_of(&pending);
    assert_eq!(
        pending["activity"],
        json!({"id": activity, "status": "ACTIVITY_STATUS_CONSENSUS_NEEDED"})
    );

    let listed = run.ok(run
        .as_user(&human)
        .args(["activity", "list", "--limit", "50"]));
    assert_eq!(listed["command"], "activity.list");
    let item = listed["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == activity)
        .unwrap_or_else(|| panic!("pending activity missing from list: {listed}"));
    assert_eq!(item["status"], "ACTIVITY_STATUS_CONSENSUS_NEEDED");
    assert_eq!(item["type"], "ACTIVITY_TYPE_CREATE_USER_TAG");

    let got = run.ok(run
        .as_user(&human)
        .args(["activity", "get", "--id", &activity]));
    assert_eq!(got["status"], "pending");
    assert_eq!(
        votes(&got),
        [(agent_id.as_str(), "VOTE_SELECTION_APPROVED")],
        "{got}"
    );

    let approved = run.approve(&human, &activity);
    assert_eq!(approved["command"], "activity.approve");
    assert_eq!(approved["activity"]["id"], activity);
    let waited = run.ok(run.as_user(&agent).args([
        "activity",
        "wait",
        "--id",
        &activity,
        "--timeout",
        "60",
    ]));
    assert_eq!(waited["command"], "activity.wait");
    assert_eq!(waited["status"], "completed");
    assert!(
        result(&waited, "createUserTagResult")["userTagId"].is_string(),
        "{waited}"
    );
    let got = run.ok(run
        .as_user(&agent)
        .args(["activity", "get", "--id", &activity]));
    let voters = votes(&got);
    assert_eq!(voters.len(), 2, "{got}");
    assert!(
        voters.iter().any(|(u, _)| *u == agent_id) && voters.iter().any(|(u, _)| *u == human_id)
    );

    let pending = run.ok(run.as_user(&agent).args([
        "user",
        "tag",
        "create",
        "--name",
        &run.name("rejected"),
    ]));
    assert_eq!(pending["status"], "pending");
    let rejected_activity = id_of(&pending);
    let rejected = run.reject(&human, &rejected_activity);
    assert_eq!(rejected["command"], "activity.reject");
    assert_eq!(rejected["status"], "rejected");
    let failed = run.err(run.as_user(&agent).args([
        "activity",
        "wait",
        "--id",
        &rejected_activity,
        "--timeout",
        "60",
    ]));
    assert_eq!(failed["code"], "api_error", "{failed}");
    assert_eq!(
        failed["details"]["activity"],
        json!({"id": rejected_activity, "status": "ACTIVITY_STATUS_REJECTED"})
    );
    let got = run.ok(run
        .as_user(&human)
        .args(["activity", "get", "--id", &rejected_activity]));
    assert!(
        votes(&got)
            .iter()
            .any(|(_, s)| *s == "VOTE_SELECTION_REJECTED"),
        "{got}"
    );
}

#[test]
#[ignore]
fn activity_list_filters_by_status_type_and_since() {
    let run = Run::new();
    let agent_tag = run.create_tag(AGENT_TAG);
    let human_tag = run.create_tag(HUMAN_TAG);
    let (_, agent) = run.create_tagged_user("agent", AGENT_TAG);
    let policy = run.submit(
        run.admin().args([
            "policy",
            "create",
            "--name",
            &run.name("agents-create-tags-with-approval"),
            "--effect",
            "allow",
            "--consensus",
            &allow_once(&agent_tag, &human_tag),
            "--condition",
            "activity.type == 'ACTIVITY_TYPE_CREATE_USER_TAG'",
        ]),
        "policy.create",
    );
    let policy_activity = id_of(&policy);
    let policy_type = policy["data"]["activity"]["type"].as_str().unwrap();

    let pending = run.ok(run.as_user(&agent).args([
        "user",
        "tag",
        "create",
        "--name",
        &run.name("awaiting-approval"),
    ]));
    assert_eq!(pending["status"], "pending", "{pending}");
    let pending_activity = id_of(&pending);

    let by_pending = run.ok(run
        .admin()
        .args(["activity", "list", "--status", "pending"]));
    assert_eq!(by_pending["command"], "activity.list");
    assert_eq!(
        ids(&by_pending),
        [pending_activity.as_str()],
        "{by_pending}"
    );
    assert_eq!(by_pending["data"]["nextCursor"], Value::Null);

    let by_completed = run.ok(run
        .admin()
        .args(["activity", "list", "--status", "completed"]));
    let completed = ids(&by_completed);
    assert!(
        completed.contains(&policy_activity.as_str()),
        "{by_completed}"
    );
    assert!(
        !completed.contains(&pending_activity.as_str()),
        "{by_completed}"
    );
    for item in by_completed["data"]["items"].as_array().unwrap() {
        assert_eq!(item["status"], "ACTIVITY_STATUS_COMPLETED", "{item}");
        assert!(item["votes"].is_array(), "{item}");
    }

    let by_type = run.ok(run.admin().args([
        "activity",
        "list",
        "--type",
        policy_type,
        "--status",
        "completed",
    ]));
    assert_eq!(ids(&by_type), [policy_activity.as_str()], "{by_type}");

    let recent = run.ok(run.admin().args(["activity", "list", "--since", "1h"]));
    let recent_ids = ids(&recent);
    assert!(recent_ids.contains(&pending_activity.as_str()), "{recent}");
    assert!(recent_ids.contains(&policy_activity.as_str()), "{recent}");
    assert_eq!(recent["data"]["nextCursor"], Value::Null);
    assert_eq!(
        recent_ids,
        ids(&run.ok(run.admin().args(["activity", "list"])))
    );

    let recent_pending = run.ok(run
        .admin()
        .args(["activity", "list", "--since", "1h", "--status", "pending"]));
    assert_eq!(ids(&recent_pending), [pending_activity.as_str()]);
    let recent_policies =
        run.ok(run
            .admin()
            .args(["activity", "list", "--since", "1h", "--type", policy_type]));
    assert_eq!(ids(&recent_policies), [policy_activity.as_str()]);

    let capped = run.ok(run
        .admin()
        .args(["activity", "list", "--since", "1h", "--limit", "1"]));
    assert_eq!(ids(&capped), [recent_ids[0]], "{capped}");
    assert_eq!(capped["data"]["nextCursor"], recent_ids[0]);
    let resumed = run.ok(run.admin().args([
        "activity",
        "list",
        "--since",
        "1h",
        "--cursor",
        recent_ids[0],
    ]));
    assert_eq!(ids(&resumed), recent_ids[1..], "{resumed}");
}

fn ids(record: &Value) -> Vec<&str> {
    record["data"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap())
        .collect()
}

fn votes(record: &Value) -> Vec<(&str, &str)> {
    record["data"]["activity"]["votes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|vote| {
            (
                vote["userId"].as_str().unwrap(),
                vote["selection"].as_str().unwrap(),
            )
        })
        .collect()
}
