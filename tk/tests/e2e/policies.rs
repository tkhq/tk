use crate::run::{Run, id_of, result};
use serde_json::json;

#[test]
#[ignore]
fn policy_lifecycle_and_update_field_names() {
    let run = Run::new();
    let name = run.name("policy");
    let created = run.submit(
        run.admin().args([
            "policy",
            "create",
            "--input-json",
            &json!({
                "policyName": name,
                "effect": "EFFECT_DENY",
                "condition": "false",
                "notes": "tk e2e",
            })
            .to_string(),
        ]),
        "policy.create",
    );
    assert_eq!(
        created["data"]["activity"]["type"],
        "ACTIVITY_TYPE_CREATE_POLICY_V3"
    );
    let policy_id = result(&created, "createPolicyResult")["policyId"]
        .as_str()
        .unwrap()
        .to_string();

    let got = run.ok(run.admin().args(["policy", "get", &policy_id]));
    assert_eq!(got["command"], "policy.get");
    assert_eq!(got["data"]["policy"]["policyId"], policy_id);
    assert_eq!(got["data"]["policy"]["policyName"], name);
    assert_eq!(got["data"]["policy"]["effect"], "EFFECT_DENY");
    assert_eq!(got["data"]["policy"]["condition"], "false");
    assert_eq!(got["data"]["policy"]["notes"], "tk e2e");

    let updated = run.submit(
        run.admin().args([
            "policy",
            "update",
            "--input-json",
            &json!({"policyId": policy_id, "policyNotes": "updated by tk e2e"}).to_string(),
        ]),
        "policy.update",
    );
    assert_eq!(
        updated["data"]["activity"]["type"],
        "ACTIVITY_TYPE_UPDATE_POLICY_V2"
    );
    let got = run.ok(run.admin().args(["policy", "get", &policy_id]));
    assert_eq!(got["data"]["policy"]["notes"], "updated by tk e2e");
    assert_eq!(got["data"]["policy"]["policyName"], name);
    let list = run.ok(run.admin().args(["policy", "list"]));
    assert_eq!(list["command"], "policy.list");
    assert!(
        list["data"]["policies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|policy| policy["policyId"] == policy_id)
    );

    let rejected = run.err(run.admin_offline().args([
        "policy",
        "update",
        "--input-json",
        &json!({"policyId": policy_id, "notes": "x"}).to_string(),
    ]));
    assert_eq!(rejected["reason"], "command_error");
    assert_eq!(rejected["code"], "invalid_input");
    assert!(
        rejected["message"]
            .as_str()
            .unwrap()
            .contains("unsupported field parameters.notes")
    );

    let deleted = run.submit(
        run.admin().args(["policy", "delete", &policy_id]),
        "policy.delete",
    );
    assert_eq!(
        result(&deleted, "deletePolicyResult")["policyId"],
        policy_id
    );
    let missing = run.err(run.admin().args(["policy", "get", &policy_id]));
    assert_eq!(missing["code"], "not_found");
}

#[test]
#[ignore]
fn consensus_approve_and_reject() {
    let run = Run::new();
    let (submitter_id, submitter) = run.create_user("submitter");
    let (approver_id, approver) = run.create_user("approver");

    let created = run.submit(
        run.admin().args([
            "policy",
            "create",
            "--input-json",
            &json!({
                "policyName": run.name("consensus"),
                "effect": "EFFECT_ALLOW",
                "condition": "activity.type == 'ACTIVITY_TYPE_CREATE_USER_TAG'",
                "consensus": format!(
                    "approvers.any(user, user.id == '{submitter_id}') && approvers.any(user, user.id == '{approver_id}')"
                ),
                "notes": "tk e2e consensus",
            })
            .to_string(),
        ]),
        "policy.create",
    );
    assert!(
        result(&created, "createPolicyResult")["policyId"].is_string(),
        "{created}"
    );

    let pending = run.ok(run.as_user(&submitter).args([
        "user",
        "tag",
        "create",
        "--input-json",
        &json!({"userTagName": run.name("tag-approved"), "userIds": []}).to_string(),
    ]));
    assert_eq!(pending["command"], "user.tag.create");
    assert_eq!(pending["status"], "pending");
    let tag_activity = id_of(&pending);
    assert_eq!(
        pending["activity"],
        json!({"id": tag_activity, "status": "ACTIVITY_STATUS_CONSENSUS_NEEDED"})
    );

    let timed_out =
        run.err(
            run.as_user(&approver)
                .args(["activity", "wait", &tag_activity, "--timeout", "2"]),
        );
    assert_eq!(timed_out["reason"], "command_error");
    assert_eq!(timed_out["code"], "wait_timeout");
    assert_eq!(timed_out["details"]["activity"], pending["activity"]);

    let approved = run.ok(run
        .as_user(&approver)
        .args(["activity", "approve", &tag_activity]));
    assert_eq!(approved["command"], "activity.approve");
    assert_eq!(approved["activity"]["id"], tag_activity);
    assert!(
        matches!(approved["status"].as_str(), Some("completed" | "pending")),
        "{approved}"
    );
    let completed = run.wait(&tag_activity);
    let tag_id = result(&completed, "createUserTagResult")["userTagId"]
        .as_str()
        .unwrap()
        .to_string();
    let tags = run.ok(run.as_user(&approver).args(["user", "tag", "list"]));
    assert_eq!(tags["command"], "user.tag.list");
    assert!(
        tags["data"]["userTags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tag| tag["tagId"] == tag_id)
    );
    let evaluations = run.ok(run
        .as_user(&approver)
        .args(["policy", "evaluations", &tag_activity]));
    assert_eq!(evaluations["command"], "policy.evaluations");
    assert!(
        !evaluations["data"]["policyEvaluations"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let pending = run.ok(run.as_user(&submitter).args([
        "user",
        "tag",
        "create",
        "--input-json",
        &json!({"userTagName": run.name("tag-rejected"), "userIds": []}).to_string(),
    ]));
    assert_eq!(pending["status"], "pending");
    let rejected_activity = id_of(&pending);
    let rejected = run.ok(run
        .as_user(&approver)
        .args(["activity", "reject", &rejected_activity]));
    assert_eq!(rejected["command"], "activity.reject");
    assert_eq!(rejected["status"], "rejected");
    assert_eq!(
        rejected["activity"],
        json!({"id": rejected_activity, "status": "ACTIVITY_STATUS_REJECTED"})
    );
    let failed = run.err(
        run.as_user(&submitter)
            .args(["activity", "wait", &rejected_activity]),
    );
    assert_eq!(failed["reason"], "command_error");
    assert_eq!(failed["code"], "api_error");
    assert_eq!(
        failed["details"]["activity"],
        json!({"id": rejected_activity, "status": "ACTIVITY_STATUS_REJECTED"})
    );
    let inspected = run.ok(run
        .as_user(&approver)
        .args(["activity", "get", &rejected_activity]));
    assert_eq!(inspected["status"], "rejected");
}
