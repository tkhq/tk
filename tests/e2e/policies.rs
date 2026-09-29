use crate::policy_helpers::tag_consensus;
use crate::run::{AGENT_TAG, Run, id_of, result};
use serde_json::json;

#[test]
#[ignore]
fn policy_lifecycle_and_update_field_names() {
    let run = Run::new();
    let name = run.name("policy");
    let created = run.create_policy(json!({
        "policyName": name,
        "effect": "EFFECT_DENY",
        "condition": "false",
        "notes": "tk e2e",
    }));
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
fn quorum_approval_completes_and_rejection_fails_a_consensus_activity() {
    let run = Run::new();
    let (submitter_id, submitter) = run.create_user("submitter");
    let (approver_id, approver) = run.create_user("approver");

    let created = run.create_policy(json!({
        "policyName": run.name("consensus"),
        "effect": "EFFECT_ALLOW",
        "condition": "activity.type == 'ACTIVITY_TYPE_CREATE_USER_TAG'",
        "consensus": format!(
            "approvers.any(user, user.id == '{submitter_id}') && approvers.any(user, user.id == '{approver_id}')"
        ),
        "notes": "tk e2e consensus",
    }));
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

    // The activity stays in consensus, so any timeout expires; the budget only
    // has to cover the polls that observe the pending status it reports back.
    let timed_out = run.err(run.as_user(&approver).args([
        "activity",
        "wait",
        &tag_activity,
        "--timeout",
        "10",
    ]));
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

#[test]
#[ignore]
fn policy_create_from_flags_stores_effect_condition_consensus_and_notes() {
    let run = Run::new();
    let name = run.name("flag-policy");
    let created = run.submit(
        run.admin().args([
            "policy",
            "create",
            "--name",
            &name,
            "--effect",
            "deny",
            "--condition",
            "activity.resource == 'CREDENTIAL'",
            "--consensus",
            "approvers.any(user, user.tags.contains('00000000-0000-4000-8000-000000000001'))",
            "--notes",
            "tk e2e flags",
        ]),
        "policy.create",
    );
    let policy_id = result(&created, "createPolicyResult")["policyId"]
        .as_str()
        .unwrap()
        .to_string();
    let got = run.ok(run.admin().args(["policy", "get", &policy_id]));
    assert_eq!(got["data"]["policy"]["policyName"], name);
    assert_eq!(got["data"]["policy"]["effect"], "EFFECT_DENY");
    assert_eq!(
        got["data"]["policy"]["condition"],
        "activity.resource == 'CREDENTIAL'"
    );
    assert_eq!(
        got["data"]["policy"]["consensus"],
        "approvers.any(user, user.tags.contains('00000000-0000-4000-8000-000000000001'))"
    );
    assert_eq!(got["data"]["policy"]["notes"], "tk e2e flags");
}

#[test]
#[ignore]
fn managing_policies_crud_and_evaluations() {
    let run = Run::new();
    let agent_tag = run.create_tag(AGENT_TAG);
    let (_, agent) = run.create_tagged_user("agent", AGENT_TAG);

    let name = run.name("agents-create-tags");
    let consensus = tag_consensus(&agent_tag);
    let condition = "activity.type == 'ACTIVITY_TYPE_CREATE_USER_TAG'";
    let policy_id = run.create_policy_from_flags(&name, "allow", &consensus, condition);

    let got = run.ok(run.admin().args(["policy", "get", &policy_id]));
    assert_eq!(got["command"], "policy.get");
    assert_eq!(got["data"]["policy"]["policyName"], name);
    assert_eq!(got["data"]["policy"]["effect"], "EFFECT_ALLOW");
    assert_eq!(got["data"]["policy"]["condition"], condition);
    assert_eq!(got["data"]["policy"]["consensus"], consensus);
    let listed = run.ok(run.admin().args(["policy", "list"]));
    assert!(
        listed["data"]["policies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|policy| policy["policyId"] == policy_id),
        "{listed}"
    );

    let allowed = run.submit(
        run.as_user(&agent)
            .args(["user", "tag", "create", "--name", &run.name("allowed")]),
        "user.tag.create",
    );
    let allowed_activity = id_of(&allowed);
    let evaluations = run.ok(run
        .admin()
        .args(["policy", "evaluations", &allowed_activity]));
    assert_eq!(evaluations["command"], "policy.evaluations");
    let outcomes: Vec<(&str, &str)> = evaluations["data"]["policyEvaluations"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|vote| vote["policyEvaluations"].as_array().unwrap())
        .map(|evaluation| {
            (
                evaluation["policyId"].as_str().unwrap(),
                evaluation["outcome"].as_str().unwrap(),
            )
        })
        .collect();
    assert!(
        outcomes.contains(&(policy_id.as_str(), "OUTCOME_ALLOW")),
        "{evaluations}"
    );

    let denied = run.err(run.as_user(&agent).args([
        "policy",
        "create",
        "--name",
        &run.name("escape"),
        "--effect",
        "allow",
        "--condition",
        "true",
    ]));
    assert_eq!(denied["code"], "unauthorized", "{denied}");
    assert_eq!(denied["httpStatus"], 403, "{denied}");

    let updated = run.submit(
        run.admin().args([
            "policy",
            "update",
            "--input-json",
            &json!({"policyId": policy_id, "policyNotes": "revised"}).to_string(),
        ]),
        "policy.update",
    );
    assert_eq!(
        updated["data"]["activity"]["type"],
        "ACTIVITY_TYPE_UPDATE_POLICY_V2"
    );
    let got = run.ok(run.admin().args(["policy", "get", &policy_id]));
    assert_eq!(got["data"]["policy"]["notes"], "revised");
    assert_eq!(got["data"]["policy"]["condition"], condition);

    run.submit(
        run.admin().args(["policy", "delete", &policy_id]),
        "policy.delete",
    );
    let missing = run.err(run.admin().args(["policy", "get", &policy_id]));
    assert_eq!(missing["code"], "not_found", "{missing}");
    let denied = run.err(run.as_user(&agent).args([
        "user",
        "tag",
        "create",
        "--name",
        &run.name("after-delete"),
    ]));
    assert_eq!(denied["code"], "unauthorized", "{denied}");
}
