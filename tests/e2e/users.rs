use crate::policy_helpers::{SignScope, allow_once};
use crate::run::{
    AGENT_TAG, HUMAN_TAG, Run, created_user_id, id_of, one_api_key, result, user_params,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

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
    let json_user = created_user_id(&created);

    let stdin_name = run.name("user-stdin");
    let created = run.submit(
        run.admin()
            .args(["user", "create", "--input-file", "-"])
            .write_stdin(user_params(&stdin_name, one_api_key(&run, &stdin_name))),
        "user.create",
    );
    let stdin_user = created_user_id(&created);

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

#[test]
#[ignore]
fn user_create_from_flags_resolves_tag_names_and_registers_anchor_and_expiring_keys() {
    let run = Run::new();
    let tag_name = run.name("agent");
    let tag_id = run.create_tag(&tag_name);

    let key = run.key();
    let public_key = hex::encode(key.compressed_public_key());
    let user_name = run.name("flag-user");

    // Turnkey requires one long-lived credential per user.
    let expiring_only = run.err(run.admin().args([
        "user",
        "create",
        "--user-name",
        &user_name,
        "--public-key",
        &public_key,
        "--expires-in",
        "2h",
    ]));
    assert_eq!(expiring_only["code"], "api_error", "{expiring_only}");
    assert_eq!(expiring_only["httpStatus"], 400, "{expiring_only}");

    let created = run.submit(
        run.admin().args([
            "user",
            "create",
            "--user-name",
            &user_name,
            "--tag-name",
            &tag_name,
            "--public-key",
            &public_key,
            "--expires-in",
            "2h",
            "--anchor-key",
        ]),
        "user.create",
    );
    let user_id = created_user_id(&created);

    let got = run.ok(run.admin().args(["user", "get", &user_id]));
    assert_eq!(got["data"]["user"]["userName"], user_name);
    assert_eq!(got["data"]["user"]["userTags"], json!([tag_id]));
    let keys = run.ok(run.admin().args(["api-key", "list", "--user-id", &user_id]));
    let ours = keys["data"]["apiKeys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["credential"]["publicKey"] == public_key)
        .unwrap_or_else(|| panic!("registered key missing: {keys}"));
    assert_eq!(ours["apiKeyName"], format!("{user_name}-key"));
    assert_eq!(ours["expirationSeconds"], "7200");
    let created: u64 = ours["createdAt"]["seconds"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        ours["expiresAt"],
        ((created + 7200) * 1000).to_string(),
        "{ours}"
    );
    let anchor = keys["data"]["apiKeys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["apiKeyName"] == format!("{user_name}-anchor"))
        .unwrap_or_else(|| panic!("anchor key missing: {keys}"));
    assert_eq!(anchor["expirationSeconds"], Value::Null, "{anchor}");
    assert_eq!(keys["data"]["apiKeys"].as_array().unwrap().len(), 2);

    let whoami = run.ok(run.as_user(&key).arg("whoami"));
    assert_eq!(whoami["data"]["userId"], user_id);

    let unknown_tag = run.err(run.admin().args([
        "user",
        "create",
        "--user-name",
        &run.name("orphan"),
        "--tag-name",
        &run.name("no-such-tag"),
    ]));
    assert_eq!(unknown_tag["code"], "not_found", "{unknown_tag}");
}

#[test]
#[ignore]
fn user_list_filters_by_tag_name_or_id() {
    let run = Run::new();
    let tag_name = run.name("tagged");
    let tag_id = run.create_tag(&tag_name);
    let (first, _) = run.create_tagged_user("tagged-a", &tag_name);
    let (second, _) = run.create_tagged_user("tagged-b", &tag_name);
    run.create_user("untagged");

    let expected: BTreeSet<String> = [first, second].into_iter().collect();
    for selector in [tag_name.as_str(), tag_id.as_str()] {
        let listed = run.ok(run.admin().args(["user", "list", "--tag", selector]));
        assert_eq!(listed["command"], "user.list");
        let ids: BTreeSet<String> = listed["data"]["users"]
            .as_array()
            .unwrap()
            .iter()
            .map(|user| user["userId"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(ids, expected, "{listed}");
    }

    for selector in [run.name("no-such-tag"), Uuid::new_v4().to_string()] {
        let missing = run.err(run.admin().args(["user", "list", "--tag", &selector]));
        assert_eq!(missing["code"], "not_found", "{missing}");
    }
}

struct Recipe {
    example: &'static str,
    filter: &'static str,
}

const TAGS: Recipe = Recipe {
    example: "inspecting.tags",
    filter: r#".data.userTags[] | "\(.tagId) \(.tagName)""#,
};
const AGENT_TAG_ID: Recipe = Recipe {
    example: "inspecting.tags",
    filter: r#".data.userTags[] | select(.tagName == "agent") | .tagId"#,
};
const TAGGED_USERS: Recipe = Recipe {
    example: "inspecting.tagged-users",
    filter: ".data.users[] | {userId, userName}",
};
const KEYS: Recipe = Recipe {
    example: "inspecting.keys",
    filter: r#".data.apiKeys[] | {apiKeyId, apiKeyName, publicKey: .credential.publicKey, expiresAt}"#,
};
const LONG_LIVED_KEYS: Recipe = Recipe {
    example: "inspecting.keys",
    filter: r#".data.apiKeys[] | "\(.userId) \(.apiKeyId)""#,
};
const EXPIRING_KEYS: Recipe = Recipe {
    example: "inspecting.keys",
    filter: r#".data.apiKeys[] | "\(.userId) \(.apiKeyId) \(.expiresAt)""#,
};
const PENDING: Recipe = Recipe {
    example: "inspecting.pending",
    filter: r#".data.items[] | {id, type, status, ageSeconds: (($now | tonumber) - (.createdAt.seconds | tonumber))}"#,
};
const NEXT_CURSOR: Recipe = Recipe {
    example: "inspecting.next-page",
    filter: ".data.nextCursor",
};
const VOTES: Recipe = Recipe {
    example: "inspecting.votes",
    filter: ".data.activity.votes[] | {userId, selection}",
};
const SECRETS: Recipe = Recipe {
    example: "inspecting.secrets",
    filter: r#".data.secrets[] | {name, properties: (.staticProperties | map("\(.key)=\(.value)"))}"#,
};
const SECRET_NAMES: Recipe = Recipe {
    example: "inspecting.secrets",
    filter: ".data.secrets[].name",
};
const POLICIES: Recipe = Recipe {
    example: "inspecting.policies",
    filter: r#".data.policies[] | select((.consensus // "") + (.condition // "") | contains($tag) or contains($user)) | {policyId, policyName, effect}"#,
};
const MINTED_BY: Recipe = Recipe {
    example: "inspecting.minted-by",
    filter: r#".data.items[] | select(any(.intent.createApiKeysIntentV2.apiKeys[]?, .intent.createUsersIntentV4.users[]?.apiKeys[]?; .publicKey == $pk)) | {id, type, status, minted: .createdAt.seconds, voters: [.votes[].userId]}"#,
};
const RECIPES: [&Recipe; 13] = [
    &TAGS,
    &AGENT_TAG_ID,
    &TAGGED_USERS,
    &KEYS,
    &LONG_LIVED_KEYS,
    &EXPIRING_KEYS,
    &PENDING,
    &NEXT_CURSOR,
    &VOTES,
    &SECRETS,
    &SECRET_NAMES,
    &POLICIES,
    &MINTED_BY,
];

fn jq(record: &Value, args: &[&str]) -> String {
    let mut child = Command::new("jq")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("jq must be installed on PATH for this test: {error}"));
    child
        .stdin
        .take()
        .unwrap()
        .write_all(record.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "jq {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn jq_values(record: &Value, args: &[&str]) -> Vec<Value> {
    serde_json::Deserializer::from_str(&jq(record, args))
        .into_iter::<Value>()
        .map(|value| value.unwrap())
        .collect()
}

fn jq_lines(record: &Value, filter: &str, args: &[&str]) -> Vec<String> {
    let mut argv = vec!["-r"];
    argv.extend_from_slice(args);
    argv.push(filter);
    jq(record, &argv).lines().map(str::to_owned).collect()
}

#[test]
#[ignore]
fn inspecting_agents_jq_recipes_answer_live_records() {
    let skill = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("skills/inspecting-agents/SKILL.md"),
    )
    .unwrap();
    for recipe in RECIPES {
        assert!(
            skill.contains(recipe.filter),
            "{} recipe drifted from SKILL.md: {}",
            recipe.example,
            recipe.filter
        );
    }

    let run = Run::new();
    let agent_tag = run.create_tag(AGENT_TAG);
    let human_tag = run.create_tag(HUMAN_TAG);
    let (agent_one_id, agent_one) = run.create_tagged_user("agent-one", AGENT_TAG);

    let (created_two, agent_two_key) = run.create_session_agent("agent-two", "2h");
    let agent_two_public_key = hex::encode(agent_two_key.compressed_public_key());
    let agent_two_name = run.name("agent-two");
    let agent_two_id = created_user_id(&created_two);
    let minted_two_activity = id_of(&created_two);

    run.create_tagged_user("human", HUMAN_TAG);
    let policy_name = run.name("agents-create-tags-with-approval");
    let policy_id = run.create_policy_from_flags(
        &policy_name,
        "allow",
        &allow_once(&agent_tag, &human_tag),
        "activity.type == 'ACTIVITY_TYPE_CREATE_USER_TAG'",
    );
    let signing_suffix = "agents-sign-ssh";
    let signing_id = run.allow_user_signing(
        signing_suffix,
        &agent_one_id,
        SignScope::PrivateKey(&Uuid::new_v4().to_string()),
    );
    let signing_name = run.name(signing_suffix);

    let pending = run.ok(run.as_user(&agent_one).args([
        "user",
        "tag",
        "create",
        "--name",
        &run.name("proposed"),
    ]));
    assert_eq!(pending["status"], "pending", "{pending}");
    let pending_id = id_of(&pending);

    let secret_name = run.name("service/API_TOKEN");
    run.submit(
        run.admin()
            .args([
                "secret",
                "import",
                &secret_name,
                "--property",
                "env=prod",
                "--property",
                "team=payments",
            ])
            .write_stdin("inspected-value"),
        "secret.import",
    );

    let registered_public_key = hex::encode(run.key().compressed_public_key());
    let registered = run.register_api_key(&agent_one_id, "ci-key", &registered_public_key);
    let registered_activity = id_of(&registered);
    let root_user_id = run.ok(run.admin().arg("whoami"))["data"]["userId"]
        .as_str()
        .unwrap()
        .to_owned();

    let tags = run.ok(run.admin().args(["user", "tag", "list"]));
    let listed: BTreeSet<String> = jq_lines(&tags, TAGS.filter, &[]).into_iter().collect();
    assert_eq!(
        listed,
        BTreeSet::from([
            format!("{agent_tag} {AGENT_TAG}"),
            format!("{human_tag} {HUMAN_TAG}"),
        ]),
        "{tags}"
    );
    assert_eq!(
        jq_lines(&tags, AGENT_TAG_ID.filter, &[]),
        [agent_tag.as_str()],
        "{tags}"
    );

    let users = run.ok(run.admin().args(["user", "list", "--tag", AGENT_TAG]));
    let tagged: BTreeSet<(String, String)> = jq_values(&users, &[TAGGED_USERS.filter])
        .into_iter()
        .map(|user| {
            (
                user["userId"].as_str().unwrap().to_owned(),
                user["userName"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        tagged,
        BTreeSet::from([
            (agent_one_id.clone(), run.name("agent-one")),
            (agent_two_id.clone(), agent_two_name.clone()),
        ]),
        "{users}"
    );

    let keys = run.ok(run
        .admin()
        .args(["api-key", "list", "--user-id", &agent_two_id]));
    let summarized = jq_values(&keys, &[KEYS.filter]);
    assert_eq!(summarized.len(), 2, "{keys}");
    let expiring = summarized
        .iter()
        .find(|key| key["publicKey"] == agent_two_public_key)
        .unwrap_or_else(|| panic!("expiring key missing: {keys}"));
    assert!(expiring["expiresAt"].is_string(), "{expiring}");
    let anchor = summarized
        .iter()
        .find(|key| key["apiKeyName"] == format!("{agent_two_name}-anchor"))
        .unwrap_or_else(|| panic!("anchor key missing: {keys}"));
    assert_eq!(anchor["expiresAt"], Value::Null, "{anchor}");
    let anchor_id = anchor["apiKeyId"].as_str().unwrap();
    let expiring_id = expiring["apiKeyId"].as_str().unwrap();

    let long_lived = run.ok(run
        .admin()
        .args(["api-key", "list", "--all-users", "--long-lived"]));
    let long_lived = jq_lines(&long_lived, LONG_LIVED_KEYS.filter, &[]);
    assert_eq!(
        long_lived
            .iter()
            .filter(|line| line.starts_with(&agent_two_id))
            .collect::<Vec<_>>(),
        [&format!("{agent_two_id} {anchor_id}")],
        "{long_lived:?}"
    );
    assert!(
        long_lived
            .iter()
            .any(|line| line.starts_with(&agent_one_id)),
        "{long_lived:?}"
    );
    let expiring_soon =
        run.ok(run
            .admin()
            .args(["api-key", "list", "--all-users", "--expiring-within", "24h"]));
    assert_eq!(
        jq_lines(&expiring_soon, EXPIRING_KEYS.filter, &[]),
        [format!(
            "{agent_two_id} {expiring_id} {}",
            expiring["expiresAt"].as_str().unwrap()
        )],
        "{expiring_soon}"
    );

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    let page = run.ok(run
        .admin()
        .args(["activity", "list", "--status", "pending", "--limit", "50"]));
    let pending_items = jq_values(&page, &["--arg", "now", &now, PENDING.filter]);
    assert_eq!(pending_items.len(), 1, "{page}");
    assert_eq!(pending_items[0]["id"], pending_id, "{page}");
    assert_eq!(
        pending_items[0]["type"], "ACTIVITY_TYPE_CREATE_USER_TAG",
        "{page}"
    );
    assert_eq!(
        pending_items[0]["status"], "ACTIVITY_STATUS_CONSENSUS_NEEDED",
        "{page}"
    );
    let age = pending_items[0]["ageSeconds"].as_i64().unwrap();
    assert!((0..3600).contains(&age), "{}", pending_items[0]);
    assert_eq!(jq_lines(&page, NEXT_CURSOR.filter, &[]), ["null"], "{page}");
    let first = run.ok(run
        .admin()
        .args(["activity", "list", "--status", "pending", "--limit", "1"]));
    let next = jq_lines(&first, NEXT_CURSOR.filter, &[]);
    assert_eq!(next, [pending_id.as_str()], "{first}");
    let rest = run.ok(run.admin().args([
        "activity", "list", "--status", "pending", "--limit", "1", "--cursor", &next[0],
    ]));
    assert_eq!(
        rest["data"],
        json!({"items": [], "nextCursor": null}),
        "{rest}"
    );

    let got = run.ok(run.admin().args(["activity", "get", &pending_id]));
    assert_eq!(
        jq_values(&got, &[VOTES.filter]),
        [json!({"userId": agent_one_id, "selection": "VOTE_SELECTION_APPROVED"})],
        "{got}"
    );

    let secrets = run.ok(run
        .admin()
        .args(["secret", "list", "--property", "env=prod"]));
    assert_eq!(
        jq_values(&secrets, &[SECRETS.filter]),
        [json!({"name": secret_name, "properties": ["env=prod", "team=payments"]})],
        "{secrets}"
    );
    assert_eq!(
        jq_lines(&secrets, NEXT_CURSOR.filter, &[]),
        ["null"],
        "{secrets}"
    );
    let staging = run.ok(run
        .admin()
        .args(["secret", "list", "--property", "env=staging"]));
    assert_eq!(
        jq_values(&staging, &[SECRETS.filter]),
        [] as [Value; 0],
        "{staging}"
    );
    let prefixed = run.ok(run.admin().args([
        "secret",
        "list",
        "--name-prefix",
        &run.name("service/"),
        "--property",
        "env=prod",
    ]));
    assert_eq!(
        jq_lines(&prefixed, SECRET_NAMES.filter, &[]),
        [secret_name.as_str()],
        "{prefixed}"
    );

    let policies = run.ok(run.admin().args(["policy", "list"]));
    let mentioning = |tag: &str, user: &str| {
        let mut found = jq_values(
            &policies,
            &["--arg", "tag", tag, "--arg", "user", user, POLICIES.filter],
        );
        found.sort_by_key(|policy| policy["policyName"].to_string());
        found
    };
    let tag_policy =
        json!({"policyId": policy_id, "policyName": policy_name, "effect": "EFFECT_ALLOW"});
    let signing_policy =
        json!({"policyId": signing_id, "policyName": signing_name, "effect": "EFFECT_ALLOW"});
    assert_eq!(
        mentioning(&agent_tag, &agent_one_id),
        [tag_policy.clone(), signing_policy.clone()],
        "{policies}"
    );
    assert_eq!(
        mentioning(&agent_tag, &agent_two_id),
        [tag_policy],
        "{policies}"
    );
    assert_eq!(
        mentioning(&agent_two_id, &agent_one_id),
        [signing_policy],
        "{policies}"
    );
    assert_eq!(
        mentioning(&agent_two_id, &agent_two_id),
        [] as [Value; 0],
        "{policies}"
    );

    let mint_types = [
        "--type",
        "ACTIVITY_TYPE_CREATE_API_KEYS_V2",
        "--type",
        "ACTIVITY_TYPE_CREATE_USERS_V4",
    ];
    let first = run.ok(run
        .admin()
        .args(["activity", "list", "--limit", "2"])
        .args(mint_types));
    assert_eq!(
        jq_values(
            &first,
            &["--arg", "pk", &agent_two_public_key, MINTED_BY.filter]
        ),
        [] as [Value; 0],
        "first page alone must not attribute the key: {first}"
    );
    let mut pages = vec![first];
    loop {
        let cursor = jq_lines(pages.last().unwrap(), NEXT_CURSOR.filter, &[]);
        let [cursor] = cursor.as_slice() else {
            panic!("nextCursor is not one line: {cursor:?}");
        };
        if cursor == "null" {
            break;
        }
        pages.push(
            run.ok(run
                .admin()
                .args(["activity", "list", "--limit", "2", "--cursor", cursor])
                .args(mint_types)),
        );
    }
    assert!(pages.len() >= 3, "{} pages", pages.len());
    let items: Vec<&Value> = pages
        .iter()
        .flat_map(|page| page["data"]["items"].as_array().unwrap())
        .collect();
    let ids: Vec<&str> = items
        .iter()
        .map(|item| item["id"].as_str().unwrap())
        .collect();
    let unique: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(
        unique.len(),
        ids.len(),
        "pages repeated an activity: {ids:?}"
    );
    assert!(unique.contains(minted_two_activity.as_str()), "{ids:?}");
    assert!(unique.contains(registered_activity.as_str()), "{ids:?}");
    assert!(!unique.contains(pending_id.as_str()), "{ids:?}");
    for item in &items {
        assert!(
            mint_types.contains(&item["type"].as_str().unwrap()),
            "{item}"
        );
    }

    let minted = |public_key: &str| -> Vec<Value> {
        pages
            .iter()
            .flat_map(|page| jq_values(page, &["--arg", "pk", public_key, MINTED_BY.filter]))
            .collect()
    };
    let by_user_create = minted(&agent_two_public_key);
    assert_eq!(
        by_user_create,
        [json!({
            "id": minted_two_activity,
            "type": "ACTIVITY_TYPE_CREATE_USERS_V4",
            "status": "ACTIVITY_STATUS_COMPLETED",
            "minted": created_two["data"]["activity"]["createdAt"]["seconds"],
            "voters": [root_user_id],
        })],
        "{by_user_create:?}"
    );
    let by_register = minted(&registered_public_key);
    assert_eq!(
        by_register,
        [json!({
            "id": registered_activity,
            "type": "ACTIVITY_TYPE_CREATE_API_KEYS_V2",
            "status": "ACTIVITY_STATUS_COMPLETED",
            "minted": registered["data"]["activity"]["createdAt"]["seconds"],
            "voters": [root_user_id],
        })],
        "{by_register:?}"
    );
    assert_eq!(
        minted(&hex::encode(run.key().compressed_public_key())),
        [] as [Value; 0]
    );
}
