//! Per-test runner; each [`Run`] owns an isolated Turnkey sub-organization.
mod readiness;
mod skip;

use std::{
    cell::RefCell,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    process, thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use assert_cmd::Command;
use serde_json::{Value, json};
pub(crate) use skip::skip;
use tempfile::TempDir;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use uuid::Uuid;

use crate::{config::E2eConfig, policy_helpers::user_consensus};

const SCRUBBED: [&str; 10] = [
    "HOME",
    "TK_PROFILE",
    "TK_NON_INTERACTIVE",
    "TK_GPG_PROGRAM",
    "TK_SSH_KEYGEN_PROGRAM",
    "TURNKEY_ORGANIZATION_ID",
    "TURNKEY_API_PUBLIC_KEY",
    "TURNKEY_API_PRIVATE_KEY",
    "TURNKEY_API_BASE_URL",
    "RUST_LOG",
];
const UNROUTABLE: &str = "http://127.0.0.1:9";
pub(crate) const AGENT_TAG: &str = "agent";
pub(crate) const HUMAN_TAG: &str = "human-approver";
const ATTEMPTS: u32 = 5;
const RATE_LIMIT_BACKOFF: Duration = Duration::from_secs(10);
const CHILD_READINESS_TIMEOUT: Duration = Duration::from_secs(30);
const CHILD_READINESS_POLL_INTERVAL: Duration = Duration::from_millis(20);

fn backoff(attempt: u32) {
    thread::sleep(Duration::from_secs(1u64 << (attempt - 1)));
}
fn rate_limited(record: &Value) -> bool {
    record["httpStatus"].as_u64() == Some(429)
}
fn activity_failed(record: &Value) -> bool {
    record["reason"] == "command_error"
        && record["code"] == "api_error"
        && record["details"]["activity"]["status"] == "ACTIVITY_STATUS_FAILED"
}
fn transient(record: &Value) -> bool {
    record["reason"] == "command_error"
        && (record["code"] == "network_error"
            || (record["code"] == "api_error"
                && record["httpStatus"]
                    .as_u64()
                    .is_some_and(|status| status == 429 || status >= 500)))
}

pub(crate) struct Run {
    pub(crate) home: TempDir,
    /// Parent organization and its admin credential.
    pub(crate) config: E2eConfig,
    marker: String,
    pub(crate) secrets: RefCell<Vec<String>>,
    sub_org: Option<String>,
}

fn now_ms() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string()
}

pub(crate) struct AdminLogin {
    pub(crate) name: String,
    pub(crate) key_file: PathBuf,
    pub(crate) record: Value,
}

pub(crate) fn bare_cli(home: &Path) -> Command {
    cli_at(Path::new(env!("CARGO_BIN_EXE_tk")), home)
}

pub(crate) fn cli_at(program: &Path, home: &Path) -> Command {
    let mut cmd = Command::new(program);
    for name in SCRUBBED {
        cmd.env_remove(name);
    }
    cmd.env("HOME", home);
    cmd
}

pub(crate) fn result<'v>(record: &'v Value, key: &str) -> &'v Value {
    &record["data"]["activity"]["result"][key]
}

// The API has answered an unknown credential with both 401 and 403.
pub(crate) fn assert_unauthenticated(record: &Value) {
    assert_eq!(record["code"], "unauthorized", "{record}");
    assert!(
        matches!(record["httpStatus"].as_u64(), Some(401 | 403)),
        "{record}"
    );
}

pub(crate) fn created_user_id(record: &Value) -> String {
    result(record, "createUsersResult")["userIds"][0]
        .as_str()
        .unwrap()
        .to_string()
}

pub(crate) fn id_of(record: &Value) -> String {
    record["activity"]["id"].as_str().unwrap().to_string()
}

pub(crate) fn one_api_key(run: &Run, label: &str) -> Value {
    let key = run.key();
    json!([{
        "apiKeyName": format!("{label}-key"),
        "publicKey": hex::encode(key.compressed_public_key()),
        "curveType": "API_KEY_CURVE_P256",
    }])
}

pub(crate) fn signed_commit(message: &str) -> [&str; 6] {
    ["commit", "-S", "--quiet", "--allow-empty", "-m", message]
}

pub(crate) fn user_params(name: &str, api_keys: Value) -> String {
    json!({"users": [{
        "userName": name,
        "apiKeys": api_keys,
        "authenticators": [],
        "oauthProviders": [],
        "userTags": [],
    }]})
    .to_string()
}

impl Run {
    /// Creates an isolated sub-organization for the test.
    pub(crate) fn new() -> Self {
        let config = E2eConfig::load();
        let secrets = RefCell::new(vec![config.private_key.0.clone()]);
        let mut run = Self {
            home: TempDir::new().unwrap(),
            config,
            marker: format!("tk-e2e-{}", Uuid::new_v4()),
            secrets,
            sub_org: None,
        };
        let parameters = json!({
            "subOrganizationName": run.marker,
            "rootUsers": [{
                "userName": run.name("root"),
                "apiKeys": [{
                    "apiKeyName": run.name("root-key"),
                    "publicKey": run.config.public_key,
                    "curveType": "API_KEY_CURVE_P256",
                }],
                "authenticators": [],
                "oauthProviders": [],
            }],
            "rootQuorumThreshold": 1,
        });
        let created = run.submit_activity_as(
            &|| run.parent(),
            "/public/v1/submit/create_sub_organization",
            "ACTIVITY_TYPE_CREATE_SUB_ORGANIZATION_V7",
            &run.config.organization_id.to_string(),
            &parameters,
        );
        let sub_org = result(&created, "createSubOrganizationResultV7")["subOrganizationId"]
            .as_str()
            .unwrap_or_else(|| panic!("sub-organization id missing: {created}"))
            .to_string();
        run.sub_org = Some(sub_org);
        run
    }

    pub(crate) fn name(&self, suffix: &str) -> String {
        format!("{}-{suffix}", self.marker)
    }

    /// The sub-organization used by this test.
    pub(crate) fn org(&self) -> &str {
        self.sub_org
            .as_deref()
            .expect("sub-organization is created before any test command runs")
    }

    pub(crate) fn registry_path(&self) -> PathBuf {
        self.home.path().join(".config/turnkey/tk.config.toml")
    }

    pub(crate) fn home(&self) -> &Path {
        self.home.path()
    }

    /// Returns the pending-export state path for a credential and secret.
    pub(crate) fn export_state(&self, api_public_key: &str, secret_id: &str) -> PathBuf {
        self.home()
            .join(".config/turnkey/tk/secrets/pending")
            .join(self.org())
            .join(api_public_key)
            .join(format!("{secret_id}.json"))
    }

    /// Returns the admin credential's public key for state paths.
    pub(crate) fn admin_public_key(&self) -> &str {
        &self.config.public_key
    }

    fn cli_at(&self, base: &str) -> Command {
        let mut cmd = bare_cli(self.home.path());
        cmd.arg("--message-format=json")
            .arg("--api-base-url")
            .arg(base);
        cmd
    }

    pub(crate) fn cli(&self) -> Command {
        self.cli_at(&self.config.api_base_url)
    }

    fn with_bundle(mut cmd: Command, org: &str, public: &str, private: &str) -> Command {
        cmd.env("TURNKEY_ORGANIZATION_ID", org)
            .env("TURNKEY_API_PUBLIC_KEY", public)
            .env("TURNKEY_API_PRIVATE_KEY", private);
        cmd
    }

    /// Admin key scoped to the parent organization.
    fn parent(&self) -> Command {
        Self::with_bundle(
            self.cli(),
            &self.config.organization_id.to_string(),
            &self.config.public_key,
            &self.config.private_key.0,
        )
    }

    fn admin_at(&self, base: &str) -> Command {
        Self::with_bundle(
            self.cli_at(base),
            self.org(),
            &self.config.public_key,
            &self.config.private_key.0,
        )
    }

    /// Admin key scoped to this run's sub-organization.
    pub(crate) fn admin(&self) -> Command {
        self.admin_at(&self.config.api_base_url)
    }

    /// Root bundle pointed at an unroutable host for preflight tests.
    pub(crate) fn admin_offline(&self) -> Command {
        self.admin_at(UNROUTABLE)
    }

    pub(crate) fn generate_key(&self, path: &Path) -> Value {
        let record = self.ok(self
            .cli()
            .args(["api-key", "generate", "--output"])
            .arg(path));
        let stored: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        self.secrets
            .borrow_mut()
            .push(stored["private_key"].as_str().unwrap().to_string());
        record
    }

    pub(crate) fn key(&self) -> TurnkeyP256ApiKey {
        let key = TurnkeyP256ApiKey::generate();
        self.secrets
            .borrow_mut()
            .push(hex::encode(key.private_key()));
        key
    }

    /// Bundle for another sub-organization user.
    pub(crate) fn as_user(&self, key: &TurnkeyP256ApiKey) -> Command {
        Self::with_bundle(
            self.cli(),
            self.org(),
            &hex::encode(key.compressed_public_key()),
            &hex::encode(key.private_key()),
        )
    }

    pub(crate) fn redact(&self, bytes: &[u8]) -> String {
        let mut text = String::from_utf8_lossy(bytes).into_owned();
        for secret in self.secrets.borrow().iter() {
            text = text.replace(secret, "<redacted>");
        }
        text
    }

    /// Runs the binary once, redacting tracked secrets from both streams.
    fn output(&self, cmd: &mut Command) -> (Option<i32>, String, String) {
        let output = cmd.output().unwrap();
        let stdout = self.redact(&output.stdout);
        let stderr = self.redact(&output.stderr);
        for (stream, raw) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
            assert!(
                self.redact(raw) == String::from_utf8_lossy(raw),
                "private key leaked to {stream}\nstdout: {stdout}\nstderr: {stderr}"
            );
        }
        (output.status.code(), stdout, stderr)
    }

    fn run(&self, cmd: &mut Command) -> (Option<i32>, Value, String) {
        let (code, stdout, stderr) = self.output(cmd);
        assert!(stderr.is_empty(), "stderr not empty: {stderr}");
        let record = serde_json::from_str(&stdout)
            .unwrap_or_else(|error| panic!("stdout is not one JSON record ({error}): {stdout}"));
        (code, record, stdout)
    }

    /// Runs the binary with backoff for transient failures.
    fn attempt(&self, cmd: &mut Command) -> (Option<i32>, Value, String) {
        for attempt in 1..ATTEMPTS {
            let (exit, record, stdout) = self.run(cmd);
            if !transient(&record) {
                return (exit, record, stdout);
            }
            eprintln!("transient failure, attempt {attempt}/{ATTEMPTS}: {stdout}");
            if rate_limited(&record) {
                thread::sleep(RATE_LIMIT_BACKOFF * (1 << (attempt - 1)));
            } else {
                backoff(attempt);
            }
        }
        self.run(cmd)
    }

    fn record(&self, cmd: &mut Command, code: i32) -> Value {
        let (exit, record, stdout) = self.attempt(cmd);
        assert_eq!(exit, Some(code), "unexpected exit code\nstdout: {stdout}");
        record
    }

    pub(crate) fn ok(&self, cmd: &mut Command) -> Value {
        self.record(cmd, 0)
    }

    pub(crate) fn err(&self, cmd: &mut Command) -> Value {
        self.record(cmd, 1)
    }

    pub(crate) fn ok_created_or_reregistered(
        &self,
        cmd: &mut Command,
        created: &str,
        registered: &str,
    ) -> Value {
        let record = self.ok(cmd);
        let reason = record["reason"].as_str();
        assert!(
            reason == Some(created) || reason == Some(registered),
            "{record}"
        );
        record
    }

    fn human_attempt(&self, cmd: &mut Command) -> (Option<i32>, String, String) {
        for attempt in 1..ATTEMPTS {
            let (code, stdout, stderr) = self.output(cmd);
            if code == Some(0) && stderr.is_empty() {
                return (code, stdout, stderr);
            }
            eprintln!(
                "transient failure, attempt {attempt}/{ATTEMPTS}\nstdout: {stdout}\nstderr: {stderr}"
            );
            backoff(attempt);
        }
        self.output(cmd)
    }

    /// Runs a human-mode command and returns its raw stdout, retrying
    /// non-zero exits and stderr output.
    pub(crate) fn human_stdout(&self, cmd: &mut Command) -> String {
        let (code, stdout, stderr) = self.human_attempt(cmd);
        assert_eq!(
            code,
            Some(0),
            "unexpected exit code\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert!(stderr.is_empty(), "stderr not empty: {stderr}");
        stdout
    }

    pub(crate) fn wait(&self, id: &str) -> Value {
        let record =
            self.ok(self
                .admin()
                .args(["activity", "wait", "--id", id, "--timeout", "90"]));
        assert_eq!(record["command"], "activity.wait");
        assert_eq!(record["status"], "completed", "{record}");
        assert_eq!(record["activity"]["id"], id);
        record
    }

    pub(crate) fn approve(&self, approver: &TurnkeyP256ApiKey, id: &str) -> Value {
        self.ok(self
            .as_user(approver)
            .args(["activity", "approve", "--id", id]))
    }

    pub(crate) fn reject(&self, approver: &TurnkeyP256ApiKey, id: &str) -> Value {
        self.ok(self
            .as_user(approver)
            .args(["activity", "reject", "--id", id]))
    }

    pub(crate) fn approve_and_wait(&self, approver: &TurnkeyP256ApiKey, activity: &str) -> Value {
        self.approve(approver, activity);
        self.wait(activity)
    }

    /// Submits once and waits for pending activities.
    fn submit_once(
        &self,
        cmd: &mut Command,
        command: &str,
        waiter: &dyn Fn() -> Command,
    ) -> Result<Value, (Value, String)> {
        let (exit, record, stdout) = self.attempt(cmd);
        if exit != Some(0) {
            return Err((record, stdout));
        }
        assert_eq!(record["command"], command, "{record}");
        match record["status"].as_str() {
            Some("completed") => Ok(record),
            Some("pending") => {
                let id = id_of(&record);
                let (exit, waited, stdout) = self.attempt(waiter().args([
                    "activity",
                    "wait",
                    "--id",
                    &id,
                    "--timeout",
                    "90",
                ]));
                if exit != Some(0) {
                    return Err((waited, stdout));
                }
                assert_eq!(waited["status"], "completed", "{waited}");
                assert_eq!(waited["activity"]["id"], id);
                Ok(waited)
            }
            other => panic!("unexpected submission status {other:?}: {record}"),
        }
    }

    /// Runs `secret export` until it delivers the value, handling approval
    /// and transient activity failures.
    pub(crate) fn export(&self, cmd: &mut Command) -> Value {
        for attempt in 1..=ATTEMPTS {
            let (exit, record, stdout) = self.attempt(cmd);
            if exit != Some(0) {
                if activity_failed(&record) && attempt < ATTEMPTS {
                    eprintln!(
                        "secret.export failed server-side, attempt {attempt}/{ATTEMPTS}: {record}"
                    );
                    backoff(attempt);
                    continue;
                }
                panic!("secret.export failed\nstdout: {stdout}");
            }
            assert_eq!(record["command"], "secret.export", "{record}");
            match record["status"].as_str() {
                Some("completed") => return record,
                Some("pending") => {
                    self.wait(&id_of(&record));
                }
                other => panic!("unexpected secret.export status {other:?}: {record}"),
            }
        }
        panic!("secret.export did not deliver within {ATTEMPTS} attempts")
    }

    /// Submits a raw activity request as `bundle` and returns its completed
    /// record. The timestamp lives in the body, so the body is rebuilt on
    /// every attempt: the API folds a byte-identical request back into the
    /// activity it already produced, and resending one after a server-side
    /// failure would keep returning that same failed activity.
    fn submit_activity_as(
        &self,
        bundle: &dyn Fn() -> Command,
        endpoint: &str,
        activity_type: &str,
        organization_id: &str,
        parameters: &Value,
    ) -> Value {
        for attempt in 1..=ATTEMPTS {
            let body = json!({
                "type": activity_type,
                "timestampMs": now_ms(),
                "organizationId": organization_id,
                "parameters": parameters,
            })
            .to_string();
            let mut cmd = bundle();
            cmd.args(["request", "--path", endpoint, "--body", &body]);
            match self.submit_once(&mut cmd, "request", bundle) {
                Ok(record) => return record,
                Err((record, _)) if activity_failed(&record) && attempt < ATTEMPTS => {
                    eprintln!(
                        "{activity_type} failed server-side, attempt {attempt}/{ATTEMPTS}: {record}"
                    );
                    backoff(attempt);
                }
                Err((_, stdout)) => panic!("{activity_type} failed\nstdout: {stdout}"),
            }
        }
        panic!("{activity_type} did not complete within {ATTEMPTS} attempts")
    }

    /// Submits a raw activity request as the sub-organization root.
    pub(crate) fn submit_activity(
        &self,
        endpoint: &str,
        activity_type: &str,
        parameters: &Value,
    ) -> Value {
        self.submit_activity_as(
            &|| self.admin(),
            endpoint,
            activity_type,
            self.org(),
            parameters,
        )
    }

    fn submit_as(&self, cmd: &mut Command, command: &str, waiter: &dyn Fn() -> Command) -> Value {
        for attempt in 1..=ATTEMPTS {
            match self.submit_once(cmd, command, waiter) {
                Ok(record) => return record,
                Err((record, _)) if activity_failed(&record) && attempt < ATTEMPTS => {
                    eprintln!(
                        "{command} failed server-side, attempt {attempt}/{ATTEMPTS}: {record}"
                    );
                    backoff(attempt);
                }
                Err((_, stdout)) => panic!("{command} failed\nstdout: {stdout}"),
            }
        }
        panic!("{command} did not complete within {ATTEMPTS} attempts")
    }
    /// Submits `command` as the sub-organization root and returns its
    /// completed activity record, retrying transient failures.
    pub(crate) fn submit(&self, cmd: &mut Command, command: &str) -> Value {
        self.submit_as(cmd, command, &|| self.admin())
    }
    /// Imports `value` as a secret named `name` and returns its id.
    pub(crate) fn import_secret(&self, name: &str, value: &str) -> String {
        let imported = self.submit(
            self.admin()
                .args(["secret", "import", "--name", name])
                .write_stdin(value),
            "secret.import",
        );
        imported["data"]["secretId"].as_str().unwrap().to_string()
    }
    /// Creates a policy from its `policy create` parameters and returns the
    /// completed `policy.create` record.
    pub(crate) fn create_policy(&self, params: Value) -> Value {
        self.submit(
            self.admin()
                .args(["policy", "create", "--input-json", &params.to_string()]),
            "policy.create",
        )
    }
    /// Creates a user with a fresh API key and returns the completed
    /// `user.create` record with that key.
    pub(crate) fn create_user_activity(&self, label: &str) -> (Value, TurnkeyP256ApiKey) {
        let name = self.name(label);
        let key = self.key();
        let api_keys = json!([{
            "apiKeyName": format!("{name}-key"),
            "publicKey": hex::encode(key.compressed_public_key()),
            "curveType": "API_KEY_CURVE_P256",
        }]);
        let created = self.submit(
            self.admin().args([
                "user",
                "create",
                "--input-json",
                &user_params(&name, api_keys),
            ]),
            "user.create",
        );
        (created, key)
    }
    /// Creates a user with a fresh API key.
    pub(crate) fn create_user(&self, label: &str) -> (String, TurnkeyP256ApiKey) {
        let (created, key) = self.create_user_activity(label);
        (created_user_id(&created), key)
    }
    pub(crate) fn create_provisioner(&self) -> TurnkeyP256ApiKey {
        let (provisioner_id, provisioner_key) = self.create_user("provisioner");
        self.create_policy(json!({
            "policyName": self.name("provisioners-mint"),
            "effect": "EFFECT_ALLOW",
            "consensus": user_consensus(&provisioner_id),
            "condition": "activity.type == 'ACTIVITY_TYPE_CREATE_API_KEYS_V2'",
            "notes": ""
        }));
        provisioner_key
    }
    pub(crate) fn provision(
        &self,
        provisioner: &TurnkeyP256ApiKey,
        user_id: &str,
        public_key: &str,
    ) -> Command {
        let mut cmd = self.as_user(provisioner);
        cmd.args([
            "session",
            "provision",
            "--user-id",
            user_id,
            "--public-key",
            public_key,
            "--expires-in",
            "2h",
        ]);
        cmd
    }
    pub(crate) fn write_key_file(&self, name: &str, public: &str, private: &str) -> PathBuf {
        let path = self.home.path().join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(
            json!({
                "public_key": public,
                "private_key": private,
                "curve": "p256",
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        path
    }

    pub(crate) fn login_as(&self, name: &str, key: &TurnkeyP256ApiKey) -> PathBuf {
        let key_file = self.write_key_file(
            &format!("{name}.json"),
            &hex::encode(key.compressed_public_key()),
            &hex::encode(key.private_key()),
        );
        self.ok(self
            .cli()
            .args([
                "profile",
                "create",
                "--profile-name",
                name,
                "--organization-id",
                self.org(),
                "--api-key-file",
            ])
            .arg(&key_file));
        self.ok(self.cli().args(["login", "--profile-name", name]));
        key_file
    }

    pub(crate) fn create_policy_from_flags(
        &self,
        name: &str,
        effect: &str,
        consensus: &str,
        condition: &str,
    ) -> String {
        let created = self.submit(
            self.admin().args([
                "policy",
                "create",
                "--name",
                name,
                "--effect",
                effect,
                "--consensus",
                consensus,
                "--condition",
                condition,
            ]),
            "policy.create",
        );
        result(&created, "createPolicyResult")["policyId"]
            .as_str()
            .unwrap()
            .to_string()
    }

    pub(crate) fn import_secret_from_file(&self, name: &str, level: &str, value: &str) -> String {
        let file = self
            .home()
            .join(format!("{}.txt", name.rsplit('/').next().unwrap()));
        fs::write(&file, value).unwrap();
        let imported = self.submit(
            self.admin()
                .args([
                    "secret",
                    "import",
                    "--name",
                    name,
                    "--property",
                    &format!("consensus={level}"),
                    "--from-file",
                ])
                .arg(&file),
            "secret.import",
        );
        assert_eq!(imported["data"]["name"], name, "{imported}");
        imported["data"]["secretId"].as_str().unwrap().to_string()
    }

    pub(crate) fn git(
        git: &Path,
        repo: &Path,
        configure: impl FnOnce(&mut process::Command),
        args: &[&str],
    ) -> process::Output {
        let mut command = process::Command::new(git);
        configure(&mut command);
        command
            .current_dir(repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("XDG_CONFIG_HOME")
            .args([
                "-c",
                "user.name=tk e2e",
                "-c",
                "user.email=tk-e2e@example.com",
            ])
            .args(args)
            .output()
            .expect("git should run")
    }

    pub(crate) fn git_ok(
        &self,
        git: &Path,
        repo: &Path,
        configure: impl FnOnce(&mut process::Command),
        args: &[&str],
    ) -> process::Output {
        let output = Self::git(git, repo, configure, args);
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            self.redact(&output.stderr)
        );
        output
    }

    pub(crate) fn register_api_key(&self, user_id: &str, name: &str, public_key: &str) -> Value {
        self.submit(
            self.admin().args([
                "api-key",
                "register",
                "--input-json",
                &json!({
                    "userId": user_id,
                    "apiKeys": [{
                        "apiKeyName": name,
                        "publicKey": public_key,
                        "curveType": "API_KEY_CURVE_P256",
                    }],
                })
                .to_string(),
            ]),
            "api-key.register",
        )
    }

    pub(crate) fn create_tag(&self, name: &str) -> String {
        let tagged = self.submit(
            self.admin().args(["user", "tag", "create", "--name", name]),
            "user.tag.create",
        );
        result(&tagged, "createUserTagResult")["userTagId"]
            .as_str()
            .unwrap()
            .to_string()
    }

    pub(crate) fn create_tagged_user(&self, label: &str, tag: &str) -> (String, TurnkeyP256ApiKey) {
        let key = self.key();
        let created = self.submit(
            self.admin().args([
                "user",
                "create",
                "--user-name",
                &self.name(label),
                "--tag-name",
                tag,
                "--public-key",
                &hex::encode(key.compressed_public_key()),
            ]),
            "user.create",
        );
        (created_user_id(&created), key)
    }

    pub(crate) fn create_agent(&self) -> (String, String, TurnkeyP256ApiKey) {
        let tag_id = self.create_tag(AGENT_TAG);
        let (user_id, key) = self.create_tagged_user("agent", AGENT_TAG);
        (tag_id, user_id, key)
    }

    pub(crate) fn api_key_id(&self, user_id: &str, public_key: &str) -> String {
        let listed = self.ok(self.admin().args(["api-key", "list", "--user-id", user_id]));
        listed["data"]["apiKeys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|key| key["credential"]["publicKey"] == public_key)
            .unwrap_or_else(|| panic!("api key {public_key} missing: {listed}"))["apiKeyId"]
            .as_str()
            .unwrap()
            .to_string()
    }

    pub(crate) fn inherit_environment(&self, bundle: Command, command: &mut process::Command) {
        for (name, value) in bundle.get_envs() {
            match value {
                Some(value) => command.env(name, value),
                None => command.env_remove(name),
            };
        }
        command.env("TURNKEY_API_BASE_URL", &self.config.api_base_url);
    }

    pub(crate) fn err_unauthorized(&self, cmd: &mut Command) -> Value {
        let denied = self.err(cmd);
        assert_eq!(denied["code"], "unauthorized", "{denied}");
        assert_eq!(denied["httpStatus"], 403, "{denied}");
        denied
    }

    pub(crate) fn assert_api_key_register_denied(&self, cmd: &mut Command, user_id: &str) {
        let escape = json!({
            "userId": user_id,
            "apiKeys": [{
                "apiKeyName": "escape",
                "publicKey": hex::encode(self.key().compressed_public_key()),
                "curveType": "API_KEY_CURVE_P256",
            }],
        });
        self.err_unauthorized(cmd.args([
            "api-key",
            "register",
            "--input-json",
            &escape.to_string(),
        ]));
    }

    pub(crate) fn create_session_agent(
        &self,
        label: &str,
        expires_in: &str,
    ) -> (Value, TurnkeyP256ApiKey) {
        let key = self.key();
        let created = self.submit(
            self.admin().args([
                "user",
                "create",
                "--user-name",
                &self.name(label),
                "--tag-name",
                AGENT_TAG,
                "--public-key",
                &hex::encode(key.compressed_public_key()),
                "--expires-in",
                expires_in,
                "--anchor-key",
            ]),
            "user.create",
        );
        (created, key)
    }

    /// Saves the admin key as a profile named after this run and logs in.
    pub(crate) fn login_admin(&self) -> AdminLogin {
        let name = self.name("admin");
        let key_file = self.write_key_file(
            "admin-key.json",
            &self.config.public_key,
            &self.config.private_key.0,
        );
        self.ok(self
            .cli()
            .args([
                "profile",
                "create",
                "--profile-name",
                &name,
                "--organization-id",
                self.org(),
                "--api-key-file",
            ])
            .arg(&key_file));
        let record = self.ok(self.cli().args(["login", "--profile-name", &name]));
        AdminLogin {
            name,
            key_file,
            record,
        }
    }

    // Deletes the sub-organization, re-submitting server-side failures.
    fn delete_sub_organization(&self, sub_org: &str) {
        self.submit_activity_as(
            &|| self.admin(),
            "/public/v1/submit/delete_sub_organization",
            "ACTIVITY_TYPE_DELETE_SUB_ORGANIZATION",
            sub_org,
            &json!({"deleteWithoutExport": true}),
        );
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        let Some(sub_org) = self.sub_org.clone() else {
            return;
        };
        let deleted = catch_unwind(AssertUnwindSafe(|| {
            self.delete_sub_organization(&sub_org);
        }));
        if let Err(panic) = deleted {
            let message = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(ToString::to_string))
                .unwrap_or_else(|| "non-string panic".to_string());
            let message = self.redact(message.as_bytes());
            eprintln!("cleanup failed: {message}");
            assert!(
                thread::panicking(),
                "sub-organization {sub_org} ({}) may be leaked in organization {}:\n{message}",
                self.marker,
                self.config.organization_id
            );
        }
    }
}
