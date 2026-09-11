//! Per-test runner. Every [`Run`] is its own Turnkey sub-organization:
//! `new` creates it with the admin credential from `.env.test` and makes that
//! same credential the sub-organization's root, every command the test runs
//! is signed by it against the sub-organization, and dropping the `Run`
//! deletes the sub-organization together with everything the test created.
//! Tests therefore never see each other's users, policies, wallets, or
//! activity history, and run in parallel.
use crate::config::E2eConfig;
use assert_cmd::Command;
use serde_json::{Value, json};
use std::cell::RefCell;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;
use uuid::Uuid;

const SCRUBBED: [&str; 11] = [
    "HOME",
    "TK_CONFIG",
    "TK_PROFILE",
    "TK_NON_INTERACTIVE",
    "TURNKEY_TK_CONFIG_PATH",
    "TURNKEY_ORGANIZATION_ID",
    "TURNKEY_API_PUBLIC_KEY",
    "TURNKEY_API_PRIVATE_KEY",
    "TURNKEY_PRIVATE_KEY_ID",
    "TURNKEY_API_BASE_URL",
    "RUST_LOG",
];
pub(crate) const UNROUTABLE: &str = "http://127.0.0.1:9";
const ATTEMPTS: u32 = 5;

fn backoff(attempt: u32) {
    thread::sleep(Duration::from_secs(1u64 << (attempt - 1)));
}
fn transient(record: &Value) -> bool {
    record["reason"] == "command_error"
        && (record["code"] == "network_error"
            || (record["code"] == "api_error"
                && record["httpStatus"]
                    .as_u64()
                    .is_some_and(|status| status == 429 || status >= 500)))
}
fn activity_failed(record: &Value) -> bool {
    record["reason"] == "command_error"
        && record["code"] == "api_error"
        && record["activity"]["status"] == "ACTIVITY_STATUS_FAILED"
}

pub(crate) struct Run {
    pub(crate) home: TempDir,
    /// The parent organization and the admin credential, which is also the
    /// root of this run's sub-organization.
    pub(crate) config: E2eConfig,
    pub(crate) marker: String,
    pub(crate) secrets: RefCell<Vec<String>>,
    /// The sub-organization this run owns; `None` only while it is being
    /// created, so a failed bootstrap never tries to delete anything.
    sub_org: Option<String>,
}

fn now_ms() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string()
}

pub(crate) fn result<'v>(record: &'v Value, key: &str) -> &'v Value {
    &record["data"]["activity"]["result"][key]
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
    /// Creates the sub-organization for one test, rooted by the admin
    /// credential from `.env.test` so the same key signs everything.
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
        let body = json!({
            "type": "ACTIVITY_TYPE_CREATE_SUB_ORGANIZATION_V7",
            "timestampMs": now_ms(),
            "organizationId": run.config.organization_id.to_string(),
            "parameters": {
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
            },
        })
        .to_string();
        let created = run.submit_as(
            run.parent().args([
                "request",
                "--path",
                "/public/v1/submit/create_sub_organization",
                "--body",
                &body,
            ]),
            "request",
            &|| run.parent(),
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

    /// The sub-organization every command of this test runs against.
    pub(crate) fn org(&self) -> String {
        self.sub_org
            .clone()
            .expect("sub-organization is created before any test command runs")
    }

    pub(crate) fn registry_path(&self) -> PathBuf {
        self.home.path().join(".config/turnkey/tk.config.toml")
    }

    pub(crate) fn cli_at(&self, base: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
        for name in SCRUBBED {
            cmd.env_remove(name);
        }
        cmd.env("HOME", self.home.path())
            .arg("--message-format=json")
            .arg("--api-base-url")
            .arg(base);
        cmd
    }

    pub(crate) fn cli(&self) -> Command {
        self.cli_at(&self.config.api_base_url)
    }

    fn with_bundle(&self, mut cmd: Command, org: &str, public: &str, private: &str) -> Command {
        cmd.env("TURNKEY_ORGANIZATION_ID", org)
            .env("TURNKEY_API_PUBLIC_KEY", public)
            .env("TURNKEY_API_PRIVATE_KEY", private);
        cmd
    }

    /// The admin key against the parent organization. Only sub-organization
    /// creation uses it.
    fn parent(&self) -> Command {
        self.with_bundle(
            self.cli(),
            &self.config.organization_id.to_string(),
            &self.config.public_key,
            &self.config.private_key.0,
        )
    }

    fn admin_at(&self, base: &str) -> Command {
        self.with_bundle(
            self.cli_at(base),
            &self.org(),
            &self.config.public_key,
            &self.config.private_key.0,
        )
    }

    /// The admin key against this run's sub-organization, where it is root.
    pub(crate) fn admin(&self) -> Command {
        self.admin_at(&self.config.api_base_url)
    }

    /// The sub-organization root bundle pointed at an unroutable host, for
    /// asserting that a check happens before any request.
    pub(crate) fn admin_offline(&self) -> Command {
        self.admin_at(UNROUTABLE)
    }

    pub(crate) fn key(&self) -> TurnkeyP256ApiKey {
        let key = TurnkeyP256ApiKey::generate();
        self.secrets
            .borrow_mut()
            .push(hex::encode(key.private_key()));
        key
    }

    /// A bundle for another user of the sub-organization.
    pub(crate) fn as_user(&self, key: &TurnkeyP256ApiKey) -> Command {
        self.with_bundle(
            self.cli(),
            &self.org(),
            &hex::encode(key.compressed_public_key()),
            &hex::encode(key.private_key()),
        )
    }

    /// Writes the admin key as a `tk api-key generate` style file.
    pub(crate) fn admin_key_file(&self) -> PathBuf {
        let path = self.home.path().join("admin-key.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(
            json!({
                "public_key": self.config.public_key,
                "private_key": self.config.private_key.0,
                "curve": "p256",
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        path
    }

    pub(crate) fn redact(&self, bytes: &[u8]) -> String {
        let mut text = String::from_utf8_lossy(bytes).into_owned();
        for secret in self.secrets.borrow().iter() {
            text = text.replace(secret, "<redacted>");
        }
        text
    }

    /// Runs the binary and parses its one JSON record, returning the exit
    /// code for callers that decide what an unexpected code means.
    fn run(&self, cmd: &mut Command) -> (Option<i32>, Value, String, String) {
        let output = cmd.output().unwrap();
        let stdout = self.redact(&output.stdout);
        let stderr = self.redact(&output.stderr);
        for (stream, raw) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
            assert!(
                self.redact(raw) == String::from_utf8_lossy(raw),
                "private key leaked to {stream}\nstdout: {stdout}\nstderr: {stderr}"
            );
        }
        assert!(stderr.is_empty(), "stderr not empty: {stderr}");
        let record = serde_json::from_str(&stdout)
            .unwrap_or_else(|error| panic!("stdout is not one JSON record ({error}): {stdout}"));
        (output.status.code(), record, stdout, stderr)
    }

    /// Runs the binary, repeating it with backoff while the outcome is a
    /// transient failure. `assert_cmd` re-spawns the process and re-applies
    /// any `write_stdin` buffer on every call.
    fn attempt(&self, cmd: &mut Command) -> (Option<i32>, Value, String, String) {
        for attempt in 1..ATTEMPTS {
            let (exit, record, stdout, stderr) = self.run(cmd);
            if !transient(&record) {
                return (exit, record, stdout, stderr);
            }
            eprintln!("transient failure, attempt {attempt}/{ATTEMPTS}: {stdout}");
            backoff(attempt);
        }
        self.run(cmd)
    }

    pub(crate) fn record(&self, cmd: &mut Command, code: i32) -> Value {
        let (exit, record, stdout, stderr) = self.attempt(cmd);
        assert_eq!(
            exit,
            Some(code),
            "unexpected exit code\nstdout: {stdout}\nstderr: {stderr}"
        );
        record
    }

    pub(crate) fn ok(&self, cmd: &mut Command) -> Value {
        self.record(cmd, 0)
    }

    pub(crate) fn err(&self, cmd: &mut Command) -> Value {
        self.record(cmd, 1)
    }

    fn wait_as(&self, mut cmd: Command, id: &str) -> Value {
        let record = self.ok(cmd.args(["activity", "wait", "--id", id, "--timeout", "90"]));
        assert_eq!(record["command"], "activity.wait");
        assert_eq!(record["status"], "completed", "{record}");
        assert_eq!(record["activity"]["id"], id);
        record
    }

    pub(crate) fn wait(&self, id: &str) -> Value {
        self.wait_as(self.admin(), id)
    }

    /// Submits once, following a `pending` answer with a wait. Returns the
    /// completed record, or the failing record with its streams.
    fn submit_once(
        &self,
        cmd: &mut Command,
        command: &str,
        waiter: &dyn Fn() -> Command,
    ) -> Result<Value, (Value, String, String)> {
        let (exit, record, stdout, stderr) = self.attempt(cmd);
        if exit != Some(0) {
            return Err((record, stdout, stderr));
        }
        assert_eq!(record["command"], command, "{record}");
        match record["status"].as_str() {
            Some("completed") => Ok(record),
            Some("pending") => {
                let id = id_of(&record);
                let (exit, waited, stdout, stderr) = self.attempt(waiter().args([
                    "activity",
                    "wait",
                    "--id",
                    &id,
                    "--timeout",
                    "90",
                ]));
                if exit != Some(0) {
                    return Err((waited, stdout, stderr));
                }
                assert_eq!(waited["status"], "completed", "{waited}");
                assert_eq!(waited["activity"]["id"], id);
                Ok(waited)
            }
            other => panic!("unexpected submission status {other:?}: {record}"),
        }
    }

    fn submit_as(&self, cmd: &mut Command, command: &str, waiter: &dyn Fn() -> Command) -> Value {
        for attempt in 1..=ATTEMPTS {
            match self.submit_once(cmd, command, waiter) {
                Ok(record) => return record,
                Err((record, _, _)) if activity_failed(&record) && attempt < ATTEMPTS => {
                    eprintln!(
                        "{command} failed server-side, attempt {attempt}/{ATTEMPTS}: {record}"
                    );
                    backoff(attempt);
                }
                Err((_, stdout, stderr)) => {
                    panic!("{command} failed\nstdout: {stdout}\nstderr: {stderr}")
                }
            }
        }
        panic!("{command} did not complete within {ATTEMPTS} attempts")
    }
    /// Submits `command` as the sub-organization root and returns its
    /// completed activity record. The API may answer before the activity
    /// finishes, so a `pending` response is legitimate and is followed by a
    /// wait; only the completed record is returned, which is why the command
    /// is asserted here rather than by callers. An activity the API accepted
    /// and then failed is submitted again with backoff. Note that `tk`
    /// subcommands stamp a fresh timestamp per invocation, so a re-submit is a
    /// new activity; a raw `request` with a fixed `timestampMs` would be
    /// deduplicated by fingerprint and must rebuild its body per attempt.
    pub(crate) fn submit(&self, cmd: &mut Command, command: &str) -> Value {
        self.submit_as(cmd, command, &|| self.admin())
    }
    /// Creates a user of the sub-organization with one fresh API key. The
    /// user can only run queries until a policy names it.
    pub(crate) fn create_user(&self, label: &str) -> (String, TurnkeyP256ApiKey) {
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
        let user_id = result(&created, "createUsersResult")["userIds"][0]
            .as_str()
            .unwrap()
            .to_string();
        (user_id, key)
    }
    /// Deletes the sub-organization and everything in it. The API has been
    /// observed to fail deletions with an internal error while other
    /// activities are in flight, and the same request succeeds once they
    /// settle. The body is rebuilt per attempt because the API deduplicates
    /// an identical `timestampMs` body to the same (failed) activity.
    fn delete_sub_organization(&self) {
        for attempt in 1..=ATTEMPTS {
            let body = json!({
                "type": "ACTIVITY_TYPE_DELETE_SUB_ORGANIZATION",
                "timestampMs": now_ms(),
                "organizationId": self.org(),
                "parameters": {"deleteWithoutExport": true},
            })
            .to_string();
            let mut cmd = self.admin();
            cmd.args([
                "request",
                "--path",
                "/public/v1/submit/delete_sub_organization",
                "--body",
                &body,
            ]);
            match self.submit_once(&mut cmd, "request", &|| self.admin()) {
                Ok(_) => return,
                Err((record, _, _)) if activity_failed(&record) && attempt < ATTEMPTS => {
                    eprintln!(
                        "sub-organization delete failed server-side, attempt {attempt}/{ATTEMPTS}: {record}"
                    );
                    backoff(attempt);
                }
                Err((_, stdout, stderr)) => panic!(
                    "delete sub-organization {} failed\nstdout: {stdout}\nstderr: {stderr}",
                    self.org()
                ),
            }
        }
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        let Some(sub_org) = self.sub_org.clone() else {
            return;
        };
        if let Err(panic) = catch_unwind(AssertUnwindSafe(|| self.delete_sub_organization())) {
            let message = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
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
