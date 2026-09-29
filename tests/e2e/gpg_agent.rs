use std::fs;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

use tempfile::TempDir;
use turnkey_api_key_stamper::TurnkeyP256ApiKey;

use crate::gpg::{add_key, create_key, create_occupied_wallet, import_public_key, openpgp_config};
use crate::run::{Run, signed_commit};
use crate::ssh::locate;

const USER_ID: &str = "tk gpg agent e2e <tk-gpg-agent-e2e@example.com>";
const BROKER_TAG: &str = "broker";

struct Agent<'r> {
    child: Option<Child>,
    run: &'r Run,
    socket: PathBuf,
}

impl<'r> Agent<'r> {
    fn start(run: &'r Run, key: &TurnkeyP256ApiKey, fingerprint: &str, socket: PathBuf) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_tk"));
        run.inherit_environment(run.as_user(key), &mut command);
        let child = command
            .args(["gpg", "agent", "serve", "--key", fingerprint, "--socket"])
            .arg(&socket)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the OpenPGP agent should start");
        let mut agent = Self {
            child: Some(child),
            run,
            socket,
        };
        run.wait_for_child(
            &mut agent.child,
            "OpenPGP agent",
            "accepting connections",
            || UnixStream::connect(&agent.socket).is_ok(),
        );
        agent
    }

    fn terminate(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if child.try_wait().unwrap().is_none() {
            let signaled = unsafe { libc::kill(child.id().cast_signed(), libc::SIGTERM) };
            assert_eq!(signaled, 0, "failed to terminate the OpenPGP agent");
        }
        let output = child
            .wait_with_output()
            .expect("the OpenPGP agent should exit after SIGTERM");
        assert_redacted(self.run, "OpenPGP agent shutdown", &output);
        assert!(
            output.status.success(),
            "OpenPGP agent failed: {}",
            self.run.redact(&output.stderr)
        );
        assert!(!self.socket.exists(), "the agent socket was not removed");
    }
}

impl Drop for Agent<'_> {
    fn drop(&mut self) {
        self.terminate();
    }
}

fn assert_redacted(run: &Run, operation: &str, output: &Output) {
    let stdout = run.redact(&output.stdout);
    let stderr = run.redact(&output.stderr);
    for (stream, raw) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
        assert_eq!(
            run.redact(raw),
            String::from_utf8_lossy(raw),
            r#"private key leaked during {operation} on {stream}
stdout: {stdout}
stderr: {stderr}"#
        );
    }
}

#[test]
#[ignore]
fn foreground_agent_signs_for_a_credential_free_git_client() {
    let (Some(gpg), Some(git_executable)) = (locate("gpg"), locate("git")) else {
        eprintln!("skipping the GPG agent test: gpg or git is not on PATH");
        return;
    };
    let run = Run::new();
    let wallet = create_occupied_wallet(&run);
    let broker_tag = run.create_tag(BROKER_TAG);
    let (broker_id, broker) = run.create_tagged_user("broker", BROKER_TAG);
    run.allow_tag_signing(
        "brokers-sign-gpg",
        &broker_tag,
        &format!("activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2' && wallet.id == '{wallet}'"),
    );
    run.deny_agent_credentials(&broker_tag);
    let created = create_key(&run, &wallet, USER_ID);
    let fingerprint = created["fingerprint"].as_str().unwrap();
    add_key(&run, &mut run.as_user(&broker), &wallet, fingerprint);
    let exported =
        run.ok(run
            .as_user(&broker)
            .args(["gpg", "keys", "export", "--key", fingerprint]));
    assert_eq!(exported["fingerprint"], fingerprint, "{exported}");
    run.assert_api_key_register_denied(&mut run.as_user(&broker), &broker_id);

    let client_home = TempDir::new().unwrap();
    let repository = client_home.path().join("repository");
    fs::create_dir(&repository).unwrap();
    let gnupghome = import_public_key(
        &run,
        &gpg,
        client_home.path(),
        fingerprint,
        exported["armored"].as_str().unwrap(),
    );
    let socket = run.home().join("gpg-agent-e2e.sock");
    let _agent = Agent::start(&run, &broker, fingerprint, socket.clone());
    let tk = Path::new(env!("CARGO_BIN_EXE_tk"));
    let client = |socket: Option<&Path>, signing_key: Option<&str>, cmd: &mut Command| {
        cmd.env_clear()
            .env("HOME", client_home.path())
            .env("GNUPGHOME", &gnupghome)
            .env("TK_GPG_PROGRAM", &gpg);
        if let Some(socket) = socket {
            cmd.env("TK_GPG_AGENT_SOCK", socket);
        }
        openpgp_config(tk, signing_key, cmd);
    };
    let unsigned = |cmd: &mut Command| client(None, None, cmd);

    let initialized = run.git_ok(&git_executable, &repository, unsigned, &["init", "--quiet"]);
    assert_redacted(&run, "Git initialization", &initialized);
    let committed = run.git_ok(
        &git_executable,
        &repository,
        |cmd| client(Some(&socket), Some(fingerprint), cmd),
        &signed_commit("signed through the foreground agent"),
    );
    assert_redacted(&run, "Git commit signing", &committed);
    assert!(committed.stdout.is_empty());
    let verified = run.git_ok(
        &git_executable,
        &repository,
        unsigned,
        &["verify-commit", "HEAD"],
    );
    assert_redacted(&run, "Git commit verification", &verified);

    let other = "FEDCBA9876543210FEDCBA9876543210FEDCBA98";
    let refused = Run::git(
        &git_executable,
        &repository,
        |cmd| client(Some(&socket), Some(other), cmd),
        &signed_commit("unserved key must fail"),
    );
    assert_redacted(&run, "unserved Git key refusal", &refused);
    assert!(!refused.status.success(), "Git signed with an unserved key");
    assert!(refused.stdout.is_empty());
    let refused_stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        refused_stderr.contains("OpenPGP agent does not serve the requested key"),
        "unexpected refusal: {refused_stderr}"
    );
    assert!(!refused_stderr.contains("SIG_CREATED"));
}
