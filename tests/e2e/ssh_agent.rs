//! Live SSH agent coverage: serving the registry, narrowing, and lifecycle.

use std::fs;
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

use assert_cmd::Command as TkCommand;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::run::{Run, bare_cli, result};
use crate::ssh::{
    check_signature, create_ed25519_key, generate_local_key, locate, register_key, text,
};

/// Stops the agent when the test ends, whether or not it passed.
struct Agent<'r> {
    run: &'r Run,
    socket: PathBuf,
    paths: Vec<String>,
    started: Value,
}

impl<'r> Agent<'r> {
    fn start(run: &'r Run, command: &mut TkCommand, keys: &[&str], paths: Vec<String>) -> Self {
        Self::start_with(run, command, keys, paths, Vec::new())
    }

    fn start_constrained(
        run: &'r Run,
        command: &mut TkCommand,
        keys: &[&str],
        paths: Vec<String>,
        allowed_hosts: &Path,
        namespaces: &[&str],
    ) -> Self {
        let start_args = [
            "--allowed-hosts-file".to_string(),
            allowed_hosts.display().to_string(),
        ]
        .into_iter()
        .chain(
            namespaces
                .iter()
                .flat_map(|namespace| ["--allow-namespace".to_string(), namespace.to_string()]),
        )
        .collect();
        Self::start_with(run, command, keys, paths, start_args)
    }

    fn start_with(
        run: &'r Run,
        command: &mut TkCommand,
        keys: &[&str],
        paths: Vec<String>,
        start_args: Vec<String>,
    ) -> Self {
        let started = run.ok(command
            .args(["ssh", "agent", "start"])
            .args(keys.iter().flat_map(|key| ["--key", key]))
            .args(&paths)
            .args(start_args));
        assert_eq!(started["reason"], "agent_started", "{started}");
        let socket = PathBuf::from(text(&started["socket"]));
        assert!(socket.exists(), "the agent socket was not created");
        Self {
            run,
            socket,
            paths,
            started,
        }
    }

    fn fingerprints(&self) -> &Value {
        &self.started["keys"]
    }

    fn status(&self) -> Value {
        self.run.ok(self
            .run
            .admin_offline()
            .args(["ssh", "agent", "status"])
            .args(&self.paths))
    }

    /// The `ssh-ed25519 <base64> turnkey:<private-key-id>` lines the agent
    /// advertises, sorted.
    fn listed_keys(&self, ssh_add: &Path) -> Vec<String> {
        let listed = Command::new(ssh_add)
            .arg("-L")
            .env("SSH_AUTH_SOCK", &self.socket)
            .output()
            .expect("ssh-add should run");
        assert!(
            listed.status.success(),
            "{}",
            String::from_utf8_lossy(&listed.stderr)
        );
        let mut lines: Vec<String> = String::from_utf8_lossy(&listed.stdout)
            .lines()
            .map(str::to_string)
            .collect();
        lines.sort();
        lines
    }

    /// Signs through the agent with the key in `public_key_path`.
    fn sign(&self, ssh_keygen: &Path, public_key_path: &Path, payload: &Path) -> Output {
        self.sign_in(ssh_keygen, "git", public_key_path, payload)
    }

    fn sign_in(
        &self,
        ssh_keygen: &Path,
        namespace: &str,
        public_key_path: &Path,
        payload: &Path,
    ) -> Output {
        Command::new(ssh_keygen)
            .args(["-Y", "sign", "-n", namespace, "-U", "-f"])
            .arg(public_key_path)
            .arg(payload)
            .env("SSH_AUTH_SOCK", &self.socket)
            .output()
            .expect("ssh-keygen should run")
    }

    fn stop(self) -> Value {
        let stopped = self.run.ok(self
            .run
            .admin_offline()
            .args(["ssh", "agent", "stop"])
            .args(&self.paths));
        assert!(!self.socket.exists(), "the agent socket was not removed");
        stopped
    }
}

impl Drop for Agent<'_> {
    fn drop(&mut self) {
        if self.socket.exists() {
            let _ = self
                .run
                .admin_offline()
                .args(["ssh", "agent", "stop"])
                .args(&self.paths)
                .output();
        }
    }
}

struct AgentPaths {
    socket: PathBuf,
    pid_file: PathBuf,
}

impl AgentPaths {
    fn new(run: &Run, name: &str) -> Self {
        Self {
            socket: run.home().join(format!("agent/{name}.sock")),
            pid_file: run.home().join(format!("agent/{name}.pid")),
        }
    }

    fn args(&self) -> Vec<String> {
        vec![
            "--socket".to_string(),
            self.socket.display().to_string(),
            "--pid-file".to_string(),
            self.pid_file.display().to_string(),
        ]
    }
}

fn public_key_file(run: &Run, name: &str, registered: &Value) -> PathBuf {
    let path = run.home().join(name);
    fs::write(&path, format!("{}\n", text(&registered["publicKey"]))).unwrap();
    path
}

/// The line the agent should advertise for a registered key: its OpenSSH
/// public key followed by the comment naming the Turnkey private key.
fn advertised(registered: &Value, private_key_id: &str) -> String {
    format!(
        "{} turnkey:{private_key_id}",
        text(&registered["publicKey"])
    )
}

fn sorted(mut lines: Vec<String>) -> Vec<String> {
    lines.sort();
    lines
}

#[test]
#[ignore]
fn agent_serves_every_registered_key_and_reports_its_lifecycle() {
    let (Some(ssh_add), Some(ssh_keygen)) = (locate("ssh-add"), locate("ssh-keygen")) else {
        eprintln!("skipping the SSH agent test: ssh-add or ssh-keygen is not on PATH");
        return;
    };
    let run = Run::new();
    let first_id = create_ed25519_key(&run);
    let first = register_key(&run, &mut run.admin(), &first_id);
    let second_id = create_ed25519_key(&run);
    let second = register_key(&run, &mut run.admin(), &second_id);
    let payload = run.home().join("payload.txt");
    fs::write(&payload, b"signed through the tk ssh agent\n").unwrap();
    let signature = run.home().join("payload.txt.sig");
    let second_public_key = public_key_file(&run, "second.pub", &second);
    let unregistered = generate_local_key(
        &ssh_keygen,
        &run.home().join("unregistered_ed25519"),
        "ed25519",
    );

    // Before the agent runs, status and stop report that plainly.
    let not_running = run.err(run.admin_offline().args(["ssh", "agent", "status"]));
    assert_eq!(not_running["code"], "command_error");
    assert_eq!(not_running["message"], "ssh-agent is not running");
    assert_eq!(
        run.ok(run.admin_offline().args(["ssh", "agent", "stop"])),
        json!({"reason": "agent_not_running"})
    );

    // Default paths live beside the registry.
    let agent = Agent::start(&run, &mut run.admin(), &[], Vec::new());
    let expected_fingerprints = json!(sorted(vec![
        text(&first["fingerprint"]).to_string(),
        text(&second["fingerprint"]).to_string(),
    ]));
    assert_eq!(agent.fingerprints(), &expected_fingerprints);
    assert_eq!(
        agent.socket,
        run.home().join(".config/turnkey/ssh-agent.sock")
    );
    assert!(run.home().join(".config/turnkey/ssh-agent.pid").exists());
    assert_eq!(agent.started["socketMode"], "600", "{}", agent.started);
    assert_eq!(
        fs::metadata(&agent.socket).unwrap().permissions().mode() & 0o777,
        0o600
    );

    assert_eq!(
        agent.listed_keys(&ssh_add),
        sorted(vec![
            advertised(&first, &first_id),
            advertised(&second, &second_id)
        ])
    );

    let status = agent.status();
    assert_eq!(
        status,
        json!({
            "reason": "agent_status_report",
            "pid": agent.started["pid"],
            "socket": agent.started["socket"],
            "socketMode": "600",
            "keys": expected_fingerprints,
        })
    );

    // A real client chooses the second key and Turnkey signs with it.
    let signed = agent.sign(&ssh_keygen, &second_public_key, &payload);
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let checked = check_signature(&ssh_keygen, &second_public_key, &payload, &signature);
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    fs::remove_file(&signature).unwrap();

    // A key the agent does not hold is refused on the wire.
    let refused = agent.sign(&ssh_keygen, &unregistered, &payload);
    assert!(
        !refused.status.success(),
        "the agent signed with an unregistered key"
    );
    assert!(!signature.exists());

    // A second start is refused while the first agent holds the socket.
    let duplicate = run.err(run.admin().args(["ssh", "agent", "start"]));
    assert_eq!(duplicate["code"], "command_error");
    assert_eq!(
        duplicate["message"],
        format!("ssh-agent is already running on {}", agent.socket.display())
    );

    // Registry edits do not reach the running agent, and the human output
    // says so.
    let mut readd = Command::new(env!("CARGO_BIN_EXE_tk"));
    run.inherit_environment(run.admin(), &mut readd);
    let readded = run.human_stdout(TkCommand::from_std(readd).args([
        "ssh",
        "keys",
        "add",
        "--private-key-id",
        &first_id,
    ]));
    assert_eq!(
        readded,
        format!(
            "{}  {}  {first_id}; restart tk ssh agent to pick this up\n",
            text(&first["fingerprint"]),
            run.org()
        )
    );
    let mut remove = bare_cli(run.home());
    let removed = run.human_stdout(remove.args(["ssh", "keys", "remove", &first_id]));
    assert_eq!(
        removed,
        format!(
            "removed SSH key {} from the registry; restart tk ssh agent to pick this up\n",
            text(&first["fingerprint"])
        )
    );
    assert_eq!(
        agent.listed_keys(&ssh_add),
        sorted(vec![
            advertised(&first, &first_id),
            advertised(&second, &second_id)
        ])
    );

    assert_eq!(agent.stop(), json!({"reason": "agent_stopped"}));
    let stopped = run.err(run.admin_offline().args(["ssh", "agent", "status"]));
    assert_eq!(stopped["message"], "ssh-agent is not running");
    assert!(!run.home().join(".config/turnkey/ssh-agent.pid").exists());

    // Without the first key the restarted agent serves the rest.
    let restarted = Agent::start(&run, &mut run.admin(), &[], Vec::new());
    assert_eq!(
        restarted.listed_keys(&ssh_add),
        vec![advertised(&second, &second_id)]
    );
    assert_eq!(restarted.stop(), json!({"reason": "agent_stopped"}));
}

#[test]
#[ignore]
fn agent_start_narrows_by_key_profile_and_organization() {
    let (Some(ssh_add), Some(ssh_keygen)) = (locate("ssh-add"), locate("ssh-keygen")) else {
        eprintln!("skipping the SSH agent narrowing test: ssh-add or ssh-keygen is not on PATH");
        return;
    };
    let run = Run::new();
    let first_id = create_ed25519_key(&run);
    let first = register_key(&run, &mut run.admin(), &first_id);
    let second_id = create_ed25519_key(&run);
    let second = register_key(&run, &mut run.admin(), &second_id);
    let first_fingerprint = text(&first["fingerprint"]).to_string();
    let second_fingerprint = text(&second["fingerprint"]).to_string();
    let payload = run.home().join("payload.txt");
    fs::write(&payload, b"narrowed agent\n").unwrap();
    let signature = run.home().join("payload.txt.sig");
    let first_public_key = public_key_file(&run, "first.pub", &first);
    let second_public_key = public_key_file(&run, "second.pub", &second);
    let paths = AgentPaths::new(&run, "narrowed");
    let unregistered = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // A named key serves only that key, by fingerprint or private key ID.
    let narrowed = Agent::start(&run, &mut run.admin(), &[&first_fingerprint], paths.args());
    assert_eq!(narrowed.fingerprints(), &json!([first_fingerprint]));
    assert_eq!(
        narrowed.listed_keys(&ssh_add),
        vec![advertised(&first, &first_id)]
    );
    let refused = narrowed.sign(&ssh_keygen, &second_public_key, &payload);
    assert!(
        !refused.status.success(),
        "the narrowed agent signed with an unserved key"
    );
    assert!(!signature.exists());
    let signed = narrowed.sign(&ssh_keygen, &first_public_key, &payload);
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    fs::remove_file(&signature).unwrap();
    assert_eq!(narrowed.stop(), json!({"reason": "agent_stopped"}));

    let by_id = Agent::start(
        &run,
        &mut run.admin(),
        &[&second_id, &second_fingerprint],
        paths.args(),
    );
    assert_eq!(by_id.fingerprints(), &json!([second_fingerprint]));
    assert_eq!(by_id.stop(), json!({"reason": "agent_stopped"}));

    // Every failure below is reported before a socket or pid file exists.
    let no_agent = |record: Value, code: &str, message: String| {
        assert_eq!(record["code"], code, "{record}");
        assert_eq!(record["message"], message, "{record}");
        assert!(
            !paths.socket.exists(),
            "a failed start left {}",
            paths.socket.display()
        );
        assert!(
            !paths.pid_file.exists(),
            "a failed start left {}",
            paths.pid_file.display()
        );
    };
    let path_args = paths.args();
    no_agent(
        run.err(
            run.admin_offline()
                .args(["ssh", "agent", "start", "--key", unregistered])
                .args(&path_args),
        ),
        "invalid_input",
        format!(
            "no registered SSH key matches {unregistered}; register it with tk ssh keys add --private-key-id ID"
        ),
    );
    let nil = Uuid::nil().to_string();
    no_agent(
        run.err(
            run.admin_offline()
                .args(["--organization-id", &nil, "ssh", "agent", "start"])
                .args(&path_args),
        ),
        "invalid_input",
        format!(
            "organization {nil} selected by --organization-id has no registered SSH keys; register one with tk ssh keys add --private-key-id <id>, or drop the identity selection"
        ),
    );

    // A profile in the key's organization is the credential for the set.
    let login = run.login_admin();
    let profiled = Agent::start(
        &run,
        run.cli().args(["--profile", &login.name]),
        &[],
        paths.args(),
    );
    assert_eq!(
        profiled.fingerprints(),
        &json!(sorted(vec![
            first_fingerprint.clone(),
            second_fingerprint.clone()
        ]))
    );
    let signed = profiled.sign(&ssh_keygen, &second_public_key, &payload);
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let checked = check_signature(&ssh_keygen, &second_public_key, &payload, &signature);
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    fs::remove_file(&signature).unwrap();
    assert_eq!(profiled.stop(), json!({"reason": "agent_stopped"}));

    // A profile of another organization has nothing to serve.
    run.ok(run
        .cli()
        .args(["profile", "set", &login.name, "--organization-id", &nil]));
    no_agent(
        run.err(
            run.cli()
                .args(["--profile", &login.name, "ssh", "agent", "start"])
                .args(&path_args),
        ),
        "invalid_input",
        format!(
            "organization {nil} selected by profile {} has no registered SSH keys; register one with tk ssh keys add --private-key-id <id>, or drop the identity selection",
            login.name
        ),
    );

    // An empty registry fails before any process is spawned.
    run.ok(run
        .admin_offline()
        .args(["ssh", "keys", "remove", &first_id]));
    run.ok(run
        .admin_offline()
        .args(["ssh", "keys", "remove", &second_id]));
    no_agent(
        run.err(
            run.admin_offline()
                .args(["ssh", "agent", "start"])
                .args(&path_args),
        ),
        "invalid_input",
        "the registry holds no SSH keys; register one with tk ssh keys add --private-key-id ID"
            .to_string(),
    );
}

#[test]
#[ignore]
fn using_ssh_register_serve_sign() {
    let ssh_add = locate("ssh-add").expect("using-ssh needs ssh-add on PATH");
    let ssh_keygen = locate("ssh-keygen").expect("using-ssh needs ssh-keygen on PATH");
    let run = Run::new();
    let (agent_tag, agent_id, agent_key) = run.create_agent();
    let create_key = |label: &str| {
        let name = run.name(label);
        let created = run.ok_created_or_reregistered(
            run.admin().args(["ssh", "keys", "create", "--name", &name]),
            "ssh_key_created",
            "ssh_key_registered",
        );
        assert_eq!(created["organizationId"], run.org(), "{created}");
        assert!(
            text(&created["fingerprint"]).starts_with("SHA256:"),
            "{created}"
        );
        assert!(
            text(&created["publicKey"]).starts_with("ssh-ed25519 "),
            "{created}"
        );
        let reused = run.ok(run.admin().args(["ssh", "keys", "create", "--name", &name]));
        assert_eq!(
            reused,
            json!({
                "reason": "ssh_key_registered",
                "organizationId": created["organizationId"],
                "privateKeyId": created["privateKeyId"],
                "fingerprint": created["fingerprint"],
                "publicKey": created["publicKey"],
            })
        );
        text(&created["privateKeyId"]).to_string()
    };
    let served_id = create_key("agent-ssh");
    let unserved_id = create_key("agent-ssh-unserved");
    run.allow_tag_signing(
        "agents-sign-ssh",
        &agent_tag,
        &format!(
            "activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2' && private_key.id == '{served_id}'"
        ),
    );
    let payload = run.home().join("payload.txt");
    fs::write(&payload, b"signed through the agent's tk ssh agent\n").unwrap();
    let signature = run.home().join("payload.txt.sig");
    let paths = AgentPaths::new(&run, "ssh");

    let served = register_key(&run, &mut run.as_user(&agent_key), &served_id);
    assert_eq!(served["privateKeyId"], served_id, "{served}");
    let unserved = register_key(&run, &mut run.as_user(&agent_key), &unserved_id);
    assert_eq!(
        run.ok(run
            .as_user(&agent_key)
            .args(["ssh", "public-key", "--key", &served_id])),
        json!({
            "reason": "public_key_printed",
            "fingerprint": served["fingerprint"],
            "publicKey": served["publicKey"],
        })
    );
    let served_public_key = public_key_file(&run, "served.pub", &served);
    let unserved_public_key = public_key_file(&run, "unserved.pub", &unserved);

    let agent = Agent::start_with(
        &run,
        &mut run.as_user(&agent_key),
        &[],
        paths.args(),
        vec!["--socket-mode".to_string(), "660".to_string()],
    );
    assert_eq!(
        fs::metadata(&agent.socket).unwrap().permissions().mode() & 0o777,
        0o660
    );
    assert_eq!(
        agent.listed_keys(&ssh_add),
        sorted(vec![
            advertised(&served, &served_id),
            advertised(&unserved, &unserved_id)
        ])
    );
    assert_eq!(
        agent.status(),
        json!({
            "reason": "agent_status_report",
            "pid": agent.started["pid"],
            "socket": agent.started["socket"],
            "socketMode": "660",
            "keys": agent.fingerprints(),
        })
    );
    let sign_and_check = |agent: &Agent<'_>| {
        let signed = agent.sign(&ssh_keygen, &served_public_key, &payload);
        assert!(
            signed.status.success(),
            "{}",
            String::from_utf8_lossy(&signed.stderr)
        );
        let checked = check_signature(&ssh_keygen, &served_public_key, &payload, &signature);
        assert!(
            checked.status.success(),
            "{}",
            String::from_utf8_lossy(&checked.stderr)
        );
        fs::remove_file(&signature).unwrap();
    };
    sign_and_check(&agent);
    let denied = agent.sign(&ssh_keygen, &unserved_public_key, &payload);
    assert!(
        !denied.status.success(),
        "the agent signed with a key no policy allows"
    );
    assert!(!signature.exists());

    let profile = run.name("agent");
    run.login_as(&profile, &agent_key);
    let profiled = Agent::start(
        &run,
        run.cli().args(["--profile", &profile]),
        &[],
        AgentPaths::new(&run, "profiled").args(),
    );
    let registry = fs::read(run.registry_path()).unwrap();
    fs::write(run.registry_path(), b"version = ").unwrap();
    let unreadable = profiled.sign(&ssh_keygen, &served_public_key, &payload);
    assert!(
        !unreadable.status.success(),
        "a daemon whose registry failed to load still signed"
    );
    assert!(!signature.exists());
    fs::write(run.registry_path(), registry).unwrap();
    sign_and_check(&profiled);

    let next_key = run.key();
    let next_public_key = hex::encode(next_key.compressed_public_key());
    run.register_api_key(&agent_id, &run.name("agent-next"), &next_public_key);
    let next_key_file = run.write_key_file(
        &format!("{profile}-next.json"),
        &next_public_key,
        &hex::encode(next_key.private_key()),
    );
    run.ok(run
        .cli()
        .args(["profile", "set", &profile, "--api-key-file"])
        .arg(&next_key_file));

    let old_id = run.api_key_id(&agent_id, &hex::encode(agent_key.compressed_public_key()));
    let deleted = run.submit(
        run.admin()
            .args(["api-key", "delete", "--user-id", &agent_id, &old_id]),
        "api-key.delete",
    );
    assert_eq!(
        result(&deleted, "deleteApiKeysResult")["apiKeyIds"],
        json!([old_id])
    );
    let revoked = run.err(run.as_user(&agent_key).arg("whoami"));
    assert_eq!(revoked["code"], "unauthorized", "{revoked}");

    let refused = agent.sign(&ssh_keygen, &served_public_key, &payload);
    assert!(
        !refused.status.success(),
        "a daemon holding the revoked credential still signed"
    );
    assert!(!signature.exists());
    assert_eq!(agent.stop(), json!({"reason": "agent_stopped"}));
    sign_and_check(&profiled);

    run.ok(run.cli().args(["profile", "delete", &profile]));
    let unselected = profiled.sign(&ssh_keygen, &served_public_key, &payload);
    assert!(
        !unselected.status.success(),
        "a daemon whose profile was deleted still signed"
    );
    assert!(!signature.exists());
    assert_eq!(profiled.stop(), json!({"reason": "agent_stopped"}));
}

struct Sshd {
    child: Option<Child>,
    log: PathBuf,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn client_supports_session_bind(ssh: &Path) -> bool {
    let output = Command::new(ssh)
        .arg("-V")
        .output()
        .expect("ssh -V should run");
    let banner = String::from_utf8_lossy(&output.stderr).to_string()
        + &String::from_utf8_lossy(&output.stdout);
    let Some(version) = banner
        .strip_prefix("OpenSSH_")
        .and_then(|rest| rest.split(['p', ' ', ',']).next())
    else {
        return false;
    };
    let mut parts = version.splitn(2, '.');
    let (Some(Ok(major)), Some(Ok(minor))) = (
        parts.next().map(str::parse::<u32>),
        parts.next().map(str::parse::<u32>),
    ) else {
        return false;
    };
    (major, minor) >= (8, 9)
}

fn known_hosts_line(name: &str, public_key_path: &Path) -> String {
    let line = fs::read_to_string(public_key_path).expect("the public key should read");
    format!("{name} {}", line.trim())
}

#[test]
#[ignore]
fn constrained_agent_signs_only_allowed_namespaces_and_reports_them() {
    let (Some(ssh_add), Some(ssh_keygen)) = (locate("ssh-add"), locate("ssh-keygen")) else {
        eprintln!("skipping the SSH agent constraints test: ssh-add or ssh-keygen is not on PATH");
        return;
    };
    let run = Run::new();
    let key_id = create_ed25519_key(&run);
    let registered = register_key(&run, &mut run.admin(), &key_id);
    let public_key = public_key_file(&run, "served.pub", &registered);
    let payload = run.home().join("payload.txt");
    fs::write(&payload, b"signed under a destination constraint\n").unwrap();
    let signature = run.home().join("payload.txt.sig");
    let host_key = generate_local_key(&ssh_keygen, &run.home().join("host_ed25519"), "ed25519");
    let allowed_hosts = run.home().join("allowed-hosts");
    fs::write(
        &allowed_hosts,
        known_hosts_line("github.com", &host_key) + "\n",
    )
    .unwrap();
    let paths = AgentPaths::new(&run, "constrained");

    let agent = Agent::start_constrained(
        &run,
        &mut run.admin(),
        &[],
        paths.args(),
        &allowed_hosts,
        &["git"],
    );
    assert_eq!(
        agent.status(),
        json!({
            "reason": "agent_status_report",
            "pid": agent.started["pid"],
            "socket": agent.started["socket"],
            "socketMode": "600",
            "keys": agent.fingerprints(),
            "allowedHosts": ["github.com"],
            "allowedNamespaces": ["git"],
        })
    );
    assert_eq!(
        agent.listed_keys(&ssh_add),
        vec![advertised(&registered, &key_id)]
    );

    let signed = agent.sign(&ssh_keygen, &public_key, &payload);
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let checked = check_signature(&ssh_keygen, &public_key, &payload, &signature);
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    fs::remove_file(&signature).unwrap();

    let refused = agent.sign_in(&ssh_keygen, "file", &public_key, &payload);
    assert!(
        !refused.status.success(),
        "the agent signed outside its allowed namespaces"
    );
    assert!(!signature.exists());
    assert_eq!(agent.stop(), json!({"reason": "agent_stopped"}));
}

#[test]
#[ignore]
fn constrained_agent_gates_ssh_userauth_by_server_host_key() {
    let (Some(sshd), Some(ssh), Some(ssh_keygen)) =
        (locate("sshd"), locate("ssh"), locate("ssh-keygen"))
    else {
        eprintln!("skipping the SSH agent userauth test: sshd, ssh, or ssh-keygen is not on PATH");
        return;
    };
    if !client_supports_session_bind(&ssh) {
        eprintln!("skipping the SSH agent userauth test: ssh is older than OpenSSH 8.9");
        return;
    }
    let run = Run::new();
    let key_id = create_ed25519_key(&run);
    let registered = register_key(&run, &mut run.admin(), &key_id);
    let public_key = public_key_file(&run, "served.pub", &registered);

    let host_public_key =
        generate_local_key(&ssh_keygen, &run.home().join("host_ed25519"), "ed25519");
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let authorized_keys = run.home().join("authorized_keys");
    fs::write(
        &authorized_keys,
        format!("{}\n", text(&registered["publicKey"])),
    )
    .unwrap();
    let sshd_log = run.home().join("sshd.log");
    let sshd_config = run.home().join("sshd_config");
    fs::write(
        &sshd_config,
        format!(
            r#"Port {port}
ListenAddress 127.0.0.1
HostKey {}
PidFile {}
AuthorizedKeysFile {}
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
LogLevel VERBOSE
"#,
            run.home().join("host_ed25519").display(),
            run.home().join("sshd.pid").display(),
            authorized_keys.display(),
        ),
    )
    .unwrap();
    let mut sshd = Sshd {
        child: Some(
            Command::new(&sshd)
                .arg("-D")
                .arg("-f")
                .arg(&sshd_config)
                .arg("-E")
                .arg(&sshd_log)
                .stderr(Stdio::piped())
                .spawn()
                .expect("sshd should spawn"),
        ),
        log: sshd_log,
    };
    run.wait_for_child(&mut sshd.child, "sshd", "listening on its port", || {
        TcpStream::connect(("127.0.0.1", port)).is_ok()
    });

    let known_hosts = run.home().join("known_hosts");
    let host_line = known_hosts_line(&format!("[127.0.0.1]:{port}"), &host_public_key);
    fs::write(&known_hosts, format!("{host_line}\n")).unwrap();
    let user = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_string();
    let connect = |agent: &Agent<'_>| {
        Command::new(&ssh)
            .args([
                "-F",
                "none",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "ConnectTimeout=10",
            ])
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
            .arg("-o")
            .arg(format!("IdentityFile={}", public_key.display()))
            .args(["-p", &port.to_string()])
            .arg(format!("{user}@127.0.0.1"))
            .arg("true")
            .env("SSH_AUTH_SOCK", &agent.socket)
            .output()
            .expect("ssh should run")
    };

    let allowed_file = run.home().join("allowed-hosts");
    fs::write(&allowed_file, format!("{host_line}\n")).unwrap();
    let paths = AgentPaths::new(&run, "allowed");
    let allowed = Agent::start_constrained(
        &run,
        &mut run.admin(),
        &[],
        paths.args(),
        &allowed_file,
        &[],
    );
    let accepted = connect(&allowed);
    assert!(
        accepted.status.success(),
        "ssh to an allowed host failed: {}\nsshd: {}",
        String::from_utf8_lossy(&accepted.stderr),
        fs::read_to_string(&sshd.log).unwrap_or_default()
    );
    assert_eq!(allowed.stop(), json!({"reason": "agent_stopped"}));

    let decoy = generate_local_key(&ssh_keygen, &run.home().join("decoy_ed25519"), "ed25519");
    let decoy_file = run.home().join("decoy-hosts");
    fs::write(&decoy_file, known_hosts_line("github.com", &decoy) + "\n").unwrap();
    let decoy_paths = AgentPaths::new(&run, "decoy");
    let refused_agent = Agent::start_constrained(
        &run,
        &mut run.admin(),
        &[],
        decoy_paths.args(),
        &decoy_file,
        &[],
    );
    let refused = connect(&refused_agent);
    assert!(
        !refused.status.success(),
        "the agent signed for a host key outside its allowed hosts"
    );
    assert_eq!(refused_agent.stop(), json!({"reason": "agent_stopped"}));
}
