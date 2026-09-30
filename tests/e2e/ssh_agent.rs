//! Live SSH agent coverage: serving the registry, narrowing, and lifecycle.

use std::{
    ffi::OsStr,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use assert_cmd::Command as TkCommand;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    policy_helpers::SignScope,
    run::{AGENT_TAG, Run, bare_cli, result, skip},
    ssh::{check_signature, create_ed25519_key, generate_local_key, locate, register_key, text},
};

/// Stops the agent when the test ends, whether or not it passed.
pub(crate) struct Agent<'r> {
    run: &'r Run,
    pub(crate) socket: PathBuf,
    paths: Vec<String>,
    pub(crate) started: Value,
}

impl<'r> Agent<'r> {
    fn start(
        run: &'r Run,
        command: &mut TkCommand,
        keys: &[&str],
        paths: Option<(&Path, &Path)>,
    ) -> Self {
        Self::start_with(run, command, keys, paths, &[])
    }

    pub(crate) fn start_with(
        run: &'r Run,
        command: &mut TkCommand,
        keys: &[&str],
        paths: Option<(&Path, &Path)>,
        start_args: &[&str],
    ) -> Self {
        let paths = paths.map_or_else(Vec::new, |(socket, pid_file)| {
            vec![
                "--socket".to_string(),
                socket.display().to_string(),
                "--pid-file".to_string(),
                pid_file.display().to_string(),
            ]
        });
        Self::spawn(run, command, keys, paths, start_args)
    }

    pub(crate) fn spawn(
        run: &'r Run,
        command: &mut TkCommand,
        keys: &[&str],
        paths: Vec<String>,
        start_args: &[&str],
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

    pub(crate) fn fingerprints(&self) -> &Value {
        &self.started["keys"]
    }

    pub(crate) fn status(&self) -> Value {
        self.run.ok(self
            .run
            .admin_offline()
            .args(["ssh", "agent", "status"])
            .args(&self.paths))
    }

    /// The `ssh-ed25519 <base64> turnkey:<private-key-id>` lines the agent
    /// advertises, sorted.
    pub(crate) fn listed_keys(&self, ssh_add: &Path) -> Vec<String> {
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
    pub(crate) fn sign(&self, ssh_keygen: &Path, public_key_path: &Path, payload: &Path) -> Output {
        self.sign_in(ssh_keygen, "git", public_key_path, payload)
    }

    pub(crate) fn sign_in(
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

    pub(crate) fn stop(self) -> Value {
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

pub(crate) fn agent_paths(run: &Run, name: &str) -> (PathBuf, PathBuf) {
    let dir = run.home().join("agent");
    (
        dir.join(format!("{name}.sock")),
        dir.join(format!("{name}.pid")),
    )
}

pub(crate) fn public_key_file(run: &Run, name: &str, registered: &Value) -> PathBuf {
    let path = run.home().join(name);
    fs::write(&path, format!("{}\n", text(&registered["publicKey"]))).unwrap();
    path
}

/// The line the agent should advertise for a registered key: its OpenSSH
/// public key followed by the comment naming the Turnkey private key.
pub(crate) fn advertised(registered: &Value, private_key_id: &str) -> String {
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
        skip("the SSH agent test: ssh-add or ssh-keygen is not on PATH");
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
    let agent = Agent::start(&run, &mut run.admin(), &[], None);
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

    let askpass = run.home().join("askpass");
    fs::write(
        &askpass,
        r#"#!/bin/sh
echo passphrase
"#,
    )
    .unwrap();
    fs::set_permissions(&askpass, fs::Permissions::from_mode(0o755)).unwrap();

    let refuses = |ssh_add_args: &[&OsStr]| {
        let output = Command::new(&ssh_add)
            .args(ssh_add_args)
            .env("SSH_AUTH_SOCK", &agent.socket)
            .env("SSH_ASKPASS", &askpass)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .output()
            .expect("ssh-add should run");
        assert!(
            !output.status.success(),
            "the agent accepted ssh-add {ssh_add_args:?}"
        );
    };

    refuses(&["-D".as_ref()]);
    refuses(&["-d".as_ref(), second_public_key.as_os_str()]);
    refuses(&[run.home().join("unregistered_ed25519").as_os_str()]);
    refuses(&["-x".as_ref()]);
    assert_eq!(
        agent.listed_keys(&ssh_add),
        sorted(vec![
            advertised(&first, &first_id),
            advertised(&second, &second_id)
        ])
    );

    // A second start is refused while the first agent holds the socket.
    let duplicate = run.err(run.admin().args(["ssh", "agent", "start"]));
    assert_eq!(duplicate["code"], "command_error");
    assert_eq!(
        duplicate["message"],
        format!("ssh-agent is already running on {}", agent.socket.display())
    );

    // A second agent given only a socket keeps its pid file beside that socket.
    let beside_socket = run.home().join("agent/beside.sock");
    let beside_pid_file = run.home().join("agent/beside.sock.pid");
    let beside = Agent::spawn(
        &run,
        &mut run.admin(),
        &[],
        vec!["--socket".to_string(), beside_socket.display().to_string()],
        &[],
    );
    assert_eq!(beside.socket, beside_socket);
    assert!(beside_pid_file.exists());
    assert_eq!(
        beside.status(),
        json!({
            "reason": "agent_status_report",
            "pid": beside.started["pid"],
            "socket": beside.started["socket"],
            "socketMode": "600",
            "keys": expected_fingerprints,
        })
    );
    assert_eq!(beside.stop(), json!({"reason": "agent_stopped"}));
    assert!(!beside_pid_file.exists());

    // An explicit pid file overrides the one beside the socket.
    let explicit_socket = run.home().join("agent/explicit.sock");
    let explicit_pid_file = run.home().join("agent/explicit-custom.pid");
    let explicit = Agent::start(
        &run,
        &mut run.admin(),
        &[],
        Some((&explicit_socket, &explicit_pid_file)),
    );
    assert_eq!(
        explicit.started,
        json!({
            "reason": "agent_started",
            "pid": explicit.started["pid"],
            "socket": explicit_socket.display().to_string(),
            "socketMode": "600",
            "keys": expected_fingerprints,
        })
    );
    assert!(explicit_pid_file.exists());
    assert!(!run.home().join("agent/explicit.sock.pid").exists());
    assert_eq!(
        explicit.status(),
        json!({
            "reason": "agent_status_report",
            "pid": explicit.started["pid"],
            "socket": explicit.started["socket"],
            "socketMode": "600",
            "keys": expected_fingerprints,
        })
    );
    assert_eq!(explicit.stop(), json!({"reason": "agent_stopped"}));
    assert!(!explicit_pid_file.exists());
    assert_eq!(agent.status(), status);

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
    let removed = run.human_stdout(remove.args(["ssh", "keys", "remove", "--key", &first_id]));
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
    let restarted = Agent::start(&run, &mut run.admin(), &[], None);
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
        skip("the SSH agent narrowing test: ssh-add or ssh-keygen is not on PATH");
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
    let (socket, pid_file) = agent_paths(&run, "narrowed");
    let paths = Some((socket.as_path(), pid_file.as_path()));
    let unregistered = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // A named key serves only that key, by fingerprint or private key ID.
    let narrowed = Agent::start(&run, &mut run.admin(), &[&first_fingerprint], paths);
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
        paths,
    );
    assert_eq!(by_id.fingerprints(), &json!([second_fingerprint]));
    assert_eq!(by_id.stop(), json!({"reason": "agent_stopped"}));

    // Every failure below is reported before a socket or pid file exists.
    let no_agent = |record: Value, code: &str, message: String| {
        assert_eq!(record["code"], code, "{record}");
        assert_eq!(record["message"], message, "{record}");
        assert!(!socket.exists(), "a failed start left {}", socket.display());
        assert!(
            !pid_file.exists(),
            "a failed start left {}",
            pid_file.display()
        );
    };
    let path_args = vec![
        "--socket".to_string(),
        socket.display().to_string(),
        "--pid-file".to_string(),
        pid_file.display().to_string(),
    ];
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
    let profiled = Agent::start(&run, run.cli().args(["--profile", &login.name]), &[], paths);
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
    run.ok(run.cli().args([
        "profile",
        "set",
        "--profile-name",
        &login.name,
        "--organization-id",
        &nil,
    ]));
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
        .args(["ssh", "keys", "remove", "--key", &first_id]));
    run.ok(run
        .admin_offline()
        .args(["ssh", "keys", "remove", "--key", &second_id]));
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
    let (_, agent_id, agent_key) = run.create_agent();
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
    run.allow_user_signing(
        "agents-sign-ssh",
        &agent_id,
        SignScope::PrivateKey(&served_id),
    );
    let payload = run.home().join("payload.txt");
    fs::write(&payload, b"signed through the agent's tk ssh agent\n").unwrap();
    let signature = run.home().join("payload.txt.sig");
    let (socket, pid_file) = agent_paths(&run, "ssh");
    let paths = Some((socket.as_path(), pid_file.as_path()));

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
        paths,
        &["--socket-mode", "660"],
    );
    assert_eq!(
        fs::metadata(&agent.socket).unwrap().permissions().mode() & 0o777,
        0o660
    );
    let advertised_keys = sorted(vec![
        advertised(&served, &served_id),
        advertised(&unserved, &unserved_id),
    ]);
    assert_eq!(agent.listed_keys(&ssh_add), advertised_keys);
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

    let (_, outsider_key) = run.create_tagged_user("agent-outsider", AGENT_TAG);
    let (outsider_socket, outsider_pid_file) = agent_paths(&run, "outsider");
    let outsider = Agent::start(
        &run,
        &mut run.as_user(&outsider_key),
        &[],
        Some((&outsider_socket, &outsider_pid_file)),
    );
    assert_eq!(outsider.listed_keys(&ssh_add), advertised_keys);
    let refused = outsider.sign(&ssh_keygen, &served_public_key, &payload);
    assert!(
        !refused.status.success(),
        "a same-tag user outside the policy consensus signed"
    );
    assert!(!signature.exists());
    assert_eq!(outsider.stop(), json!({"reason": "agent_stopped"}));

    let profile = run.name("agent");
    run.login_as(&profile, &agent_key);
    let (profiled_socket, profiled_pid_file) = agent_paths(&run, "profiled");
    let profiled = Agent::start(
        &run,
        run.cli().args(["--profile", &profile]),
        &[],
        Some((&profiled_socket, &profiled_pid_file)),
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
        .args([
            "profile",
            "set",
            "--profile-name",
            &profile,
            "--api-key-file",
        ])
        .arg(&next_key_file));

    let old_id = run.api_key_id(&agent_id, &hex::encode(agent_key.compressed_public_key()));
    let deleted = run.submit(
        run.admin()
            .args(["api-key", "delete", "--user-id", &agent_id, "--id", &old_id]),
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

    run.ok(run
        .cli()
        .args(["profile", "delete", "--profile-name", &profile]));
    let unselected = profiled.sign(&ssh_keygen, &served_public_key, &payload);
    assert!(
        !unselected.status.success(),
        "a daemon whose profile was deleted still signed"
    );
    assert!(!signature.exists());
    assert_eq!(profiled.stop(), json!({"reason": "agent_stopped"}));
}
