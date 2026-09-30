//! Live SSH agent destination constraints: allowed hosts, namespaces, and forwarding.

use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
};

use serde_json::{Value, json};

use crate::{
    run::{Run, skip},
    ssh::{check_signature, create_ed25519_key, generate_local_key, locate, register_key},
    ssh_agent::{Agent, advertised, agent_paths, public_key_file},
};

struct Tools {
    sshd: PathBuf,
    ssh: PathBuf,
    ssh_keygen: PathBuf,
}

impl Tools {
    fn locate(test: &str) -> Option<Self> {
        let (Some(sshd), Some(ssh), Some(ssh_keygen)) =
            (locate("sshd"), locate("ssh"), locate("ssh-keygen"))
        else {
            skip(format_args!(
                "the {test}: sshd, ssh, or ssh-keygen is not on PATH"
            ));
            return None;
        };

        if !client_supports_session_bind(&ssh) {
            skip(format_args!("the {test}: ssh is older than OpenSSH 8.9"));
            return None;
        }

        Some(Self {
            sshd,
            ssh,
            ssh_keygen,
        })
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

fn shell_words<S: AsRef<str>>(words: impl IntoIterator<Item = S>) -> String {
    words
        .into_iter()
        .map(|word| format!("'{}'", word.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

struct Sshd {
    child: Option<Child>,
    log: PathBuf,
    port: u16,
    user: String,
    identity: PathBuf,
    known_hosts: PathBuf,
    host_line: String,
}

impl Sshd {
    fn start(run: &Run, tools: &Tools, host_key_type: &str, identity: &Path) -> Self {
        let host_key = run.home().join(format!("host_{host_key_type}"));
        let host_public_key = generate_local_key(&tools.ssh_keygen, &host_key, host_key_type);
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };

        let authorized_keys = run.home().join(format!("authorized_keys_{host_key_type}"));
        fs::copy(identity, &authorized_keys).unwrap();
        let log = run.home().join(format!("sshd_{host_key_type}.log"));
        let config = run.home().join(format!("sshd_config_{host_key_type}"));
        fs::write(
            &config,
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
AllowAgentForwarding yes
LogLevel VERBOSE
"#,
                host_key.display(),
                run.home()
                    .join(format!("sshd_{host_key_type}.pid"))
                    .display(),
                authorized_keys.display(),
            ),
        )
        .unwrap();

        let mut sshd = Self {
            child: Some(
                Command::new(&tools.sshd)
                    .arg("-D")
                    .arg("-f")
                    .arg(&config)
                    .arg("-E")
                    .arg(&log)
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("sshd should spawn"),
            ),
            log,
            port,
            user: String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
                .unwrap()
                .trim()
                .to_string(),
            identity: identity.to_path_buf(),
            known_hosts: run.home().join(format!("known_hosts_{host_key_type}")),
            host_line: known_hosts_line(&format!("[127.0.0.1]:{port}"), &host_public_key),
        };

        run.wait_for_child_port(&mut sshd.child, port, "sshd", "listening on its port");
        fs::write(&sshd.known_hosts, format!("{}\n", sshd.host_line)).unwrap();
        sshd
    }

    fn client_options(&self) -> Vec<String> {
        [
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
        ]
        .map(String::from)
        .into_iter()
        .chain([
            "-o".to_string(),
            format!("UserKnownHostsFile={}", self.known_hosts.display()),
            "-o".to_string(),
            format!("IdentityFile={}", self.identity.display()),
            "-p".to_string(),
            self.port.to_string(),
        ])
        .collect()
    }

    fn destination(&self) -> String {
        format!("{}@127.0.0.1", self.user)
    }

    fn login(&self, ssh: &Path, agent: &Agent<'_>, options: &[&str], remote: &str) -> Output {
        Command::new(ssh)
            .args(self.client_options())
            .args(options)
            .arg(self.destination())
            .arg(remote)
            .env("SSH_AUTH_SOCK", &agent.socket)
            .output()
            .expect("ssh should run")
    }

    fn assert_logged_in(&self, output: &Output, context: &str) {
        assert!(
            output.status.success(),
            "{context}: {}\nsshd: {}",
            String::from_utf8_lossy(&output.stderr),
            fs::read_to_string(&self.log).unwrap_or_default()
        );
    }
}

impl Drop for Sshd {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn served_key() -> (Run, String, Value, PathBuf) {
    let run = Run::new();
    let key_id = create_ed25519_key(&run);
    let registered = register_key(&run, &mut run.admin(), &key_id);
    let public_key = public_key_file(&run, "served.pub", &registered);
    (run, key_id, registered, public_key)
}

fn ed25519_sshd(test: &str) -> Option<(Tools, Run, PathBuf, Sshd)> {
    let tools = Tools::locate(test)?;
    let (run, _, _, public_key) = served_key();
    let sshd = Sshd::start(&run, &tools, "ed25519", &public_key);
    Some((tools, run, public_key, sshd))
}

fn start_allowing<'r>(run: &'r Run, name: &str, host_line: &str, start_args: &[&str]) -> Agent<'r> {
    let allowed_hosts = run.home().join(format!("{name}-hosts"));
    fs::write(&allowed_hosts, format!("{host_line}\n")).unwrap();

    let (socket, _) = agent_paths(run, name);
    let allowed_hosts = allowed_hosts.display().to_string();
    let start_args = [
        &["--allowed-hosts-file", allowed_hosts.as_str()],
        start_args,
    ]
    .concat();
    Agent::spawn(
        run,
        &mut run.admin(),
        &[],
        vec!["--socket".to_string(), socket.display().to_string()],
        &start_args,
    )
}

#[test]
#[ignore]
fn constrained_agent_signs_only_allowed_namespaces_and_reports_them() {
    let (Some(ssh_add), Some(ssh_keygen)) = (locate("ssh-add"), locate("ssh-keygen")) else {
        skip("the SSH agent constraints test: ssh-add or ssh-keygen is not on PATH");
        return;
    };
    let (run, key_id, registered, public_key) = served_key();
    let payload = run.home().join("payload.txt");
    fs::write(&payload, b"signed under a destination constraint\n").unwrap();
    let signature = run.home().join("payload.txt.sig");
    let host_key = generate_local_key(&ssh_keygen, &run.home().join("host_ed25519"), "ed25519");

    let agent = start_allowing(
        &run,
        "constrained",
        &known_hosts_line("github.com", &host_key),
        &["--allow-namespace", "git"],
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
    let Some((tools, run, _, sshd)) = ed25519_sshd("SSH agent userauth test") else {
        return;
    };

    let git_only = ["--allow-namespace", "git"];
    let allowed = start_allowing(&run, "allowed", &sshd.host_line, &git_only);
    let accepted = sshd.login(&tools.ssh, &allowed, &[], "true");
    sshd.assert_logged_in(&accepted, "ssh to an allowed host failed");
    assert_eq!(allowed.stop(), json!({"reason": "agent_stopped"}));

    let decoy = generate_local_key(
        &tools.ssh_keygen,
        &run.home().join("decoy_ed25519"),
        "ed25519",
    );
    let refused_agent = start_allowing(
        &run,
        "decoy",
        &known_hosts_line("github.com", &decoy),
        &git_only,
    );
    let refused = sshd.login(&tools.ssh, &refused_agent, &[], "true");
    assert!(
        !refused.status.success(),
        "the agent signed for a host key outside its allowed hosts"
    );
    assert_eq!(refused_agent.stop(), json!({"reason": "agent_stopped"}));
}

#[test]
#[ignore]
fn constrained_agent_refuses_a_forwarded_hop() {
    let Some(ssh_add) = locate("ssh-add") else {
        skip("the SSH agent forwarding test: ssh-add is not on PATH");
        return;
    };
    let Some((tools, run, public_key, sshd)) = ed25519_sshd("SSH agent forwarding test") else {
        return;
    };
    let payload = run.home().join("payload.txt");
    fs::write(&payload, b"signed through a forwarded agent\n").unwrap();
    let signature = run.home().join("payload.txt.sig");

    // The remote side reaches the agent through the forwarded
    // `SSH_AUTH_SOCK` that sshd sets.
    let list = shell_words([&ssh_add.display().to_string(), "-L"]);
    let hop = shell_words(
        [tools.ssh.display().to_string()]
            .into_iter()
            .chain(sshd.client_options())
            .chain([sshd.destination(), "true".to_string()]),
    );
    let sign = shell_words([
        &tools.ssh_keygen.display().to_string(),
        "-Y",
        "sign",
        "-n",
        "git",
        "-U",
        "-f",
        &public_key.display().to_string(),
        &payload.display().to_string(),
    ]);
    let remote = format!("{list}; echo $?; {hop} >/dev/null; echo $?; {sign} >/dev/null; echo $?");

    for (name, start_args) in [
        ("forwarded", &[][..]),
        ("forwarded-git", &["--allow-namespace", "git"][..]),
    ] {
        let agent = start_allowing(&run, name, &sshd.host_line, start_args);
        let forwarded = sshd.login(&tools.ssh, &agent, &["-A"], &remote);
        sshd.assert_logged_in(
            &forwarded,
            &format!("{name}: the outer login to an allowed host failed"),
        );

        let stdout = String::from_utf8_lossy(&forwarded.stdout);
        let stderr = String::from_utf8_lossy(&forwarded.stderr);
        // OpenSSH 10 sshd binds forwarded agents under the user's real
        // `~/.ssh/agent`, which macOS denies to an unprivileged sshd.
        if stderr.contains("Couldn't get agent socket") {
            assert_eq!(agent.stop(), json!({"reason": "agent_stopped"}));
            skip("the SSH agent forwarding test: sshd could not create the forwarded socket");
            return;
        }
        let mut lines = stdout.lines();
        let listed: Vec<&str> = lines.by_ref().take(2).collect();
        assert_eq!(
            listed,
            ["The agent has no identities.", "1"],
            "{name}: list through the forwarded agent: {stderr}"
        );
        let signed: Vec<bool> = lines.map(|status| status == "0").collect();
        assert_eq!(
            signed,
            [false, false],
            "{name}: hop and sign through the forwarded agent: {stderr}"
        );
        assert!(!signature.exists(), "{name}: a forwarded agent signed");
        assert_eq!(agent.stop(), json!({"reason": "agent_stopped"}));
    }
}

#[test]
#[ignore]
fn unconstrained_agent_answers_session_bind_during_login() {
    let Some((tools, run, _, sshd)) = ed25519_sshd("SSH agent unconstrained login test") else {
        return;
    };
    let (socket, pid_file) = agent_paths(&run, "unconstrained");
    let agent = Agent::start_with(&run, &mut run.admin(), &[], Some((&socket, &pid_file)), &[]);

    let accepted = sshd.login(&tools.ssh, &agent, &[], "true");
    sshd.assert_logged_in(&accepted, "ssh through an unconstrained agent failed");
    assert_eq!(agent.stop(), json!({"reason": "agent_stopped"}));
}

#[test]
#[ignore]
fn constrained_agent_accepts_ecdsa_and_rsa_host_keys() {
    let Some(tools) = Tools::locate("SSH agent host key types test") else {
        return;
    };
    let (run, _, _, public_key) = served_key();

    for (host_key_type, algorithm) in [("ecdsa", "ecdsa-sha2-nistp256"), ("rsa", "rsa-sha2-512")] {
        let sshd = Sshd::start(&run, &tools, host_key_type, &public_key);
        let agent = start_allowing(&run, host_key_type, &sshd.host_line, &[]);
        let host_key_algorithms = format!("HostKeyAlgorithms={algorithm}");
        let accepted = sshd.login(&tools.ssh, &agent, &["-o", &host_key_algorithms], "true");
        sshd.assert_logged_in(
            &accepted,
            &format!("ssh to an allowed {algorithm} host failed"),
        );
        assert_eq!(agent.stop(), json!({"reason": "agent_stopped"}));
    }
}
