use std::env;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{self, Stdio};
use std::str;

use assert_cmd::Command;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::policy_helpers::SignScope;
use crate::run::{AdminLogin, Run, result, signed_commit};

const USER_ID: &str = "tk e2e <tk-e2e@example.com>";
const SECOND_USER_ID: &str = "tk e2e second <tk-e2e-2@example.com>";

fn locate(binary: &str) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|dir| dir.join(binary))
            .find(|candidate| candidate.is_file())
    })
}

/// Creating a key also registers it in the run's registry.
fn create_key_with(run: &Run, cli: &mut Command, wallet: &str, user_id: &str) -> Value {
    let created = run.ok_created_or_reregistered(
        cli.args([
            "gpg",
            "keys",
            "create",
            "--wallet-id",
            wallet,
            "--user-id",
            user_id,
        ]),
        "gpg_key_created",
        "gpg_key_registered",
    );
    assert_eq!(created["organizationId"], run.org());
    assert_eq!(created["walletId"], wallet);
    assert_eq!(created["userId"], user_id);
    let fingerprint = created["fingerprint"].as_str().unwrap();
    assert_eq!(fingerprint.len(), 40);
    assert!(
        fingerprint
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())
    );
    assert!(created["created"].as_u64().unwrap() > 1_700_000_000);
    created
}

pub(crate) fn create_key(run: &Run, wallet: &str, user_id: &str) -> Value {
    create_key_with(run, &mut run.admin(), wallet, user_id)
}

pub(crate) fn add_key(run: &Run, cli: &mut Command, wallet: &str, key: &str) -> Value {
    let added = run.ok(cli.args(["gpg", "keys", "add", "--wallet-id", wallet, "--key", key]));
    assert_eq!(added["reason"], "gpg_key_registered", "{added}");
    added
}

fn registered(run: &Run, wallet: &str, created: &Value, account_id: &str) -> Value {
    json!({
        "fingerprint": created["fingerprint"],
        "userId": created["userId"],
        "organizationId": run.org(),
        "walletId": wallet,
        "walletAccountId": account_id,
        "created": created["created"],
    })
}

pub(crate) fn import_public_key(
    run: &Run,
    gpg: &Path,
    home: &Path,
    fingerprint: &str,
    armored: &str,
) -> PathBuf {
    let gnupghome = home.join("gnupg");
    fs::create_dir(&gnupghome).unwrap();
    fs::set_permissions(&gnupghome, fs::Permissions::from_mode(0o700)).unwrap();
    let public_key = home.join(format!("{fingerprint}.asc"));
    fs::write(&public_key, armored).unwrap();
    let staged = process::Command::new(gpg)
        .env_clear()
        .env("GNUPGHOME", &gnupghome)
        .args([
            "--batch",
            "--with-colons",
            "--import-options",
            "show-only",
            "--import",
        ])
        .arg(&public_key)
        .output()
        .unwrap();
    let staging = String::from_utf8_lossy(&staged.stdout);
    let lines: Vec<&str> = staging.lines().collect();
    let records = |prefix: &str| lines.iter().filter(|line| line.starts_with(prefix)).count();
    let primary_fingerprint = lines
        .iter()
        .position(|line| line.starts_with("pub:"))
        .and_then(|index| lines.get(index + 1))
        .is_some_and(|line| *line == format!("fpr:::::::::{fingerprint}:"));
    assert!(
        staged.status.success()
            && records("pub:") == 1
            && records("sec:") == 0
            && records("ssb:") == 0
            && primary_fingerprint,
        "staged armor is not exactly one public key {fingerprint}: {staging}{}",
        run.redact(&staged.stderr)
    );
    let imported = process::Command::new(gpg)
        .env_clear()
        .env("GNUPGHOME", &gnupghome)
        .args(["--batch", "--import"])
        .arg(&public_key)
        .output()
        .unwrap();
    assert!(
        imported.status.success(),
        "GnuPG import failed: {}",
        run.redact(&imported.stderr)
    );
    let listed = process::Command::new(gpg)
        .env_clear()
        .env("GNUPGHOME", &gnupghome)
        .args(["--batch", "--with-colons", "--list-keys", fingerprint])
        .output()
        .unwrap();
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(
        listed.status.success()
            && listing
                .lines()
                .any(|line| line == format!("fpr:::::::::{fingerprint}:")),
        "imported key does not list fingerprint {fingerprint}: {listing}{}",
        run.redact(&listed.stderr)
    );
    gnupghome
}

fn create_wallet(run: &Run, label: &str, accounts: Value) -> String {
    let created = run.submit(
        run.admin().args([
            "wallet",
            "create",
            "--input-json",
            &json!({"walletName": run.name(label), "accounts": accounts}).to_string(),
        ]),
        "wallet.create",
    );
    result(&created, "createWalletResult")["walletId"]
        .as_str()
        .unwrap()
        .to_string()
}

pub(crate) fn create_occupied_wallet(run: &Run) -> String {
    create_wallet(
        run,
        "gpg-wallet",
        json!([{
            "curve": "CURVE_SECP256K1",
            "pathFormat": "PATH_FORMAT_BIP32",
            "path": "m/5261136'/0'/0'/0'",
            "addressFormat": "ADDRESS_FORMAT_ETHEREUM",
        }]),
    )
}

pub(crate) fn openpgp_config(
    program: &Path,
    signing_key: Option<&str>,
    command: &mut process::Command,
) {
    command
        .args(["-c", "gpg.format=openpgp"])
        .arg("-c")
        .arg(format!("gpg.program={}", program.display()));
    if let Some(key) = signing_key {
        command.arg("-c").arg(format!("user.signingkey={key}"));
    }
}

fn wallet_accounts(run: &Run, wallet: &str) -> Vec<Value> {
    let accounts = run.ok(run
        .admin()
        .args(["wallet", "account", "list", "--wallet-id", wallet]));
    let mut accounts = accounts["data"]["accounts"].as_array().unwrap().clone();
    accounts.sort_by_key(|account| account["path"].as_str().unwrap().to_string());
    accounts
}

#[test]
#[ignore]
fn gpg_keys_create_list_export_sign_remove_and_add() {
    let run = Run::new();
    let wallet = create_occupied_wallet(&run);

    let created = create_key(&run, &wallet, USER_ID);
    assert_eq!(
        created["keyIndex"], 1,
        "index 0 is occupied by the Ethereum account"
    );
    let fingerprint = created["fingerprint"].as_str().unwrap().to_string();

    let second = create_key(&run, &wallet, SECOND_USER_ID);
    assert_eq!(second["keyIndex"], 2);
    let second_fingerprint = second["fingerprint"].as_str().unwrap().to_string();

    let accounts = wallet_accounts(&run, &wallet);
    let paths: Vec<&str> = accounts
        .iter()
        .map(|account| account["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        paths,
        [
            "m/5261136'/0'/0'/0'",
            "m/5261136'/0'/1'/0'",
            "m/5261136'/0'/2'/0'"
        ]
    );
    let account_id = accounts[1]["walletAccountId"].as_str().unwrap();
    let second_account_id = accounts[2]["walletAccountId"].as_str().unwrap();

    let listed = run.ok(run
        .admin()
        .args(["gpg", "keys", "list", "--wallet-id", &wallet]));
    assert_eq!(
        listed,
        json!({
            "reason": "gpg_keys_listed",
            "walletId": wallet,
            "keys": [
                {"keyIndex": 1, "fingerprint": fingerprint, "userId": USER_ID, "created": created["created"]},
                {"keyIndex": 2, "fingerprint": second_fingerprint, "userId": SECOND_USER_ID, "created": second["created"]},
            ],
        })
    );

    let mut expected = vec![
        registered(&run, &wallet, &created, account_id),
        registered(&run, &wallet, &second, second_account_id),
    ];
    expected.sort_by_key(|key| key["fingerprint"].as_str().unwrap().to_string());
    let registry = run.ok(run.admin_offline().args(["gpg", "keys", "list"]));
    assert_eq!(
        registry,
        json!({"reason": "gpg_keys_registered", "keys": expected})
    );

    let ambiguous = run.err(run.admin_offline().args(["gpg", "keys", "export"]));
    assert_eq!(ambiguous["code"], "invalid_input");

    let exported = run.ok(run
        .admin()
        .args(["gpg", "keys", "export", "--key", &fingerprint]));
    let again = run.ok(run.admin().args([
        "gpg",
        "keys",
        "export",
        "--key",
        &fingerprint[24..].to_ascii_lowercase(),
    ]));
    assert_eq!(exported, again, "export must be byte stable");
    assert_eq!(exported["fingerprint"], fingerprint);
    let armored = exported["armored"].as_str().unwrap();
    assert!(armored.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"));
    assert!(armored.ends_with("-----END PGP PUBLIC KEY BLOCK-----\n"));

    let payload = run.home.path().join("payload.txt");
    fs::write(&payload, b"signed by the tk e2e suite\n").unwrap();
    let signed = run.ok(run
        .admin()
        .args(["gpg", "sign", "--key", &fingerprint, "--file"])
        .arg(&payload));
    assert_eq!(signed["reason"], "gpg_signature_created");
    assert_eq!(signed["fingerprint"], fingerprint);
    assert_eq!(signed["output"], Value::Null);
    let signature = signed["armored"].as_str().unwrap();
    assert!(signature.starts_with("-----BEGIN PGP SIGNATURE-----\n"));

    let removed =
        run.ok(run
            .admin_offline()
            .args(["gpg", "keys", "remove", "--key", &second_fingerprint]));
    let mut expected_removed = registered(&run, &wallet, &second, second_account_id);
    expected_removed["reason"] = json!("gpg_key_removed");
    assert_eq!(removed, expected_removed);
    let one = run.ok(run.admin_offline().args(["gpg", "keys", "list"]));
    assert_eq!(
        one,
        json!({
            "reason": "gpg_keys_registered",
            "keys": [registered(&run, &wallet, &created, account_id)],
        })
    );
    let unnamed = run.ok(run.admin().args(["gpg", "sign", "--file"]).arg(&payload));
    assert_eq!(unnamed["fingerprint"], fingerprint);
    assert_eq!(wallet_accounts(&run, &wallet).len(), 3);

    let added = add_key(&run, &mut run.admin(), &wallet, &second_fingerprint);
    assert_eq!(
        added,
        json!({
            "reason": "gpg_key_registered",
            "organizationId": run.org(),
            "walletId": wallet,
            "keyIndex": 2,
            "fingerprint": second_fingerprint,
            "userId": SECOND_USER_ID,
            "created": second["created"],
        })
    );
    let both = run.ok(run.admin_offline().args(["gpg", "keys", "list"]));
    assert_eq!(
        both,
        json!({"reason": "gpg_keys_registered", "keys": expected})
    );

    let Some(gpg) = locate("gpg") else {
        eprintln!("skipping GnuPG verification: gpg is not on PATH");
        return;
    };
    let gnupghome = import_public_key(&run, &gpg, run.home.path(), &fingerprint, armored);
    let signature_file = run.home.path().join("payload.txt.asc");
    fs::write(&signature_file, signature).unwrap();
    let verified = process::Command::new(&gpg)
        .env("GNUPGHOME", &gnupghome)
        .args(["--batch", "--verify"])
        .arg(&signature_file)
        .arg(&payload)
        .status()
        .unwrap();
    assert!(verified.success(), "GnuPG rejected the tk signature");
}

#[test]
#[ignore]
fn gpg_key_organization_selects_the_profile() {
    let run = Run::new();
    let wallet = create_occupied_wallet(&run);
    let AdminLogin { record: login, .. } = run.login_admin();
    assert_eq!(login["command"], "auth.login");

    let created = create_key_with(&run, &mut run.cli(), &wallet, USER_ID);
    let fingerprint = created["fingerprint"].as_str().unwrap().to_string();

    let logout = run.ok(run.cli().args(["auth", "logout"]));
    assert_eq!(logout["command"], "auth.logout");
    let no_identity = run.err(run.cli().args(["auth", "whoami"]));
    assert_eq!(no_identity["code"], "invalid_input");

    let payload = run.home.path().join("payload.txt");
    fs::write(&payload, b"signed through the key's organization\n").unwrap();
    let signed = run.ok(run.cli().args(["gpg", "sign", "--file"]).arg(&payload));
    assert_eq!(signed["reason"], "gpg_signature_created");
    assert_eq!(signed["fingerprint"], fingerprint);

    let mismatched = run.err(
        run.cli()
            .args([
                "--organization-id",
                &Uuid::nil().to_string(),
                "gpg",
                "sign",
                "--file",
            ])
            .arg(&payload),
    );
    assert_eq!(mismatched["code"], "invalid_input");
}

#[test]
#[ignore]
fn gpg_shim_signs_and_git_verifies() {
    let (Some(gpg), Some(git)) = (locate("gpg"), locate("git")) else {
        eprintln!("skipping the git shim test: gpg or git is not on PATH");
        return;
    };
    let run = Run::new();
    let wallet = create_occupied_wallet(&run);
    let created = create_key(&run, &wallet, USER_ID);
    let fingerprint = created["fingerprint"].as_str().unwrap().to_string();
    let exported = run.ok(run.admin().args(["gpg", "keys", "export"]));
    let gnupghome = import_public_key(
        &run,
        &gpg,
        run.home.path(),
        &fingerprint,
        exported["armored"].as_str().unwrap(),
    );

    let shim_env = |cmd: &mut process::Command| {
        run.inherit_environment(run.admin(), cmd);
        cmd.env("GNUPGHOME", &gnupghome);
    };

    let mut shim = process::Command::new(env!("CARGO_BIN_EXE_tk"));
    shim_env(&mut shim);
    let output = shim
        .args(["--status-fd=2", "-bsau", &fingerprint])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.take().unwrap().write_all(b"hello from git\n")?;
            child.wait_with_output()
        })
        .unwrap();
    for (stream, raw) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
        assert_eq!(
            run.redact(raw),
            String::from_utf8_lossy(raw),
            "private key leaked to the shim's {stream}"
        );
    }
    assert!(output.status.success(), "{}", run.redact(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("-----BEGIN PGP SIGNATURE-----\n"));
    let status_lines: Vec<&str> = str::from_utf8(&output.stderr).unwrap().lines().collect();
    assert_eq!(status_lines.len(), 2);
    assert_eq!(status_lines[0], "[GNUPG:] BEGIN_SIGNING");
    let sig_created = status_lines[1];
    assert!(sig_created.starts_with("[GNUPG:] SIG_CREATED D 19 8 00 "));
    assert!(sig_created.ends_with(&fingerprint));

    let repo = run.home.path().join("repo");
    fs::create_dir(&repo).unwrap();
    let tk = Path::new(env!("CARGO_BIN_EXE_tk"));
    let openpgp = |signing_key: Option<&str>, cmd: &mut process::Command| {
        shim_env(cmd);
        openpgp_config(tk, signing_key, cmd);
    };
    let unnamed = |cmd: &mut process::Command| openpgp(None, cmd);
    run.git_ok(&git, &repo, unnamed, &["init", "--quiet"]);
    run.git_ok(
        &git,
        &repo,
        |cmd| openpgp(Some(&fingerprint), cmd),
        &signed_commit("signed by tk"),
    );
    run.git_ok(&git, &repo, unnamed, &["verify-commit", "HEAD"]);

    // With user.signingkey unset, git names the committer ident, which is
    // the key's user ID, so the same key signs.
    run.git_ok(&git, &repo, unnamed, &signed_commit("signed by user id"));
    run.git_ok(&git, &repo, unnamed, &["verify-commit", "HEAD"]);

    let other = "FEDCBA9876543210FEDCBA9876543210FEDCBA98";
    let refused = Run::git(
        &git,
        &repo,
        |cmd| openpgp(Some(other), cmd),
        &signed_commit("refused"),
    );
    assert!(
        !refused.status.success(),
        "git signed with a key it did not name"
    );
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains(&format!(
            "no OpenPGP key in the registry matches signing key {other}; set user.signingkey to the key fingerprint"
        )),
        "{}",
        run.redact(&refused.stderr)
    );
}

#[test]
#[ignore]
fn signing_git_commits_gpg_with_scoped_policy() {
    let gpg = locate("gpg").expect("gpg must be on PATH: the signing-git-commits gate needs GnuPG");
    let git = locate("git").expect("git must be on PATH: the signing-git-commits gate needs git");
    let run = Run::new();
    let (_, agent_id, agent) = run.create_agent();
    let wallet = create_wallet(&run, "gpg", json!([]));
    let other_wallet = create_wallet(&run, "gpg-outside-scope", json!([]));
    run.allow_user_signing("agents-sign-gpg", &agent_id, SignScope::Wallet(&wallet));

    let created = create_key(&run, &wallet, USER_ID);
    let fingerprint = created["fingerprint"].as_str().unwrap().to_string();
    let rerun = run.ok(run.admin().args([
        "gpg",
        "keys",
        "create",
        "--wallet-id",
        &wallet,
        "--user-id",
        USER_ID,
    ]));
    assert_eq!(
        rerun,
        json!({
            "reason": "gpg_key_registered",
            "organizationId": run.org(),
            "walletId": wallet,
            "keyIndex": created["keyIndex"],
            "fingerprint": fingerprint,
            "userId": USER_ID,
            "created": created["created"],
        }),
        "rerunning create with a user ID the wallet holds registers that key"
    );
    let other = create_key(&run, &other_wallet, SECOND_USER_ID);
    let other_fingerprint = other["fingerprint"].as_str().unwrap().to_string();

    let added = add_key(&run, &mut run.as_user(&agent), &wallet, &fingerprint);
    assert_eq!(
        added,
        json!({
            "reason": "gpg_key_registered",
            "organizationId": run.org(),
            "walletId": wallet,
            "keyIndex": created["keyIndex"],
            "fingerprint": fingerprint,
            "userId": USER_ID,
            "created": created["created"],
        })
    );
    let exported =
        run.ok(run
            .as_user(&agent)
            .args(["gpg", "keys", "export", "--key", &fingerprint]));
    assert_eq!(exported["fingerprint"], fingerprint, "{exported}");
    let gnupghome = import_public_key(
        &run,
        &gpg,
        run.home.path(),
        &fingerprint,
        exported["armored"].as_str().unwrap(),
    );

    add_key(
        &run,
        &mut run.as_user(&agent),
        &other_wallet,
        &other_fingerprint,
    );
    run.err_unauthorized(run.as_user(&agent).args([
        "gpg",
        "keys",
        "export",
        "--key",
        &other_fingerprint,
    ]));
    let payload = run.home.path().join("payload.txt");
    fs::write(&payload, b"outside the policy scope\n").unwrap();
    run.err_unauthorized(
        run.as_user(&agent)
            .args(["gpg", "sign", "--key", &other_fingerprint, "--file"])
            .arg(&payload),
    );

    let openpgp = |home: &Path, program: &Path, cmd: &mut process::Command| {
        run.inherit_environment(run.as_user(&agent), cmd);
        cmd.env("HOME", home).env("GNUPGHOME", &gnupghome);
        openpgp_config(program, Some(&fingerprint), cmd);
    };
    let commit = signed_commit("signed by tk");
    let tk = Path::new(env!("CARGO_BIN_EXE_tk"));

    let repo = run.home.path().join("repo");
    fs::create_dir(&repo).unwrap();
    let own_home = |cmd: &mut process::Command| openpgp(run.home.path(), tk, cmd);
    run.git_ok(&git, &repo, own_home, &["init", "--quiet"]);
    run.git_ok(&git, &repo, own_home, &commit);
    run.git_ok(&git, &repo, own_home, &["verify-commit", "HEAD"]);

    let other_home = run.home.path().join("other-home");
    fs::create_dir(&other_home).unwrap();
    let other_repo = other_home.join("repo");
    fs::create_dir(&other_repo).unwrap();
    let no_registry = |cmd: &mut process::Command| openpgp(&other_home, tk, cmd);
    run.git_ok(&git, &other_repo, no_registry, &["init", "--quiet"]);
    let unregistered = Run::git(&git, &other_repo, no_registry, &commit);
    assert!(
        !unregistered.status.success(),
        "git signed from a HOME with no registry"
    );
    let wrapper = run.home.path().join("tk-wrapper.sh");
    fs::write(
        &wrapper,
        format!(
            r#"#!/bin/sh
export HOME='{}'
exec '{}' "$@"
"#,
            run.home.path().display(),
            tk.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
    let wrapped = |cmd: &mut process::Command| openpgp(&other_home, &wrapper, cmd);
    run.git_ok(&git, &other_repo, wrapped, &commit);
    run.git_ok(&git, &other_repo, wrapped, &["verify-commit", "HEAD"]);
}
