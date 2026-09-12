use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::{Value, json};

use crate::run::{Run, result};

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
    let created = run.ok(cli.args([
        "gpg",
        "keys",
        "create",
        "--wallet-id",
        wallet,
        "--user-id",
        user_id,
    ]));
    assert_eq!(created["reason"], "gpg_key_created");
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

fn create_key(run: &Run, wallet: &str, user_id: &str) -> Value {
    create_key_with(run, &mut run.admin(), wallet, user_id)
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

fn import_into_gpg(run: &Run, gpg: &Path, armored: &str) -> PathBuf {
    let gnupghome = run.home.path().join("gnupg");
    fs::create_dir(&gnupghome).unwrap();
    let key_file = run.home.path().join("key.asc");
    fs::write(&key_file, armored).unwrap();
    let imported = std::process::Command::new(gpg)
        .env("GNUPGHOME", &gnupghome)
        .args(["--batch", "--import"])
        .arg(&key_file)
        .status()
        .unwrap();
    assert!(imported.success());
    gnupghome
}

/// The wallet starts with an Ethereum account at OpenPGP key index 0, which
/// `tk gpg` must skip as a key but still count as occupied.
fn create_wallet(run: &Run) -> String {
    let created = run.submit(
        run.admin().args([
            "wallet",
            "create",
            "--input-json",
            &json!({
                "walletName": run.name("gpg-wallet"),
                "accounts": [{
                    "curve": "CURVE_SECP256K1",
                    "pathFormat": "PATH_FORMAT_BIP32",
                    "path": "m/5261136'/0'/0'/0'",
                    "addressFormat": "ADDRESS_FORMAT_ETHEREUM",
                }],
            })
            .to_string(),
        ]),
        "wallet.create",
    );
    result(&created, "createWalletResult")["walletId"]
        .as_str()
        .unwrap()
        .to_string()
}

/// The wallet's accounts, sorted by path.
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
    let wallet = create_wallet(&run);

    let created = create_key(&run, &wallet, USER_ID);
    assert_eq!(
        created["keyIndex"], 1,
        "index 0 is occupied by the Ethereum account"
    );
    let fingerprint = created["fingerprint"].as_str().unwrap().to_string();

    let second = create_key(&run, &wallet, SECOND_USER_ID);
    assert_eq!(second["keyIndex"], 2);
    let second_fingerprint = second["fingerprint"].as_str().unwrap().to_string();

    // One key is one wallet account, at the signing path of its index.
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

    // Both creates registered their keys. The registry lists by fingerprint.
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

    // Two registered keys and no --key is ambiguous, before any request.
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
        .args(["gpg", "sign", "--key", &fingerprint])
        .arg(&payload));
    assert_eq!(signed["reason"], "gpg_signature_created");
    assert_eq!(signed["fingerprint"], fingerprint);
    assert_eq!(signed["output"], Value::Null);
    let signature = signed["armored"].as_str().unwrap();
    assert!(signature.starts_with("-----BEGIN PGP SIGNATURE-----\n"));

    // Forgetting a key leaves its account in the wallet and makes the other
    // key the only one, so sign needs no --key.
    let removed = run.ok(run
        .admin_offline()
        .args(["gpg", "keys", "remove", &second_fingerprint]));
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
    let unnamed = run.ok(run.admin().args(["gpg", "sign"]).arg(&payload));
    assert_eq!(unnamed["fingerprint"], fingerprint);
    assert_eq!(wallet_accounts(&run, &wallet).len(), 3);

    // An existing key is registered again from its wallet.
    let added = run.ok(run.admin().args([
        "gpg",
        "keys",
        "add",
        "--wallet-id",
        &wallet,
        "--key",
        &second_fingerprint,
    ]));
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
    assert_eq!(both["keys"].as_array().unwrap().len(), 2);

    let Some(gpg) = locate("gpg") else {
        eprintln!("skipping GnuPG verification: gpg is not on PATH");
        return;
    };
    let gnupghome = import_into_gpg(&run, &gpg, armored);
    let signature_file = run.home.path().join("payload.txt.asc");
    fs::write(&signature_file, signature).unwrap();
    let verified = std::process::Command::new(&gpg)
        .env("GNUPGHOME", &gnupghome)
        .args(["--batch", "--verify"])
        .arg(&signature_file)
        .arg(&payload)
        .status()
        .unwrap();
    assert!(verified.success(), "GnuPG rejected the tk signature");
}

/// With no explicit identity, the key's organization selects the profile.
#[test]
#[ignore]
fn gpg_key_organization_selects_the_profile() {
    let run = Run::new();
    let wallet = create_wallet(&run);
    let profile = run.name("admin");
    let key_file = run.admin_key_file();
    let org = run.org();

    let login = run.ok(run
        .cli()
        .args([
            "login",
            &profile,
            "--organization-id",
            &org,
            "--api-key-file",
        ])
        .arg(&key_file));
    assert_eq!(login["command"], "auth.login");

    // Created through the active profile, so the entry carries its org.
    let created = create_key_with(&run, &mut run.cli(), &wallet, USER_ID);
    let fingerprint = created["fingerprint"].as_str().unwrap().to_string();

    // With no active profile and no bundle, an ordinary command has no
    // identity, but the registered key still finds the profile for its org.
    let logout = run.ok(run.cli().args(["auth", "logout"]));
    assert_eq!(logout["command"], "auth.logout");
    let no_identity = run.err(run.cli().args(["auth", "whoami"]));
    assert_eq!(no_identity["code"], "invalid_input");

    let payload = run.home.path().join("payload.txt");
    fs::write(&payload, b"signed through the key's organization\n").unwrap();
    let signed = run.ok(run.cli().args(["gpg", "sign"]).arg(&payload));
    assert_eq!(signed["reason"], "gpg_signature_created");
    assert_eq!(signed["fingerprint"], fingerprint);

    // An explicit organization that is not the key's is rejected before any
    // request.
    let mismatched = run.err(
        run.cli()
            .args([
                "--organization-id",
                &uuid::Uuid::nil().to_string(),
                "gpg",
                "sign",
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
    let wallet = create_wallet(&run);
    let created = create_key(&run, &wallet, USER_ID);
    let fingerprint = created["fingerprint"].as_str().unwrap().to_string();
    let exported = run.ok(run.admin().args(["gpg", "keys", "export"]));
    let gnupghome = import_into_gpg(&run, &gpg, exported["armored"].as_str().unwrap());

    // The shim receives no tk flags, so the identity travels in the
    // environment and the key in the registry the create wrote under HOME.
    let shim_env = |cmd: &mut std::process::Command| {
        // Mirror the runner's environment exactly: its removals matter too,
        // since a host RUST_LOG or TK_PROFILE would reach the shim otherwise.
        for (name, value) in run.admin().get_envs() {
            match value {
                Some(value) => cmd.env(name, value),
                None => cmd.env_remove(name),
            };
        }
        // Git reads /etc/gitconfig and $XDG_CONFIG_HOME/git/config as well,
        // so settings such as commit.gpgsign on the host would reach this
        // test. Both are cut off here.
        cmd.env("HOME", run.home.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("XDG_CONFIG_HOME")
            .env("TURNKEY_API_BASE_URL", &run.config.api_base_url)
            .env("GNUPGHOME", &gnupghome);
    };

    let mut shim = std::process::Command::new(env!("CARGO_BIN_EXE_tk"));
    shim_env(&mut shim);
    let output = shim
        .args(["--status-fd=2", "-bsau", &fingerprint])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(b"hello from git\n")?;
            child.wait_with_output()
        })
        .unwrap();
    // Run::output makes this check for every command it spawns. This test
    // spawns the binary itself, so it makes the check itself.
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
    let status_lines: Vec<&str> = std::str::from_utf8(&output.stderr)
        .unwrap()
        .lines()
        .collect();
    assert_eq!(status_lines.len(), 2);
    assert_eq!(status_lines[0], "[GNUPG:] BEGIN_SIGNING");
    let sig_created = status_lines[1];
    assert!(sig_created.starts_with("[GNUPG:] SIG_CREATED D 19 8 00 "));
    assert!(sig_created.ends_with(&fingerprint));

    let repo = run.home.path().join("repo");
    fs::create_dir(&repo).unwrap();
    let git = |config: &[&str], args: &[&str]| {
        let mut cmd = std::process::Command::new(&git);
        shim_env(&mut cmd);
        cmd.current_dir(&repo)
            .args([
                "-c",
                "user.name=tk e2e",
                "-c",
                "user.email=tk-e2e@example.com",
            ])
            .args(["-c", "gpg.format=openpgp"])
            .arg("-c")
            .arg(format!("gpg.program={}", env!("CARGO_BIN_EXE_tk")));
        for setting in config {
            cmd.arg("-c").arg(setting);
        }
        cmd.args(args).output().unwrap()
    };
    let git_ok = |config: &[&str], args: &[&str]| {
        let output = git(config, args);
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            run.redact(&output.stderr)
        );
    };
    let signingkey = format!("user.signingkey={fingerprint}");
    git_ok(&[], &["init", "--quiet"]);
    git_ok(
        &[&signingkey],
        &[
            "commit",
            "-S",
            "--quiet",
            "--allow-empty",
            "-m",
            "signed by tk",
        ],
    );
    git_ok(&[], &["verify-commit", "HEAD"]);

    // With user.signingkey unset, git names the committer ident, which is
    // the key's user ID, so the same key signs.
    git_ok(
        &[],
        &[
            "commit",
            "-S",
            "--quiet",
            "--allow-empty",
            "-m",
            "signed by user id",
        ],
    );
    git_ok(&[], &["verify-commit", "HEAD"]);

    // A key git names that is not registered fails the commit rather than
    // signing with another key.
    let other = "FEDCBA9876543210FEDCBA9876543210FEDCBA98";
    let refused = git(
        &[&format!("user.signingkey={other}")],
        &["commit", "-S", "--quiet", "--allow-empty", "-m", "refused"],
    );
    assert!(
        !refused.status.success(),
        "git signed with a key it did not name"
    );
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains(&format!(
            "no registered OpenPGP key matches signing key {other}; set user.signingkey to the key fingerprint"
        )),
        "{}",
        run.redact(&refused.stderr)
    );
}
