use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde_json::json;

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

fn create_wallet(run: &Run) -> String {
    let created = run.submit(
        run.admin().args([
            "wallet",
            "create",
            "--input-json",
            &json!({"walletName": run.name("gpg-wallet"), "accounts": []}).to_string(),
        ]),
        "wallet.create",
    );
    result(&created, "createWalletResult")["walletId"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
#[ignore]
fn gpg_keys_create_list_export_and_sign() {
    let run = Run::new();
    let wallet = create_wallet(&run);

    let created = run.ok(run.admin().args([
        "gpg",
        "keys",
        "create",
        "--wallet-id",
        &wallet,
        "--user-id",
        USER_ID,
    ]));
    assert_eq!(created["reason"], "gpg_key_created");
    assert_eq!(created["walletId"], wallet);
    assert_eq!(created["keyIndex"], 0);
    assert_eq!(created["userId"], USER_ID);
    let fingerprint = created["fingerprint"].as_str().unwrap().to_string();
    assert_eq!(fingerprint.len(), 40);
    assert!(
        fingerprint
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())
    );
    assert!(created["created"].as_u64().unwrap() > 1_700_000_000);

    let second = run.ok(run.admin().args([
        "gpg",
        "keys",
        "create",
        "--wallet-id",
        &wallet,
        "--user-id",
        SECOND_USER_ID,
    ]));
    assert_eq!(second["keyIndex"], 1);

    // One key is one wallet account, at the signing path of its index.
    let accounts = run.ok(run
        .admin()
        .args(["wallet", "account", "list", "--wallet-id", &wallet]));
    let mut paths: Vec<&str> = accounts["data"]["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|account| account["path"].as_str().unwrap())
        .collect();
    paths.sort_unstable();
    assert_eq!(paths, ["m/5261136'/0'/0'/0'", "m/5261136'/0'/1'/0'"]);

    let listed = run.ok(run
        .admin()
        .args(["gpg", "keys", "list", "--wallet-id", &wallet]));
    assert_eq!(
        listed,
        json!({
            "reason": "gpg_keys_listed",
            "walletId": wallet,
            "keys": [
                {"keyIndex": 0, "fingerprint": fingerprint, "userId": USER_ID, "created": created["created"]},
                {"keyIndex": 1, "fingerprint": second["fingerprint"], "userId": SECOND_USER_ID, "created": second["created"]},
            ],
        })
    );

    // A create at an index the wallet already holds fails locally, after the
    // listing query and before any signature.
    let occupied = run.err(run.admin().args([
        "gpg",
        "keys",
        "create",
        "--wallet-id",
        &wallet,
        "--at-index",
        "0",
        "--user-id",
        SECOND_USER_ID,
    ]));
    assert_eq!(occupied["code"], "invalid_input");

    let ambiguous = run.err(
        run.admin()
            .args(["gpg", "keys", "export", "--wallet-id", &wallet]),
    );
    assert_eq!(ambiguous["code"], "invalid_input");

    let exported = run.ok(run.admin().args([
        "gpg",
        "keys",
        "export",
        "--wallet-id",
        &wallet,
        "--key-index",
        "0",
    ]));
    let again = run.ok(run.admin().args([
        "gpg",
        "keys",
        "export",
        "--wallet-id",
        &wallet,
        "--key-index",
        "0",
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
        .args(["gpg", "sign", "--wallet-id", &wallet, "--key-index", "0"])
        .arg(&payload));
    assert_eq!(signed["reason"], "gpg_signature_created");
    assert_eq!(signed["fingerprint"], fingerprint);
    assert_eq!(signed["output"], serde_json::Value::Null);
    let signature = signed["armored"].as_str().unwrap();
    assert!(signature.starts_with("-----BEGIN PGP SIGNATURE-----\n"));

    let Some(gpg) = locate("gpg") else {
        eprintln!("skipping GnuPG verification: gpg is not on PATH");
        return;
    };
    let gnupghome = run.home.path().join("gnupg");
    fs::create_dir(&gnupghome).unwrap();
    let key_file = run.home.path().join("key.asc");
    let signature_file = run.home.path().join("payload.txt.asc");
    fs::write(&key_file, armored).unwrap();
    fs::write(&signature_file, signature).unwrap();
    let imported = Command::new(&gpg)
        .env("GNUPGHOME", &gnupghome)
        .args(["--batch", "--import"])
        .arg(&key_file)
        .status()
        .unwrap();
    assert!(imported.success());
    let verified = Command::new(&gpg)
        .env("GNUPGHOME", &gnupghome)
        .args(["--batch", "--verify"])
        .arg(&signature_file)
        .arg(&payload)
        .status()
        .unwrap();
    assert!(verified.success(), "GnuPG rejected the tk signature");
}

/// `tk gpg use` writes the target into the active profile, and later gpg
/// commands run with no target flags at all.
#[test]
#[ignore]
fn gpg_use_stores_the_target_for_later_commands() {
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

    let used = run.ok(run.cli().args(["gpg", "use", "--wallet-id", &wallet]));
    assert_eq!(
        used,
        json!({
            "reason": "gpg_profile_updated",
            "profile": profile,
            "walletId": wallet,
            "keyIndex": 0,
        })
    );

    let created = run.ok(run
        .cli()
        .args(["gpg", "keys", "create", "--user-id", USER_ID]));
    assert_eq!(created["reason"], "gpg_key_created");
    assert_eq!(created["walletId"], wallet);
    assert_eq!(created["keyIndex"], 0);
    assert_eq!(created["userId"], USER_ID);

    let listed = run.ok(run.cli().args(["gpg", "keys", "list"]));
    assert_eq!(
        listed,
        json!({
            "reason": "gpg_keys_listed",
            "walletId": wallet,
            "keys": [
                {
                    "keyIndex": 0,
                    "fingerprint": created["fingerprint"],
                    "userId": USER_ID,
                    "created": created["created"],
                },
            ],
        })
    );
}

/// Git calls `tk` as its `gpg.program`. The shim signs stdin and reports the
/// status lines git parses, and GnuPG accepts the commit it produces.
#[test]
#[ignore]
fn gpg_shim_signs_and_git_verifies() {
    let (Some(gpg), Some(git)) = (locate("gpg"), locate("git")) else {
        eprintln!("skipping the git shim test: gpg or git is not on PATH");
        return;
    };
    let run = Run::new();
    let wallet = create_wallet(&run);
    let created = run.ok(run.admin().args([
        "gpg",
        "keys",
        "create",
        "--wallet-id",
        &wallet,
        "--user-id",
        USER_ID,
    ]));
    let fingerprint = created["fingerprint"].as_str().unwrap().to_string();
    let exported = run.ok(run
        .admin()
        .args(["gpg", "keys", "export", "--wallet-id", &wallet]));

    let gnupghome = run.home.path().join("gnupg");
    fs::create_dir(&gnupghome).unwrap();
    let key_file = run.home.path().join("key.asc");
    fs::write(&key_file, exported["armored"].as_str().unwrap()).unwrap();
    assert!(
        Command::new(&gpg)
            .env("GNUPGHOME", &gnupghome)
            .args(["--batch", "--import"])
            .arg(&key_file)
            .status()
            .unwrap()
            .success()
    );

    // The shim receives no tk flags, so the identity travels in the environment.
    let shim_env = |cmd: &mut Command| {
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
            .env("TK_GPG_WALLET_ID", &wallet)
            .env("GNUPGHOME", &gnupghome);
    };

    let mut shim = Command::new(env!("CARGO_BIN_EXE_tk"));
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
    let git_ok = |args: &[&str]| {
        let mut cmd = Command::new(&git);
        shim_env(&mut cmd);
        let status = cmd
            .current_dir(&repo)
            .args([
                "-c",
                "user.name=tk e2e",
                "-c",
                "user.email=tk-e2e@example.com",
            ])
            .args(["-c", "gpg.format=openpgp"])
            .arg("-c")
            .arg(format!("gpg.program={}", env!("CARGO_BIN_EXE_tk")))
            .arg("-c")
            .arg(format!("user.signingkey={fingerprint}"))
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    };
    git_ok(&["init", "--quiet"]);
    git_ok(&[
        "commit",
        "-S",
        "--quiet",
        "--allow-empty",
        "-m",
        "signed by tk",
    ]);
    git_ok(&["verify-commit", "HEAD"]);
}
