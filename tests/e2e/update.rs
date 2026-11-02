use std::{
    fs,
    path::{Path, PathBuf},
};

use serde_json::{Value, json};
use tempfile::TempDir;

use crate::run::{Run, cli_at};

const PINNED: &str = "v0.4.0";

fn copy_tk(dir: &Path) -> PathBuf {
    fs::create_dir_all(dir).unwrap();
    let tk = dir.join("tk");
    fs::copy(env!("CARGO_BIN_EXE_tk"), &tk).unwrap();
    fs::canonicalize(tk).unwrap()
}

fn update(tk: &Path, home: &Path, args: &[&str]) -> Value {
    let output = cli_at(tk, home)
        .env_remove("CARGO_HOME")
        .env_remove("CARGO_INSTALL_ROOT")
        .args(["--message-format", "json", "update"])
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
#[ignore]
fn update_refuses_an_unsigned_release_without_replacing_the_binary() {
    let run = Run::new();
    let tk = copy_tk(&run.home().join("install"));

    let before = fs::read(&tk).unwrap();
    let output = run
        .as_admin(cli_at(&tk, run.home()))
        .env_remove("CARGO_HOME")
        .env_remove("CARGO_INSTALL_ROOT")
        .arg("--api-base-url")
        .arg(&run.config.api_base_url)
        .args(["--message-format=json", "update", "--tag", PINNED])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let record: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(record["code"], "not_found", "{record}");
    assert_eq!(record["httpStatus"], 404, "{record}");
    assert_eq!(fs::read(&tk).unwrap(), before);
    assert_eq!(
        fs::read_dir(tk.parent().unwrap()).unwrap().count(),
        1,
        "the staged binary should not outlive the update"
    );
}

#[test]
#[ignore]
fn update_leaves_a_binary_no_older_than_the_latest_release() {
    let dir = TempDir::new().unwrap();
    let tk = copy_tk(&dir.path().join("install"));
    let before = fs::read(&tk).unwrap();

    let record = update(&tk, dir.path(), &[]);

    assert_eq!(record["reason"], "already_up_to_date", "{record}");
    assert_eq!(record["version"], env!("CARGO_PKG_VERSION"), "{record}");
    assert_eq!(fs::read(&tk).unwrap(), before);
}

#[test]
fn update_defers_to_cargo_for_a_cargo_install() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("cargo");
    let tk = copy_tk(&root.join("bin"));
    fs::write(
        root.join(".crates.toml"),
        r#"[v1]
"turnkey_tk 0.4.1 (registry+https://github.com/rust-lang/crates.io-index)" = ["tk"]
"#,
    )
    .unwrap();
    let before = fs::read(&tk).unwrap();
    let root = fs::canonicalize(&root).unwrap();

    assert_eq!(
        update(&tk, dir.path(), &[]),
        json!({
            "reason": "update_via_cargo",
            "command": format!("cargo install turnkey_tk --locked --root '{}'", root.display()),
        })
    );
    assert_eq!(
        update(&tk, dir.path(), &["--tag", PINNED]),
        json!({
            "reason": "update_via_cargo",
            "command": format!(
                "cargo install turnkey_tk --locked --version 0.4.0 --root '{}'",
                root.display()
            ),
        })
    );
    let prerelease = cli_at(&tk, dir.path())
        .args([
            "--message-format",
            "json",
            "update",
            "--tag",
            "pr-70-6f683c2",
        ])
        .output()
        .unwrap();
    assert_eq!(prerelease.status.code(), Some(1), "{prerelease:?}");
    assert_eq!(
        serde_json::from_slice::<Value>(&prerelease.stdout).unwrap(),
        json!({
            "reason": "command_error",
            "code": "invalid_input",
            "message": "cargo installed this tk, and crates.io publishes only vX.Y.Z releases, not pr-70-6f683c2",
        })
    );
    assert_eq!(fs::read(&tk).unwrap(), before);
}
