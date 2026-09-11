//! Bakes release and provenance metadata into the `tk` binary as `TK_*`
//! compile-time environment variables.
//!
//! The release tag is the version of record: the release workflow sets
//! `TK_RELEASE_VERSION` to the tag, and local builds fall back to
//! `git describe --tags` and then to the manifest version. Every value read
//! from the environment is declared with `rerun-if-env-changed` so a changed
//! value is never served from a stale build-script cache.
use std::env;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    if let Some(git_dir) = git(&["rev-parse", "--git-dir"]) {
        for path in ["HEAD", "index"] {
            println!("cargo::rerun-if-changed={git_dir}/{path}");
        }
    }
    println!("cargo::rerun-if-env-changed=SOURCE_DATE_EPOCH");
    println!("cargo::rerun-if-env-changed=TK_RELEASE_BUILD");

    set(
        "TK_VERSION",
        env_override("TK_RELEASE_VERSION")
            .or_else(|| git(&["describe", "--tags"]))
            .or_else(|| env::var("CARGO_PKG_VERSION").ok()),
    );
    set(
        "TK_GIT_SHA",
        env_override("TK_GIT_SHA").or_else(|| git(&["rev-parse", "--short=12", "HEAD"])),
    );
    set(
        "TK_GIT_BRANCH",
        env_override("TK_GIT_BRANCH")
            .or_else(|| git(&["branch", "--show-current"]))
            .filter(|branch| !branch.is_empty()),
    );
    set(
        "TK_GIT_COMMIT_TIMESTAMP",
        env_override("TK_GIT_COMMIT_TIMESTAMP").or_else(|| git(&["log", "-1", "--format=%cI"])),
    );
    set(
        "TK_GIT_DIRTY",
        env_override("TK_GIT_DIRTY").or_else(dirty_state),
    );
    set("TK_BUILD_TIMESTAMP", Some(build_timestamp()));
    set("TK_BUILD_TARGET", env::var("TARGET").ok());
    println!(
        "cargo::rustc-env=TK_RELEASE_BUILD={}",
        env::var("TK_RELEASE_BUILD").is_ok_and(|value| value == "1")
    );
}

/// Reads `name` from the build environment, letting builds without a git
/// checkout, such as distribution packaging, provide the repository metadata.
fn env_override(name: &str) -> Option<String> {
    println!("cargo::rerun-if-env-changed={name}");
    env::var(name).ok().filter(|value| !value.is_empty())
}

fn git(arguments: &[&str]) -> Option<String> {
    let output = Command::new("git").args(arguments).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn dirty_state() -> Option<String> {
    let output = git(&["status", "--porcelain", "--untracked-files=no"])?;
    Some(if output.is_empty() { "clean" } else { "dirty" }.to_owned())
}

/// The build time as Unix epoch seconds, taken from `SOURCE_DATE_EPOCH` when
/// set so reproducible builds do not embed the wall clock.
fn build_timestamp() -> String {
    match env::var("SOURCE_DATE_EPOCH") {
        Ok(value) => {
            value
                .parse::<u64>()
                .expect("SOURCE_DATE_EPOCH must be a Unix timestamp");
            value
        }
        Err(_) => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before the Unix epoch")
            .as_secs()
            .to_string(),
    }
}

fn set(name: &str, value: Option<String>) {
    println!(
        "cargo::rustc-env={name}={}",
        value.as_deref().unwrap_or("unknown")
    );
}
