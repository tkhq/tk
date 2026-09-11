//! Bakes release and provenance metadata into the `tk` binary as `TK_*`
//! compile-time environment variables. The release tag is the version of
//! record: the release workflow sets `TK_RELEASE_VERSION` to the tag, and
//! local builds fall back to `git describe --tags` and then to the manifest
//! version. Git-derived values can be overridden through the environment for
//! builds without a checkout.
use std::env;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// Reads a non-empty build environment variable, re-running the script when
/// it changes.
fn var(name: &str) -> Option<String> {
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

fn main() {
    if let Some(git_dir) = git(&["rev-parse", "--git-dir"]) {
        println!("cargo::rerun-if-changed={git_dir}/HEAD");
        println!("cargo::rerun-if-changed={git_dir}/index");
    }

    let dirty = || {
        git(&["status", "--porcelain", "--untracked-files=no"])
            .map(|status| if status.is_empty() { "clean" } else { "dirty" }.to_owned())
    };
    // SOURCE_DATE_EPOCH keeps reproducible builds from embedding the wall clock.
    let build_timestamp = var("SOURCE_DATE_EPOCH").unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before the Unix epoch")
            .as_secs()
            .to_string()
    });
    build_timestamp
        .parse::<u64>()
        .expect("SOURCE_DATE_EPOCH must be a Unix timestamp");

    let values = [
        (
            "TK_VERSION",
            var("TK_RELEASE_VERSION")
                .or_else(|| git(&["describe", "--tags"]))
                .or_else(|| env::var("CARGO_PKG_VERSION").ok()),
        ),
        (
            "TK_GIT_SHA",
            var("TK_GIT_SHA").or_else(|| git(&["rev-parse", "--short=12", "HEAD"])),
        ),
        (
            "TK_GIT_BRANCH",
            var("TK_GIT_BRANCH")
                .or_else(|| git(&["branch", "--show-current"]))
                .filter(|branch| !branch.is_empty()),
        ),
        (
            "TK_GIT_COMMIT_TIMESTAMP",
            var("TK_GIT_COMMIT_TIMESTAMP").or_else(|| git(&["log", "-1", "--format=%cI"])),
        ),
        ("TK_GIT_DIRTY", var("TK_GIT_DIRTY").or_else(dirty)),
        ("TK_BUILD_TIMESTAMP", Some(build_timestamp)),
        ("TK_BUILD_TARGET", env::var("TARGET").ok()),
        (
            "TK_RELEASE_BUILD",
            Some((var("TK_RELEASE_BUILD").as_deref() == Some("1")).to_string()),
        ),
    ];
    for (name, value) in values {
        println!(
            "cargo::rustc-env={name}={}",
            value.as_deref().unwrap_or("unknown")
        );
    }
}
