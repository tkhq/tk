//! Asserts the release pipeline's invariants from its configuration so that a
//! regression is caught by `cargo test` rather than by a broken release.
use serde_yaml_ng::Value;

const RELEASE_WORKFLOW: &str = include_str!("../../.github/workflows/release.yml");
const INSTALLER: &str = include_str!("../../install.sh");
const RELEASE_DOC: &str = include_str!("../../docs/releasing.md");
const WORKSPACE_MANIFEST: &str = include_str!("../../Cargo.toml");
const PACKAGE_MANIFEST: &str = include_str!("../Cargo.toml");

/// Native runner per target; the installer must map `uname` output onto
/// exactly this set.
const TARGETS: [(&str, &str); 4] = [
    ("ubuntu-22.04", "x86_64-unknown-linux-gnu"),
    ("ubuntu-22.04-arm", "aarch64-unknown-linux-gnu"),
    ("macos-latest", "aarch64-apple-darwin"),
    ("macos-15-intel", "x86_64-apple-darwin"),
];

fn workflow() -> Value {
    serde_yaml_ng::from_str(RELEASE_WORKFLOW).expect("release workflow should be valid YAML")
}

fn steps<'a>(workflow: &'a Value, job: &str) -> &'a [Value] {
    workflow["jobs"][job]["steps"]
        .as_sequence()
        .unwrap_or_else(|| panic!("{job} should contain steps"))
}

fn step<'a>(workflow: &'a Value, job: &str, name: &str) -> &'a Value {
    steps(workflow, job)
        .iter()
        .find(|step| step["name"] == name)
        .unwrap_or_else(|| panic!("{job} should contain a step named `{name}`"))
}

fn run_script<'a>(workflow: &'a Value, job: &str, name: &str) -> &'a str {
    step(workflow, job, name)["run"]
        .as_str()
        .unwrap_or_else(|| panic!("`{name}` should be a shell step"))
}

fn assert_contains(document: &str, expected: &str) {
    assert!(
        document.contains(expected),
        "expected document to contain `{expected}`"
    );
}

#[test]
fn release_runs_only_for_version_tags() {
    let workflow = workflow();
    assert_eq!(
        workflow["on"]["push"]["tags"],
        Value::Sequence(vec![Value::String("v*".into())])
    );
    assert!(workflow["on"]["pull_request"].is_null());
    assert!(workflow["on"]["workflow_dispatch"].is_null());
}

#[test]
fn release_tag_must_be_on_main() {
    let workflow = workflow();
    let checkout = steps(&workflow, "validate")
        .iter()
        .find(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|action| action.starts_with("actions/checkout@"))
        })
        .expect("validate should check out the repository");
    assert_eq!(checkout["with"]["fetch-depth"], 0);

    let script = run_script(
        &workflow,
        "validate",
        "Require the tagged commit to be on main",
    );
    assert_contains(
        script,
        "git fetch --no-tags origin main:refs/remotes/origin/main",
    );
    assert_contains(
        script,
        r#"if ! git merge-base --is-ancestor "$GITHUB_SHA" origin/main; then"#,
    );
    assert_eq!(workflow["jobs"]["build"]["needs"], "validate");
    assert_eq!(workflow["jobs"]["release"]["needs"], "build");
    assert_contains(
        RELEASE_DOC,
        "**The tag must point at a commit already on `main`.**",
    );
}

#[test]
fn every_action_is_pinned_to_a_commit_with_a_version_comment() {
    let uses: Vec<_> = RELEASE_WORKFLOW
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("- uses: "))
        .collect();
    assert!(!uses.is_empty());
    for reference in uses {
        let (action, comment) = reference
            .split_once(" # ")
            .unwrap_or_else(|| panic!("`{reference}` should carry a version comment"));
        let (_, sha) = action
            .split_once('@')
            .unwrap_or_else(|| panic!("`{action}` should name a ref"));
        assert!(
            sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()),
            "`{action}` should be pinned to a full commit SHA"
        );
        assert!(!comment.trim().is_empty());
    }
}

#[test]
fn build_matrix_uses_native_runners_for_every_target() {
    let workflow = workflow();
    let include = workflow["jobs"]["build"]["strategy"]["matrix"]["include"]
        .as_sequence()
        .expect("build should define a matrix");
    let pairs: Vec<_> = include
        .iter()
        .map(|entry| {
            (
                entry["os"].as_str().expect("matrix os"),
                entry["target"].as_str().expect("matrix target"),
            )
        })
        .collect();
    assert_eq!(pairs, TARGETS);
    assert_eq!(workflow["jobs"]["build"]["runs-on"], "${{ matrix.os }}");
    assert_eq!(workflow["jobs"]["build"]["strategy"]["fail-fast"], false);
}

#[test]
fn release_build_bakes_the_tag_into_the_binary() {
    let workflow = workflow();
    let build = step(&workflow, "build", "Build release binary");
    assert_eq!(
        build["run"],
        "cargo build --locked --release --package tk --bin tk --target ${{ matrix.target }}"
    );
    assert_eq!(build["env"]["TK_RELEASE_BUILD"], "1");
    assert_eq!(build["env"]["TK_RELEASE_VERSION"], "${{ github.ref_name }}");

    let toolchain = steps(&workflow, "build")
        .iter()
        .find(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|action| action.starts_with("dtolnay/rust-toolchain@"))
        })
        .expect("build should install a Rust toolchain");
    let pinned: toml::Value = toml::from_str(include_str!("../../rust-toolchain.toml")).unwrap();
    assert_eq!(
        toolchain["with"]["toolchain"].as_str(),
        pinned["toolchain"]["channel"].as_str()
    );
    assert!(toolchain["with"]["toolchain"].is_string());
    assert_eq!(toolchain["with"]["targets"], "${{ matrix.target }}");
}

#[test]
fn packaging_follows_the_artifact_contract() {
    let workflow = workflow();
    let script = run_script(&workflow, "build", "Package archive and checksum");
    assert_contains(script, r#"package="tk-${TARGET}-${GITHUB_REF_NAME}""#);
    assert_contains(script, r#"mkdir "$package""#);
    assert_contains(
        script,
        r#"cp "target/${TARGET}/release/tk" README.md "$package/""#,
    );
    assert_contains(script, r#"tar -czf "$package.tar.gz" "$package""#);
    assert_contains(
        script,
        r#"shasum -a 256 "$package.tar.gz" > "$package.tar.gz.sha256""#,
    );

    let upload = steps(&workflow, "build")
        .iter()
        .find(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|action| action.starts_with("actions/upload-artifact@"))
        })
        .expect("build should upload its artifacts");
    assert_eq!(upload["with"]["if-no-files-found"], "error");
    assert_eq!(
        upload["with"]["path"],
        "tk-${{ matrix.target }}-${{ github.ref_name }}.tar.gz\n\
         tk-${{ matrix.target }}-${{ github.ref_name }}.tar.gz.sha256\n"
    );
}

#[test]
fn release_verifies_checksums_and_the_full_matrix_before_publishing() {
    let workflow = workflow();
    let script = run_script(
        &workflow,
        "release",
        "Verify every archive against its checksum",
    );
    assert_contains(script, "for archive in *.tar.gz; do");
    assert_contains(script, r#"shasum -a 256 --check "$archive.sha256""#);
    let expected_count = format!(r#"= "{}""#, TARGETS.len());
    assert_contains(script, &expected_count);

    let publish = steps(&workflow, "release")
        .iter()
        .find(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|action| action.starts_with("softprops/action-gh-release@"))
        })
        .expect("release should publish a GitHub release");
    assert_eq!(publish["with"]["fail_on_unmatched_files"], true);
    assert_eq!(publish["with"]["tag_name"], "${{ github.ref_name }}");
    assert_eq!(publish["with"]["files"], "dist/*.tar.gz\ndist/*.sha256\n");
    assert_eq!(
        workflow["jobs"]["release"]["permissions"]["contents"],
        "write"
    );
    assert_eq!(workflow["permissions"]["contents"], "read");
}

#[test]
fn rust_caches_are_read_only_in_release_jobs() {
    let workflow = workflow();
    let jobs = workflow["jobs"].as_mapping().expect("jobs");
    let mut caches = 0;
    for (job, definition) in jobs {
        let Some(steps) = definition["steps"].as_sequence() else {
            continue;
        };
        for step in steps.iter().filter(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|action| action.starts_with("Swatinem/rust-cache@"))
        }) {
            caches += 1;
            assert_eq!(
                step["with"]["save-if"],
                false,
                "{} should not save a cache",
                job.as_str().unwrap_or_default()
            );
        }
    }
    assert_eq!(caches, 1, "only the build job restores a cache");
}

#[test]
fn installer_agrees_with_the_workflow_on_targets_and_names() {
    assert!(INSTALLER.starts_with("#!/bin/sh\n"));
    assert_contains(INSTALLER, "set -eu");
    assert_contains(INSTALLER, r#"repository_url="https://github.com/tkhq/tk""#);
    for (_, target) in TARGETS {
        assert_contains(INSTALLER, &format!(r#"target="{target}""#));
    }
    assert_contains(INSTALLER, r#"archive_name="tk-$target-$version.tar.gz""#);
    assert_contains(INSTALLER, r#"checksum_name="$archive_name.sha256""#);
    assert_contains(INSTALLER, r#"expected_binary="$package/tk""#);
    assert_contains(INSTALLER, r#"install_dir=${TK_INSTALL_DIR:-}"#);
    assert_contains(INSTALLER, r#"install_dir="$HOME/.local/bin""#);

    // Every download goes over pinned-protocol TLS.
    let curls: Vec<_> = INSTALLER
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("curl ") || line.contains("=$(curl "))
        .collect();
    assert_eq!(curls.len(), 3);
    for line in curls {
        assert_contains(line, "curl --proto '=https' --tlsv1.2 -LsSf");
    }
}

#[test]
fn installer_verifies_before_it_trusts() {
    assert_contains(INSTALLER, "getconf GNU_LIBC_VERSION");
    assert_contains(INSTALLER, r#""$repository_url/releases/latest""#);
    assert_contains(INSTALLER, "v[0-9]*) ;;");
    assert_contains(INSTALLER, r#"*/* | *\?* | *\#*)"#);
    assert_contains(
        INSTALLER,
        r#"if [ "$listed_name" != "$archive_name" ]; then"#,
    );
    assert_contains(INSTALLER, r#"sha256sum -c "$checksum_name""#);
    assert_contains(INSTALLER, r#"shasum -a 256 -c "$checksum_name""#);
    assert_contains(INSTALLER, r#"tar -tzf "$archive" >"$entries""#);
    assert_contains(
        INSTALLER,
        r#"index($0, root) != 1 || $0 ~ /(^|\/)\.\.(\/|$)/ { exit 1 }"#,
    );
    assert_contains(INSTALLER, r#"if [ "$binary_count" -ne 1 ]; then"#);
    assert_contains(
        INSTALLER,
        r#"tar -xzf "$archive" -C "$extract_dir" "$expected_binary""#,
    );
    assert_contains(
        INSTALLER,
        r#"staged_binary=$(mktemp "$install_dir/.tk.XXXXXX")"#,
    );
    assert_contains(
        INSTALLER,
        r#"if ! "$staged_binary" --version >/dev/null 2>&1; then"#,
    );
    assert_contains(INSTALLER, r#"mv -f "$staged_binary" "$destination""#);
    assert_contains(INSTALLER, "trap cleanup EXIT HUP INT TERM");

    let verify = INSTALLER.find("sha256sum -c").unwrap();
    let list = INSTALLER.find("tar -tzf").unwrap();
    let extract = INSTALLER.find("tar -xzf").unwrap();
    let smoke = INSTALLER.find(r#""$staged_binary" --version"#).unwrap();
    let install = INSTALLER.find(r#"mv -f "$staged_binary""#).unwrap();
    assert!(verify < list && list < extract && extract < smoke && smoke < install);
}

#[test]
fn crates_version_together_from_the_workspace() {
    let workspace: toml::Value = toml::from_str(WORKSPACE_MANIFEST).unwrap();
    assert_eq!(
        workspace["workspace"]["package"]["version"].as_str(),
        Some("0.1.0")
    );
    let package: toml::Value = toml::from_str(PACKAGE_MANIFEST).unwrap();
    assert_eq!(
        package["package"]["version"]["workspace"].as_bool(),
        Some(true)
    );
    assert_eq!(package["package"]["publish"].as_bool(), Some(false));
    assert_eq!(package["package"]["build"].as_str(), Some("build.rs"));
}
