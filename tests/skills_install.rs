//! `tk skills` against the real binary without a network or a readable
//! configuration: the embedded records and the filesystem contract of `install`.

// Test helpers may panic.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Component, Path, PathBuf},
};

use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

const SCRUBBED: [&str; 8] = [
    "HOME",
    "TK_PROFILE",
    "TK_NON_INTERACTIVE",
    "TURNKEY_ORGANIZATION_ID",
    "TURNKEY_API_PUBLIC_KEY",
    "TURNKEY_API_PRIVATE_KEY",
    "TURNKEY_API_BASE_URL",
    "RUST_LOG",
];

const MALFORMED_CONFIG: &str = r#"version = "not a number"
[profiles
"#;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

struct Workspace {
    _dir: TempDir,
    root: PathBuf,
    home: PathBuf,
    into: PathBuf,
}

fn workspace() -> Workspace {
    let dir = tempdir().unwrap();
    // macOS places TMPDIR under the /var symlink, which `install` refuses.
    let root = dir.path().canonicalize().unwrap();
    let home = root.join("home");
    let into = root.join("skills");
    Workspace {
        _dir: dir,
        root,
        home,
        into,
    }
}

fn bare(home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tk"));
    for name in SCRUBBED {
        cmd.env_remove(name);
    }
    cmd.env("HOME", home);
    cmd
}

fn tk(home: &Path) -> Command {
    let config = home.join(".config/turnkey");
    fs::create_dir_all(&config).unwrap();
    fs::write(config.join("tk.config.toml"), MALFORMED_CONFIG).unwrap();
    let mut cmd = bare(home);
    cmd.args(["--message-format", "json"]);
    cmd
}

fn record(cmd: &mut Command, code: i32) -> Value {
    let output = cmd.output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(code), "{stdout}");
    assert_eq!(output.stderr, b"", "stderr must stay empty");
    serde_json::from_str(stdout.trim_end()).unwrap_or_else(|e| panic!("{e}: {stdout}"))
}

fn ok(cmd: &mut Command) -> Value {
    record(cmd, 0)
}

fn invalid_input(cmd: &mut Command) -> String {
    let error = record(cmd, 1);
    assert_eq!(error["reason"], "command_error", "{error}");
    assert_eq!(error["code"], "invalid_input", "{error}");
    error["message"].as_str().unwrap().to_owned()
}

fn refused_untouched(ws: &Workspace) -> String {
    let before = snapshot(&ws.into);
    let message = invalid_input(&mut install_cmd(&ws.home, &ws.into));
    assert_eq!(snapshot(&ws.into), before);
    message
}

fn install_cmd(home: &Path, into: &Path) -> Command {
    let mut cmd = tk(home);
    cmd.args(["skills", "install", "--into"]).arg(into);
    cmd
}

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files_under(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = Vec::new();
    files_under(dir, &mut files);
    files
        .into_iter()
        .map(|path| {
            let bytes = fs::read(&path).unwrap();
            (path.strip_prefix(dir).unwrap().to_path_buf(), bytes)
        })
        .collect()
}

fn frontmatter(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .skip(1)
        .take_while(|line| *line != "---")
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect()
}

fn links(text: &str) -> Vec<&str> {
    let mut links = Vec::new();
    let mut rest = text;
    while let Some(position) = rest.find("](") {
        let after = &rest[position + 2..];
        let Some(end) = after.find(')') else { break };
        links.push(after[..end].split('#').next().unwrap());
        rest = &after[end + 1..];
    }
    links
}

fn workflow_names() -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(repo_root().join("skills"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir() && path.file_name().is_some_and(|n| n != "references"))
        .map(|dir| dir.file_name().unwrap().to_str().unwrap().to_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn list_names_the_index_and_every_workflow_with_its_description() {
    let ws = workspace();
    let listed = ok(tk(&ws.home).args(["skills", "list"]));
    assert_eq!(listed["reason"], "skills_listed", "{listed}");
    assert_eq!(listed["version"], env!("CARGO_PKG_VERSION"));
    let digest = listed["digest"].as_str().unwrap();
    assert!(
        digest.len() == 64 && digest.chars().all(|c| c.is_ascii_hexdigit()),
        "digest {digest} is not hex SHA-256"
    );

    let skills = repo_root().join("skills");
    let mut expected = vec![("turnkey-tk".to_owned(), skills.join("SKILL.md"))];
    expected.extend(
        workflow_names()
            .into_iter()
            .map(|name| (skills.join(&name).join("SKILL.md"), name))
            .map(|(path, name)| (name, path)),
    );
    let expected: Vec<Value> = expected
        .into_iter()
        .map(|(name, path)| {
            let fields = frontmatter(&fs::read_to_string(path).unwrap());
            assert_eq!(fields["name"], name);
            json!({"name": name, "description": fields["description"]})
        })
        .collect();
    assert_eq!(listed["skills"], Value::Array(expected));
}

#[test]
fn show_prints_a_workflow_with_its_doc_links_rebased() {
    let ws = workspace();
    let source = fs::read_to_string(repo_root().join("skills/managing-policies/SKILL.md")).unwrap();
    let shown = ok(tk(&ws.home).args(["skills", "show", "--name", "managing-policies"]));
    assert_eq!(
        shown,
        json!({
            "reason": "skills_shown",
            "name": "managing-policies",
            "path": "turnkey-tk/managing-policies/SKILL.md",
            "content": source.replace("](../../docs/", "](../docs/"),
        })
    );

    let index = fs::read_to_string(repo_root().join("skills/SKILL.md")).unwrap();
    let shown = ok(tk(&ws.home).args(["skills", "show", "--name", "turnkey-tk"]));
    assert_eq!(shown["path"], "turnkey-tk/SKILL.md");
    assert_eq!(shown["content"], index.replace("](../docs/", "](docs/"));

    let reference =
        fs::read_to_string(repo_root().join("skills/references/cli-convention.md")).unwrap();
    let output = bare(&ws.home)
        .args(["skills", "show", "--name", "references/cli-convention"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        reference.replace("](../../docs/", "](../docs/")
    );
}

#[test]
fn show_rejects_names_outside_the_package() {
    let ws = workspace();
    for name in [
        "nope",
        "docs/activities",
        "../SKILL.md",
        "references/missing",
    ] {
        let error = record(tk(&ws.home).args(["skills", "show", "--name", name]), 2);
        assert_eq!(
            error,
            json!({
                "reason": "command_error",
                "code": "usage_error",
                "message": format!(
                    r#"error: invalid value '{name}' for '--name <NAME>': not a skill in this package; run `tk skills list`

For more information, try '--help'."#
                ),
            })
        );
    }
}

#[test]
fn install_writes_the_package_with_a_manifest_and_resolvable_links() {
    let ws = workspace();
    let into = ws.root.join("agent/skills");
    let installed = ok(&mut install_cmd(&ws.home, &into));
    let destination = into.join("turnkey-tk");
    let listed = ok(tk(&ws.home).args(["skills", "list"]));

    let tree = snapshot(&destination);
    let mut written: Vec<String> = tree
        .keys()
        .map(|path| path.to_str().unwrap().to_owned())
        .collect();
    written.retain(|path| path != "turnkey-tk.json");
    written.sort();
    assert_eq!(
        installed,
        json!({
            "reason": "skills_installed",
            "destination": destination.to_str().unwrap(),
            "version": env!("CARGO_PKG_VERSION"),
            "digest": listed["digest"],
            "files": written,
            "alreadyInstalled": false,
        })
    );
    assert!(written.contains(&"SKILL.md".to_owned()));
    assert!(written.contains(&"docs/commands.md".to_owned()));
    for name in workflow_names() {
        assert!(
            written.contains(&format!("{name}/SKILL.md")),
            "{name} missing"
        );
    }

    let manifest: Value = serde_json::from_slice(&tree[Path::new("turnkey-tk.json")]).unwrap();
    assert_eq!(
        manifest,
        json!({
            "binaryVersion": env!("CARGO_PKG_VERSION"),
            "digest": installed["digest"],
            "files": written,
        })
    );

    let installed_paths: BTreeSet<&Path> = tree.keys().map(PathBuf::as_path).collect();
    let mut broken = Vec::new();
    for (path, bytes) in &tree {
        if path.extension().is_none_or(|e| e != "md") {
            continue;
        }
        let text = str::from_utf8(bytes).unwrap();
        for link in links(text) {
            if link.is_empty() || link.starts_with("https://") || link.starts_with("http://") {
                continue;
            }
            let mut resolved = PathBuf::new();
            for component in path.parent().unwrap().join(link).components() {
                match component {
                    Component::CurDir => {}
                    Component::ParentDir => {
                        if !resolved.pop() {
                            broken.push(format!("{}: {link} escapes the package", path.display()));
                        }
                    }
                    other => resolved.push(other),
                }
            }
            if !installed_paths.contains(resolved.as_path()) {
                broken.push(format!("{}: {link}", path.display()));
            }
        }
    }
    assert!(
        broken.is_empty(),
        "unresolvable links:\n{}",
        broken.join("\n")
    );

    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&destination), 0o755);
    assert_eq!(mode(&destination.join("docs")), 0o755);
    assert_eq!(mode(&destination.join("SKILL.md")), 0o644);
    assert_eq!(mode(&destination.join("turnkey-tk.json")), 0o644);
    assert_eq!(
        fs::read_dir(&into).unwrap().count(),
        1,
        "install left something beside turnkey-tk"
    );

    let again = ok(&mut install_cmd(&ws.home, &into));
    assert_eq!(
        again,
        json!({
            "reason": "skills_installed",
            "destination": installed["destination"],
            "version": installed["version"],
            "digest": installed["digest"],
            "files": installed["files"],
            "alreadyInstalled": true,
        })
    );
    assert_eq!(snapshot(&destination), tree);
}

#[test]
fn install_refuses_a_differing_destination_and_leaves_it_untouched() {
    let ws = workspace();
    let destination = ws.into.join("turnkey-tk");
    fs::create_dir_all(&destination).unwrap();
    fs::write(destination.join("SKILL.md"), "someone else's index\n").unwrap();
    let message = refused_untouched(&ws);
    assert_eq!(
        message,
        format!(
            "{} exists without a turnkey-tk.json; if no other install is running, remove it or choose another --into",
            destination.display()
        )
    );

    fs::write(
        destination.join("turnkey-tk.json"),
        json!({"binaryVersion": "0.0.1", "digest": "0".repeat(64), "files": []}).to_string(),
    )
    .unwrap();
    let message = refused_untouched(&ws);
    assert_eq!(
        message,
        format!(
            "{} holds a different turnkey-tk package; remove it to install this one",
            destination.display()
        )
    );

    fs::write(destination.join("turnkey-tk.json"), "{").unwrap();
    let message = refused_untouched(&ws);
    assert_eq!(
        message,
        format!(
            "{} is not a turnkey-tk install manifest; remove {} to reinstall: {}",
            destination.join("turnkey-tk.json").display(),
            destination.display(),
            serde_json::from_str::<Value>("{").unwrap_err()
        )
    );

    fs::remove_file(destination.join("turnkey-tk.json")).unwrap();
    fs::create_dir(destination.join("turnkey-tk.json")).unwrap();
    let message = refused_untouched(&ws);
    assert_eq!(
        message,
        format!(
            "{} could not be read; remove {} to reinstall: {}",
            destination.join("turnkey-tk.json").display(),
            destination.display(),
            io::Error::from_raw_os_error(21)
        )
    );
}

#[test]
fn a_persisted_manifest_with_the_same_digest_is_reported_as_installed_as_written() {
    let ws = workspace();
    let destination = ws.into.join("turnkey-tk");
    let digest = ok(tk(&ws.home).args(["skills", "list"]))["digest"].clone();
    fs::create_dir_all(&destination).unwrap();
    fs::write(
        destination.join("turnkey-tk.json"),
        json!({"binaryVersion": "0.0.1", "digest": digest, "files": ["SKILL.md"]}).to_string(),
    )
    .unwrap();
    let before = snapshot(&ws.into);
    let installed = ok(&mut install_cmd(&ws.home, &ws.into));
    assert_eq!(
        installed,
        json!({
            "reason": "skills_installed",
            "destination": destination.to_str().unwrap(),
            "version": env!("CARGO_PKG_VERSION"),
            "digest": digest,
            "files": ["SKILL.md"],
            "alreadyInstalled": true,
        })
    );
    assert_eq!(snapshot(&ws.into), before);
}

#[test]
fn install_refuses_parent_segments_and_nesting_inside_an_install() {
    let ws = workspace();
    let error = record(
        install_cmd(&ws.home, Path::new("a/../b")).current_dir(&ws.root),
        2,
    );
    assert_eq!(
        error,
        json!({
            "reason": "command_error",
            "code": "usage_error",
            "message": r#"error: invalid value 'a/../b' for '--into <DIR>': contains ..; pass the resolved directory instead

For more information, try '--help'."#,
        })
    );
    assert!(!ws.root.join("a").exists() && !ws.root.join("b").exists());

    ok(&mut install_cmd(&ws.home, &ws.into));
    let nested = ws.into.join("turnkey-tk/docs");
    let message = invalid_input(&mut install_cmd(&ws.home, &nested));
    assert_eq!(
        message,
        format!(
            "--into {} is inside a turnkey-tk install",
            ws.into.join("turnkey-tk").display()
        )
    );
    assert!(!nested.join("turnkey-tk").exists());
}

#[test]
fn install_refuses_a_symlinked_ancestor() {
    let ws = workspace();
    let real = ws.root.join("real");
    fs::create_dir(&real).unwrap();
    let link = ws.root.join("link");
    symlink(&real, &link).unwrap();
    let message = invalid_input(&mut install_cmd(&ws.home, &link.join("skills")));
    assert_eq!(
        message,
        format!(
            "--into {} is a symlink; pass the resolved directory instead",
            link.display()
        )
    );
    assert_eq!(fs::read_dir(&real).unwrap().count(), 0);

    fs::create_dir(&ws.into).unwrap();
    symlink(&real, ws.into.join("turnkey-tk")).unwrap();
    let message = invalid_input(&mut install_cmd(&ws.home, &ws.into));
    assert_eq!(
        message,
        format!(
            "{} is a symlink; remove it or choose another --into",
            ws.into.join("turnkey-tk").display()
        )
    );
    assert_eq!(fs::read_dir(&real).unwrap().count(), 0);
}

#[test]
fn install_refuses_a_file_as_an_ancestor() {
    let ws = workspace();
    let file = ws.root.join("file");
    fs::write(&file, "").unwrap();
    let message = invalid_input(&mut install_cmd(&ws.home, &file.join("skills")));
    assert_eq!(
        message,
        format!("--into {} is not a directory", file.display())
    );
    assert_eq!(fs::read_to_string(&file).unwrap(), "");
}

#[test]
fn install_resolves_a_relative_destination_against_the_working_directory() {
    let ws = workspace();
    let installed =
        ok(install_cmd(&ws.home, Path::new("./nested/./skills/")).current_dir(&ws.root));
    assert_eq!(
        installed["destination"],
        ws.root.join("nested/skills/turnkey-tk").to_str().unwrap()
    );
    assert!(ws.root.join("nested/skills/turnkey-tk/SKILL.md").is_file());
}

#[test]
fn install_into_an_unwritable_directory_leaves_nothing_behind() {
    let ws = workspace();
    fs::create_dir(&ws.into).unwrap();
    fs::set_permissions(&ws.into, fs::Permissions::from_mode(0o555)).unwrap();
    let error = record(&mut install_cmd(&ws.home, &ws.into), 1);
    fs::set_permissions(&ws.into, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(error["reason"], "command_error", "{error}");
    assert_eq!(error["code"], "command_error", "{error}");
    assert_eq!(
        error["message"],
        format!(
            "stage turnkey-tk under {}: {}",
            ws.into.display(),
            io::Error::from_raw_os_error(13)
        ),
        "{error}"
    );
    assert_eq!(fs::read_dir(&ws.into).unwrap().count(), 0);
}

#[test]
fn commands_run_with_an_empty_home() {
    let ws = workspace();
    let listed = ok(bare(Path::new("")).args(["skills", "list", "--message-format", "json"]));
    assert_eq!(listed["reason"], "skills_listed", "{listed}");

    let installed = ok(bare(Path::new(""))
        .args(["skills", "install", "--message-format", "json", "--into"])
        .arg(ws.root.join("skills")));
    assert_eq!(installed["alreadyInstalled"], false, "{installed}");
}
