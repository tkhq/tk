//! Release pipeline invariants that a broken release would otherwise be the
//! first to catch.
use std::{collections::BTreeSet, fs, path::Path};

const WORKFLOW: &str = include_str!("../.github/workflows/release.yml");
const INSTALLER: &str = include_str!("../install.sh");
const UPDATER: &str = include_str!("../src/update.rs");

#[test]
fn release_tag_must_name_the_manifest_version_and_be_on_main() {
    assert!(WORKFLOW.contains(r#"if [ "$GITHUB_REF_NAME" != "v$manifest_version" ]; then"#));
    assert!(WORKFLOW.contains("fetch-depth: 0"));
    assert!(WORKFLOW.contains(r#"git merge-base --is-ancestor "$GITHUB_SHA" origin/main"#));
    assert!(WORKFLOW.contains("needs: validate"));
}

#[test]
fn every_action_is_pinned_to_a_commit_with_a_version_comment() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows");
    let workflows: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert!(!workflows.is_empty());
    for path in workflows {
        let name = path.display();
        let workflow = fs::read_to_string(&path).unwrap();
        let uses = workflow.lines().filter_map(|line| {
            let line = line.trim_start();
            line.strip_prefix("- ")
                .unwrap_or(line)
                .strip_prefix("uses: ")
        });
        for reference in uses {
            let (action, comment) = reference
                .split_once(" # ")
                .unwrap_or_else(|| panic!("{name}: `{reference}` should carry a version comment"));
            let (_, sha) = action.split_once('@').unwrap();
            assert!(
                sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()),
                "{name}: `{action}` should be pinned to a full commit SHA"
            );
            assert!(!comment.trim().is_empty());
        }
    }
}

#[test]
fn installer_targets_match_the_build_matrix() {
    let matrix: BTreeSet<_> = WORKFLOW
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("target: "))
        .collect();
    let installer: BTreeSet<_> = INSTALLER
        .lines()
        .filter_map(|line| line.split_once(r#"target=""#)?.1.split('"').next())
        .collect();
    assert_eq!(matrix.len(), 3);
    assert_eq!(installer, matrix);
}

#[test]
fn updater_targets_match_the_build_matrix() {
    let matrix: BTreeSet<_> = WORKFLOW
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("target: "))
        .collect();
    let updater: BTreeSet<_> = UPDATER
        .lines()
        .filter_map(|line| line.trim().strip_prefix(r#"Some(""#)?.strip_suffix(r#"")"#))
        .collect();
    assert_eq!(updater, matrix);
}
