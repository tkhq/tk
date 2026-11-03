//! Release pipeline invariants that a broken release would otherwise be the
//! first to catch.
use std::{collections::BTreeSet, fs, path::Path};

const WORKFLOW: &str = include_str!("../.github/workflows/release.yml");
const INSTALLER: &str = include_str!("../install.sh");
const UPDATER: &str = include_str!("../src/update.rs");
const E2E_UPDATE: &str = include_str!("e2e/update.rs");

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

#[test]
fn e2e_update_target_table_matches_the_updater() {
    let table = |source: &'static str| {
        let start = source.find("const TARGET: Option<&str> = ").unwrap();
        let len = source[start..].find("\n};\n").unwrap();
        &source[start..start + len]
    };
    assert_eq!(table(E2E_UPDATE), table(UPDATER));
}

#[test]
fn every_release_archive_gets_a_provenance_attestation() {
    let build = WORKFLOW
        .split_once("\n  build:\n")
        .and_then(|(_, rest)| rest.split_once("\n  release:\n"))
        .map(|(build, _)| build)
        .unwrap();
    assert!(build.contains("id-token: write"));
    assert!(build.contains("attestations: write"));
    assert!(build.contains("ARCHIVE: tk-${{ matrix.target }}-${{ github.ref_name }}.tar.gz"));
    assert!(build.contains("subject-path: ${{ env.ARCHIVE }}"));
    assert!(build.contains("BUNDLE: ${{ steps.provenance.outputs.bundle-path }}"));
    assert!(build.contains(r#"run: cp "$BUNDLE" "$ARCHIVE.sigstore.json""#));
    assert!(build.contains("${{ env.ARCHIVE }}.sigstore.json"));
    assert!(WORKFLOW.contains("dist/*.sigstore.json"));
}

#[test]
fn release_verification_covers_real_cosign_and_successful_updates() {
    let (_, release) = WORKFLOW.split_once("\n  release:\n").unwrap();
    let (before_publish, _) = release.split_once("softprops/action-gh-release@").unwrap();
    assert!(before_publish.contains("cosign-release: v3.1.4"));
    assert!(before_publish.contains(
        r#"sh ../.github/scripts/verify-release-provenance.sh "$archive" "$archive.sigstore.json" "$IDENTITY""#
    ));
    assert!(
        WORKFLOW
            .contains(r#""$TK_INSTALL_DIR/tk" --message-format json update --tag "$TK_VERSION""#)
    );
}
