# Releasing `tk`

Cutting a tag is the whole release process. Pushing a `v*` tag runs the
`release` workflow, which builds native binaries for every supported target,
checksums them, and publishes a GitHub release that the installer picks up.

## Cut a release

```sh
# from a clean, up-to-date main
git fetch origin
git switch main
git pull --ff-only
git tag v0.2.0
git push origin v0.2.0
```

## Rules

- **The tag must point at a commit already on `main`.** The workflow's
  `validate` job refuses to release a tagged commit that is not an ancestor of
  `origin/main`, so tagging a branch tip fails the release.
- **Wait for `main` CI to pass on the commit before tagging it.** The release
  workflow builds, but it does not run the test suite.
- **Never move or reuse a published tag.** If a release is wrong, bump to a new
  version and cut a new tag. The installer and the self-updater resolve
  versions by tag name, so a moved tag would silently change what an existing
  version means.

## The tag is the version

The manifest version in `Cargo.toml` stays at `0.1.0` and is never bumped for a
release. Nothing publishes to crates.io, so a bump would buy nothing a user can
see. Instead the release workflow passes the tag to the build as
`TK_RELEASE_VERSION`, and `tk/build.rs` bakes it into the binary as
`TK_VERSION`. `tk --version` reports that value. Local builds fall back to
`git describe --tags`, then to the manifest version.

There is no version-bump script and no release PR. Revisit this when `tk` is
published to crates.io: at that point the manifest version has to match the
tag, `validate` should assert it, and `cargo-release` or `release-plz` is the
right tool rather than a hand-rolled script.

Because a tag has no corresponding version-bump commit, `git log` alone does not
show what shipped when. The release job asks GitHub to generate release notes
from the merged pull requests since the previous tag; if richer notes are
wanted, generate them in the release job with `git-cliff` rather than
reintroducing a bump commit.

## Artifact contract

Every release publishes, for each target:

```
tk-<target>-<vX.Y.Z>.tar.gz          # contains one directory, tk-<target>-<vX.Y.Z>/
tk-<target>-<vX.Y.Z>.tar.gz.sha256   # `shasum -a 256` output (hash and filename)
```

The archive directory holds `tk` and `README.md`. Targets are built
on native runners, without cross-compilation:

| target                      | runner            |
| --------------------------- | ----------------- |
| `x86_64-unknown-linux-gnu`  | `ubuntu-22.04`    |
| `aarch64-unknown-linux-gnu` | `ubuntu-22.04-arm`|
| `aarch64-apple-darwin`      | `macos-latest`    |
| `x86_64-apple-darwin`       | `macos-15-intel`  |

`install.sh` at the repository root depends on this layout: it resolves the
latest tag from the `/releases/latest` redirect, downloads the archive and its
checksum, requires the checksum file to name that exact archive, inspects the
archive listing before extracting only the binary, smoke-tests it, and moves it
into place atomically. Change the naming scheme and the installer together.

Checksums come from the same release as the archives, so GitHub is the trust
boundary. Artifact signing can be layered on later without changing this
layout.

## Workflow invariants

`tk/tests/release_pipeline.rs` parses the release workflow and the installer in
a normal `cargo test` run and asserts the rules above: the tag must be on
`main`, every action is pinned to a commit, caches are read-only, the build
matrix and installer agree on targets, and the published assets match the
artifact contract. Editing the workflow means keeping that test passing.
