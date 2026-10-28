# Releasing `tk`

Push a `v*` tag to start the `release` workflow. The workflow builds a native
binary for every supported target, checksums and signs each archive, publishes
`turnkey_tk` to crates.io, and then publishes a GitHub release. `install.sh`,
`tk update`, and `cargo binstall turnkey_tk` install from that release.

The repository needs an Actions secret named `CARGO_REGISTRY_TOKEN` holding a
crates.io token that can publish `turnkey_tk`.

1. Open a pull request that bumps `version` under `[package]` in the root
   `Cargo.toml` and refreshes the pinned entry in `Cargo.lock`, and wait for CI
   to pass. CI, the tag validation, and the release build run with `--locked`,
   so a stale lockfile fails all three:

   ```sh
   cargo update -p turnkey_tk --offline
   ```
2. Merge it to `main`.
3. Tag the merge commit with the same version prefixed by `v` and push the
   tag:

   ```sh
   git switch main && git pull --ff-only
   git tag v0.2.0
   git push origin v0.2.0
   ```

## Rules

- **The tag must equal `v` plus the manifest version and point at a commit
  already on `main`.** The `validate` job refuses any other tag,
  including release candidates, which the installer would otherwise treat as
  the latest stable release, and any tagged commit that is not an ancestor of
  `origin/main`.
- **Wait for `main` CI to pass on the commit before tagging it.** The release
  workflow builds the binaries but does not run the test suite.
- **Never move or reuse a published tag.** Bump to a new version instead. The
  installer resolves versions by tag name.
- **Never run `cargo publish` by hand.** The `publish` job pins the release's
  signing key into the published manifest; a hand-published version carries no
  key and makes the `publish` job fail.
- **Rerun failed jobs rather than the whole workflow.** A full rerun generates
  a new signing key, which no longer matches the key a successful `publish`
  already put on crates.io.

## The manifest is the version

`tk --version` reports the manifest version, and the release tag must match it.
That version lives in `[package]`, so bumping it there is what moves the
release.

## Signing

The `sign` job generates a minisign keypair for this run only, signs every
archive, verifies each archive against its checksum and signature, and deletes
the secret key when the step exits. The `publish` job appends the public key to
`Cargo.toml` as `[package.metadata.binstall.signing]` before `cargo publish`,
so the crates.io package of each version names the only key that can have
signed it. The `prerelease` workflow stays checksum-only, because a prerelease
has no crates.io package to carry its key.

## Publishing to crates.io

The package is `turnkey_tk`, because `tk` is taken on crates.io, and it ships
one binary named `tk`. `include` carries `src/`, `build.rs`, `skills/`, and
`docs/`, because the build script embeds the skills package and rebases its
links into `docs/`:

```sh
# Builds the tarball and compiles it in isolation, which the tests are left out of.
cargo package
```

## Artifact contract

Each release publishes three files for every target, plus the public key
that verifies them:

```
tk-<target>-<vX.Y.Z>.tar.gz          # one directory, tk-<target>-<vX.Y.Z>/, holding tk and README.md
tk-<target>-<vX.Y.Z>.tar.gz.sha256   # `shasum -a 256` output (hash and filename)
tk-<target>-<vX.Y.Z>.tar.gz.sig      # minisign signature of the archive
minisign.pub                         # the key generated for this release
```
