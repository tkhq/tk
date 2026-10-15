# Releasing `tk`

Push a `v*` tag to start the `release` workflow. The workflow builds a native
binary for every supported target, checksums each one, and publishes a GitHub
release. `install.sh` and `tk update` install from that release.

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

## The manifest is the version

`tk --version` reports the manifest version, and the release tag must match it.
That version lives in `[package]`, so bumping it there is what moves the
release.

## Publishing to crates.io

The package is `turnkey_tk`, because `tk` is taken on crates.io, and it ships
one binary named `tk`. `include` carries `src/`, `build.rs`, `skills/`, and
`docs/`, because the build script embeds the skills package and rebases its
links into `docs/`:

```sh
# Builds the tarball and compiles it in isolation, which the tests are left out of.
cargo package

# Publishes that tarball; the git tag and the GitHub release are separate.
cargo publish
```

## Artifact contract

Each release publishes two files for every target:

```
tk-<target>-<vX.Y.Z>.tar.gz          # one directory, tk-<target>-<vX.Y.Z>/, holding tk and README.md
tk-<target>-<vX.Y.Z>.tar.gz.sha256   # `shasum -a 256` output (hash and filename)
```
