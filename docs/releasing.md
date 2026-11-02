# Releasing `tk`

Push a `v*` tag to start the `release` workflow. The workflow builds a native
binary for every supported target, checksums and signs each archive, and
publishes a GitHub release. `install.sh` and `tk update` install from that release.

The repository needs an Actions secret named `TK_RELEASE_SIGNING_KEY` holding
the complete passwordless minisign private key matching `keys/release.pub`.

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

## Signing

The `sign` job writes `TK_RELEASE_SIGNING_KEY` to a private temporary file,
signs every archive, and removes that file when the step exits. It verifies
each archive's checksum and signature against `keys/release.pub` before
publication.

The public key is pinned in the shell installer and embedded in the updater.
See [installation](./installation.md) for verifying a download in Bash and
for prerelease verification behavior. The `prerelease` workflow has no access
to the signing secret. Rotating the signing key requires distributing the new
public key to installers and existing installations before signing with it.

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

Each release publishes three files for every target, plus the public key
that verifies them:

```
tk-<target>-<vX.Y.Z>.tar.gz          # one directory, tk-<target>-<vX.Y.Z>/, holding tk and README.md
tk-<target>-<vX.Y.Z>.tar.gz.sha256   # `shasum -a 256` output (hash and filename)
tk-<target>-<vX.Y.Z>.tar.gz.sig      # minisign signature of the archive
minisign.pub                         # a copy of keys/release.pub
```
