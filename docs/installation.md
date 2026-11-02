# Installation and updates

The shell installer and `update` download published `tk` archives from GitHub.
Stable releases require a signature from the pinned Turnkey release key.

```bash
# Install minisign before running the installer on macOS.
brew install minisign
```

```bash
# Install minisign before running the installer on Debian and Ubuntu.
sudo apt-get install minisign
```

```bash
# Install the latest release for this machine.
curl --proto '=https' --tlsv1.2 -LsSf https://raw.githubusercontent.com/tkhq/tk/main/install.sh | sh
```

The installer stops before extraction if the signature is missing or invalid.
Set `TK_INSTALL_DIR` to an absolute path to change the default destination,
`$HOME/.local/bin`.

## Verify a download in Bash

```bash
set -euo pipefail

# Pin the release key independently of the assets being downloaded.
PUBLIC_KEY='RWSDsovatPaWT9HcRg0VXl7ARwrjhixImIcBBqb9z7XE74uvlvfCt2XD'
VERSION='RELEASE_TAG'
TARGET='x86_64-unknown-linux-musl'
ARCHIVE="tk-$TARGET-$VERSION.tar.gz"
BASE="https://github.com/tkhq/tk/releases/download/$VERSION"

# Download the archive and its detached signature.
curl --proto '=https' --tlsv1.2 -fLO "$BASE/$ARCHIVE"
curl --proto '=https' --tlsv1.2 -fLO "$BASE/$ARCHIVE.sig"

# Extract only after minisign verifies the archive.
minisign -Vm "$ARCHIVE" -x "$ARCHIVE.sig" -P "$PUBLIC_KEY"
tar -xzf "$ARCHIVE"
```

`minisign` exits unsuccessfully on an invalid signature; `set -e` stops the
script before extraction. A downloaded `minisign.pub` is a copy for inspection;
trust the pinned key independently of the GitHub release assets.

## Update an installed binary

```bash
# Replace the running installation with the latest signed release.
tk update
```

`update` verifies the checksum and signature in Rust, so it requires no
external `minisign` executable. A verification failure returns exit status 1
with `code: "command_error"` and leaves the installed binary intact. A missing
signature returns `not_found`. Older stable releases published without
signatures cannot be installed by this updater or the current shell installer.
A Cargo-managed installation returns `reason: "update_via_cargo"` and the
command to run instead of replacing the binary. An installation already at or
above the latest release returns `reason: "already_up_to_date"`.

## Prereleases

```bash
# Select a pull request build with the shell installer.
TK_VERSION=pr-44-abc1234 sh install.sh

# Replace an archive installation with a pull request build.
tk update --tag pr-44-abc1234
```

Explicit `pr-*` and `dev-*` tags use checksums only. They are not signed by the
stable release key. The installer prints this distinction before downloading.
The `--tag` option also accepts a stable release tag, including an older one.

## Skills

- [bootstrapping-organization](../skills/bootstrapping-organization/SKILL.md): install and verify the CLI before saving an organization credential.
