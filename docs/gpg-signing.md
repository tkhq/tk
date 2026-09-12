# GPG signing

`tk` signs Git commits with an OpenPGP key backed by a Turnkey wallet
account. The private key never leaves Turnkey.

```sh
# Create a wallet to hold the signing key, if you don't have one.
tk wallet create --input-json '{"walletName": "gpg", "accounts": []}'

# Create and register a signing key under that wallet.
tk gpg keys create --wallet-id <wallet uuid> --user-id "Your Name <you@example.com>"

# Import the public key into your local GnuPG keyring.
tk gpg keys export | gpg --import

# Trust the key so gpg doesn't warn when verifying.
echo "<FINGERPRINT>:6:" | gpg --import-ownertrust

# Point git at tk as the GPG program.
git config --global gpg.format openpgp
git config --global gpg.program tk
git config --global user.signingkey <FINGERPRINT>
git config --global commit.gpgsign true

# Sign and verify a commit. `git tag -s` works the same way.
git commit -S --allow-empty -m test
git verify-commit HEAD
```

To add the key to GitHub, paste the output of `tk gpg keys export` into
Settings, SSH and GPG keys, New GPG key.

## Key management

```sh
tk gpg keys list                                          # registered keys (add --wallet-id to scope to one wallet)
tk gpg keys add --wallet-id <uuid> [--key <fingerprint>]  # register an existing wallet key
tk gpg keys remove <fingerprint>                          # forget a key; leaves the wallet account in place
```

## Notes

- `user.signingkey` must be a registered key's fingerprint (hex, 16+ chars)
  or, if unset, must equal the committer's user ID exactly.
- The registered key's organization selects the credential; use `--profile`,
  `TK_PROFILE`, or `--organization-id` to pick explicitly when you have more
  than one profile for that organization.
- A policy that requires approval blocks signing; use a policy that lets the
  API key sign without approval.
- `git verify-commit` runs the real `gpg` binary; set `TK_GPG_PROGRAM` if
  `gpg` isn't on `PATH`.
