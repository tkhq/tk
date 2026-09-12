# GPG signing

`tk` acts as a GPG program for Git. It signs commits with an OpenPGP key
backed by a Turnkey wallet account. The private key never leaves Turnkey.
`tk` sends only a SHA-256 digest to Turnkey for signing.

The key signs and certifies. It does not decrypt, so the exported block
carries no encryption subkey.

## Setup

1. Log in with `tk login`. Step 3 saves the key target in that profile.

2. Create a signing key in a wallet:

   ```sh
   tk gpg keys create --wallet-id <wallet uuid> --user-id "Your Name <you@example.com>"
   ```

   Note the fingerprint in the output.

3. Save the wallet and key index for later commands:

   ```sh
   tk gpg use --wallet-id <wallet uuid> --key-index 0
   ```

4. Import the public key into GnuPG:

   ```sh
   tk gpg keys export | gpg --import
   ```

   `tk gpg keys export` signs the self certification with the key, so a
   policy that requires approval blocks it.

5. Trust the imported key:

   ```sh
   echo "<FINGERPRINT>:6:" | gpg --import-ownertrust
   ```

6. Point Git at `tk`:

   ```sh
   git config --global gpg.format openpgp
   git config --global gpg.program tk
   git config --global user.signingkey <FINGERPRINT>
   git config --global commit.gpgsign true
   ```

   Set `user.signingkey` to the fingerprint. Git sends that value to `tk`,
   and `tk` signs with the key it names. A fingerprint names one key, in one
   wallet, whatever the wallet holds.

7. Add the key to GitHub. Run `tk gpg keys export`. Paste the output into
   GitHub Settings, SSH and GPG keys, New GPG key.

8. Check the setup:

   ```sh
   git commit -S --allow-empty -m test
   git verify-commit HEAD
   ```

## Key selection

Git sends the `user.signingkey` value to `tk`. `tk` reads it two ways. A hex
value of 16 characters or more names a key by its fingerprint. Any other
value must equal a key's user ID exactly, which is what git sends when
`user.signingkey` is unset. A value that names no key fails the commit. `tk`
never signs with a key git did not ask for.

`tk` uses the saved key index only when git names no key.

## Consensus

A policy can require approval before Turnkey signs. A key behind such a
policy cannot sign for Git and cannot export. Each run signs a new digest
and opens a new activity, so approving one activity does not complete a
later run. The command fails with `approval_required` and names the activity
id for the audit trail. Use a policy that lets the API key sign without
approval.

## Signing access

`tk` asks for no prompt and no touch. Any process that can run
`git commit -S` in your session gets a signature under the profile's
credential. The policy on the API key is the only limit.

## Verification

Git also runs `tk` for verification calls, such as `git verify-commit`. `tk`
detects these calls and runs the real `gpg` binary instead of signing. Set
`TK_GPG_PROGRAM` when `gpg` is not on `PATH`. `tk` runs that program with
the caller's arguments, so set it only to a binary you trust.

## Environment

`TK_GPG_WALLET_ID` and `TK_GPG_KEY_INDEX` override the wallet and key index
saved by `tk gpg use`. If you use the `TURNKEY_*` environment bundle instead
of a profile, set both variables. `tk gpg use` needs a profile.

`tk gpg keys create` takes `--at-index` for the slot to create at. The
command fails when that index already holds an account. No environment
variable sets that slot.

`tk gpg use` writes a `gpg` table into the profile registry. An older `tk`
binary rejects the whole registry once that table is there, not only the
table it does not know. Every `tk` command on that machine then fails with
"invalid identity registry". Upgrade `tk` everywhere before you run
`tk gpg use`.

`tk login` writes a new profile and does not carry a saved target into it.
Run `tk gpg use` again for a new profile.
