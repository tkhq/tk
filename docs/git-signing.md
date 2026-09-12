# Git signing

`tk` can sign Git commits and tags either as Git's SSH signing program, backed
by your Turnkey Ed25519 key, or as its GPG program, backed by a Turnkey
OpenPGP key.

Ensure you have followed the [configuration section of the repository readme](../README.md#configuration).

## SSH signing

```bash
git config --global gpg.format ssh
git config --global gpg.ssh.program "$(which tk)"
git config --global user.signingkey "key::$(tk public-key)"
printf '%s %s\n' "you@example.com" "$(tk public-key)" >> ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
```

After this setup, Git can use `tk git-sign` through the configured SSH signing program when creating signed commits or tags. It is invoked with `tk -Y` since that is how Git expects to invoke the given ssh program.

## GPG signing

Point Git at `tk` as its `gpg.program` and set `user.signingkey` to the
fingerprint of a registered Turnkey OpenPGP key. See
[GPG signing](./gpg-signing.md) for the full setup.
