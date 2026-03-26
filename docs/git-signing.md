# Git signing

Use `tk` as Git's SSH signing program to sign commits and tags with your Turnkey wallet key.

Ensure you have run `tk init` first (see the [quick start](../README.md#quick-start)).

```bash
git config --global gpg.format ssh
git config --global gpg.ssh.program "$(which tk)"
git config --global user.signingkey "key::$(tk public-key)"
printf '%s %s\n' "you@example.com" "$(tk public-key)" >> ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
```

After this setup, Git invokes `tk -Y sign` when creating signed commits or tags.
