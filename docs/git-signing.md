# Git signing

Use `tk` as Git's SSH signing program after configuring your Turnkey credentials.

Ensure you have followed the [configuration section of the repository readme](../README.md#configuration).

```bash
git config --global gpg.format ssh
git config --global gpg.ssh.program "$(which tk)"
git config --global user.signingkey "key::$(tk public-key)"
printf '%s %s\n' "you@example.com" "$(tk public-key)" >> ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
```

After this setup, Git can use `tk git-sign` through the configured SSH signing program when creating signed commits or tags. It is invoked with `tk -Y` since that is how Git expects to invoke the given ssh program.
