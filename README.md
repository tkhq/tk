<img width="1500" height="500" alt="tk" src="assets/banner.png" />

<h4 align="center">
    Git signing and SSH for agents, with keys that never leave Turnkey.
</h4>

`tk` lets an agent sign Git commits and open SSH connections without a private
key on its machine. Turnkey holds the key, enforces expressive policies on
every signature, and logs every approval.

- **Git signing**: `tk` acts as Git's SSH or GPG signing program, so
  `git commit -S` and `git verify-commit` work unchanged.
- **SSH**: `tk ssh agent` serves Turnkey keys on a standard `SSH_AUTH_SOCK`, so
  `ssh`, `git push`, and `git clone` over SSH work unchanged.

## Local agents

For an agent on your laptop, for example Claude Code or Codex in a terminal:

- **No key for the agent to read**: the signing and SSH keys stay in Turnkey,
  not in `~/.ssh` or a GnuPG keyring that the agent could read or copy.
- **Its own identity**: the agent signs and connects with its own key, not
  yours, so its commits are attributable and its access can be revoked
  without touching your keys.
- **Policy and audit**: expressive Turnkey policies decide which keys the
  agent may use, and Turnkey logs every signature and approval.

## Background agents

For an unattended agent in CI, a container, or a VM, the agent never holds a
long-lived credential:

- **Expiring session keys**: the agent generates its own API key, and a
  separate provisioner registers it with an expiry and renews it.
- **Signing broker**: a separate process holds the signing credential. The
  agent gets only a Unix socket and a public key.
- **Policy-scoped signing**: each agent can sign only with the keys a policy
  names. Revoking its API key cuts it off at once.

## Getting started

Paste this into your agent:

```
Install the Turnkey tk CLI with
`curl --proto '=https' --tlsv1.2 -LsSf https://raw.githubusercontent.com/tkhq/tk/main/install.sh | sh`.
Install the tk skills with `tk skills install --into <your skills directory>`,
read the installed turnkey-tk/SKILL.md, and walk me through bootstrapping my
Turnkey organization at https://app.turnkey.com.
```

## Manual installation

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://raw.githubusercontent.com/tkhq/tk/main/install.sh | sh
```

## Docs

Git signing and SSH:

- [Git signing](./docs/git-signing.md): sign commits and tags with SSH or GPG keys held in Turnkey
- [SSH](./docs/ssh-agent.md): registered keys and the SSH agent
- [GPG signing](./docs/gpg-signing.md): OpenPGP keys, the GPG agent, and GitHub setup

Running background agents:

- [Sessions](./docs/sessions.md): expiring keys registered by a provisioner
- [Secrets](./docs/secrets.md): inject credentials into an agent at startup

Foundations:

- [Authentication](./docs/authentication.md): profiles and the environment bundle
- [Resources](./docs/resources.md): users, policies, API keys, and wallets
- [Activities](./docs/activities.md): inspect, approve, reject, and wait
- [Signing](./docs/signing.md): payloads and serialized transactions
- [Raw requests](./docs/requests.md): sign and send an exact request body
- [Skills](./docs/skills.md): the agent skills package embedded in the binary
- [Command reference](./docs/commands.md): every command and flag, generated from the parser

## Contact us

`tk` is part of Turnkey's agent auth beta. To ask a question or tell us what
your agents need, reach us at
[turnkey.com/agent-auth-beta](https://www.turnkey.com/agent-auth-beta).

For the thinking behind this project, see
[this thread](https://x.com/ZekeMostov/status/2100277046207266887).
