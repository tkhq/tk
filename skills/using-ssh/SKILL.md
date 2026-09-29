---
name: using-ssh
description: Give an agent SSH access (git over SSH, remote hosts) with a Turnkey-held Ed25519 key served by tk ssh agent, so no private key is on disk. Use to register a key, start the agent, point git or ssh at the socket, or restart it after a credential rotation; not for commit signing (signing-git-commits).
---

# Using SSH

Result: an agent that authenticates to git hosts and remote machines with an
Ed25519 key that exists only inside Turnkey. `tk ssh agent` answers the
OpenSSH agent protocol on a Unix socket and turns each challenge into a
policy-checked signing activity under the agent's own credential.

Inputs: the root profile (`admin`), the agent's profile (`agent`) and tag id
(`AGENT_TAG`), and the host or git host that will hold the public key.

## Reference

- [ssh](../../docs/ssh-agent.md): `ssh keys`, `ssh public-key`, and `ssh agent` records and default paths.
- [resources](../../docs/resources.md): the `policy create` record that scopes signing to one `private_key.id`.
- [activities](../../docs/activities.md): `activity list` and `policy evaluations` on a failed signing activity.

## Rules

- Root creates the Turnkey private key once with `ssh keys create`, which
  also registers it in root's own registry. The agent host registers the
  same id with `ssh keys add`, which needs nothing but the id. The private
  key never leaves Turnkey and there is nothing to back up on the host.
- The signing policy is allow-always, scoped by `private_key.id`
  (`agents-sign-ssh` in [policy-patterns.md](../references/policy-patterns.md)).
  SSH waits for the signature synchronously, so an approval-gated policy
  makes every connection fail, not wait.
- Socket access is signing authority. The socket lives in the principal's own
  home and is never forwarded off the host; under the broker path it is
  shared with the application alone, read-only, and nothing else crosses.
- The daemon resolves its API credential once, at start. After the agent's
  API key changes, stop and start the daemon; a running daemon keeps signing
  with the old key until that key is revoked, then every signature fails.
- The registry is `~/.config/turnkey/tk.config.toml` under the `HOME` of the
  process that runs `ssh keys add` and `ssh agent start`. Pin `HOME` and
  `--profile` explicitly where the daemon runs; a service with a different
  home sees an empty registry.
- Host-key verification stays on. `tk` replaces the client key, not the
  trust in the server.
- When a signing broker holds signing for this deployment, do not create
  `agents-sign-*` policies. Run this workflow as the broker principal instead:
  the step 2 policy names `BROKER_TAG` in place of `AGENT_TAG`, step 4 runs
  `tk ssh agent start --key SSH_FINGERPRINT` under the broker's `HOME`, and
  the application receives only the socket, never the broker's profile.

## Instructions

1. **Create the private key.** Root, once:

   <!-- example: ssh.create-key -->
   ```sh
   tk --profile admin --message-format json ssh keys create --name agent-ssh
   ```

   Save the record's `privateKeyId` as `PRIVATE_KEY_ID`; the policy and the
   agent host both need it. Rerunning with the same name registers the
   existing key instead of creating a second one.

2. **Allow the agent to sign with that key.** Root:

   <!-- shared: agents-sign-ssh -->
   <!-- example: ssh.policy -->
   ```sh
   tk --profile admin --message-format json policy create --name agents-sign-ssh --effect allow \
     --consensus "approvers.any(user, user.tags.contains('AGENT_TAG'))" \
     --condition "activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2' && private_key.id == 'PRIVATE_KEY_ID'"
   ```

   One policy per key. A key without a matching policy is still listed by
   the agent, and every signature with it is refused.

3. **Register the key and publish the public half.** The agent, in the home
   the daemon will use:

   <!-- example: ssh.register -->
   ```sh
   tk --profile agent --message-format json ssh keys add --private-key-id PRIVATE_KEY_ID
   tk --profile agent --message-format json ssh public-key --key PRIVATE_KEY_ID | jq -r .publicKey > ./agent-ssh.pub
   ```

   Install `agent-ssh.pub` where the server expects it: the
   remote `authorized_keys`, or the git host's SSH key settings for the
   agent's account. That step is manual and outside `tk`.

4. **Start the agent.** The agent identity, with `--profile` explicit:

   <!-- example: ssh.agent-start -->
   ```sh
   tk --profile agent --message-format json ssh agent start
   export SSH_AUTH_SOCK=~/.config/turnkey/ssh-agent.sock
   tk --profile agent --message-format json ssh agent status
   ```

   `agent_started` carries `pid`, `socket`, and the `keys` fingerprints it
   serves; `agent_status_report` repeats them while it runs. An unattended
   deployment passes `--key SSH_FINGERPRINT` so the daemon serves one key;
   custom socket and pid-file paths are in [ssh](../../docs/ssh-agent.md#agent).

5. **Point clients at the socket and verify.** Per repository, or per
   connection:

   ```sh
   SSH_OPTS="-o IdentityAgent=~/.config/turnkey/ssh-agent.sock -o IdentitiesOnly=yes -o IdentityFile=./agent-ssh.pub"
   git config core.sshCommand "ssh $SSH_OPTS"
   ssh $SSH_OPTS user@host
   ```

   `IdentitiesOnly` with the public key file stops ssh from offering keys it
   finds on disk, so only the Turnkey key is ever presented.

   Verify the chain without a server, with OpenSSH tools only:

   <!-- example: ssh.verify -->
   ```sh
   ssh-add -L
   ssh-keygen -Y sign -n git -U -f ./agent-ssh.pub ./payload.txt
   ssh-keygen -Y check-novalidate -n git -f ./agent-ssh.pub -s ./payload.txt.sig < ./payload.txt
   ```

   `ssh-add -L` lists each served key as `ssh-ed25519 ... turnkey:PRIVATE_KEY_ID`.
   The sign step writes `payload.txt.sig` through the socket; the check
   step accepts it. Both exit `0` or the key is not usable yet.

6. **Restart after a credential rotation.** After the agent's API key
   changed (`profile set --api-key-file`, or `session activate` on the
   session route), as the agent:

   <!-- example: ssh.rotate -->
   ```sh
   tk --profile agent --message-format json ssh agent stop
   tk --profile agent --message-format json ssh agent start
   ```

   `agent_stopped` then `agent_started`. Restart before the old key is
   deleted; the old daemon signs until then and fails afterwards with no
   local symptom other than refused connections.

7. **Hand off.** Report `PRIVATE_KEY_ID`, the fingerprint and public key
   line, the policy id, the socket path, and the exact `start` command the
   agent's process runs. Stop.

## Verified by

| Examples | Test |
|---|---|
| ssh.create-key, ssh.policy, ssh.register, ssh.agent-start, ssh.verify, ssh.rotate | ssh_agent::using_ssh_register_serve_sign |
| ssh.agent-start | ssh_agent::agent_serves_every_registered_key_and_reports_its_lifecycle |
| ssh.register | ssh::ssh_key_register_list_print_and_remove_by_every_name |

## Troubleshooting

- `ssh agent start` exits `1` with `invalid_input` "the registry holds no
  SSH keys" or "no registered SSH key matches": step 3 was skipped or ran
  under another `HOME`. Register in the home the daemon uses.
- `ssh agent status` exits `1` with `command_error` "ssh-agent is not
  running": nothing holds the pid file. Start it; if `--socket` or
  `--pid-file` were given at start, give them here too.
- `ssh agent start` exits `1` with `command_error` "ssh-agent is already
  running on": stop that one first, or start on another `--socket` and
  `--pid-file`.
- `ssh-keygen -Y sign` or `ssh` fails with "agent refused operation" while
  `ssh-add -L` lists the key: Turnkey denied the signature. As root, run
  `tk --profile admin --message-format json activity list --limit 5`
  and `tk --profile admin --message-format json policy evaluations ACTIVITY_ID`
  on the failed `SIGN_RAW_PAYLOAD` activity; the usual cause is a policy
  scoped to a different `private_key.id` or a consensus that names the
  wrong tag. Do not start the daemon as root instead.
- Signatures were refused right after the agent's API key changed: the
  daemon still holds the old credential. Run step 6.
- `ssh keys add` exits `1` with `invalid_input` naming another curve: the
  id is an existing non-Ed25519 key. Create one with step 1.
- The key is served but the server rejects it: the public key line is not
  installed on that host or account; compare it with `ssh public-key`.

## Related Skills

- [signing-git-commits](../signing-git-commits/SKILL.md): sign commits with
  the same registered key, or with an OpenPGP key.
- [managing-identities](../managing-identities/SKILL.md): the agent user,
  its profile, and the credential rotation that requires step 6.
- [managing-policies](../managing-policies/SKILL.md): debugging the
  `agents-sign-ssh` scope with `policy evaluations`.
- [provisioning-session-agent](../provisioning-session-agent/SKILL.md):
  when the agent's key expires and renews, and the daemon restart that
  follows each renewal.
- [sidecar-patterns](../sidecar-patterns/SKILL.md): where the daemon and
  socket live when the agent runs in its own OS user or container.
