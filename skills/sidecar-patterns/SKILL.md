---
name: sidecar-patterns
description: Run tk beside an unattended agent so the agent process holds only what it needs: separate credential stores, a renewal loop outside the agent, secrets injected at startup, an SSH socket per OS user, commit signing through a broker socket, and an operator alert that does not depend on the agent's own credential. Use when deploying an agent that uses tk on a VM or in a container, or when a deployment keeps losing its session key; not for choosing policies or approval models.
---

# Sidecar patterns

Result: a deployment where the agent reads its secrets once at startup, a separate renewal
loop keeps the agent's expiring credential fresh, SSH goes through a socket, git signs
commits through a broker's socket, and an operator hears about an expired credential from
something other than the agent. Every `tk` step in this workflow is a command another workflow already documents; this workflow fixes where each one runs and what state it keeps.

## Reference

- [sessions](../../docs/sessions.md): the four `session` commands and their records.
- [secrets](../../docs/secrets.md): `secret env` and pending exports.
- [ssh-agent](../../docs/ssh-agent.md): the agent socket and its lifecycle.
- [gpg-signing](../../docs/gpg-signing.md): `gpg agent serve` and the client socket.
- [authentication](../../docs/authentication.md): the `whoami` record and how `HOME` and `TK_PROFILE` select a profile.

## Rules

- Separation means one boundary (a container, VM, sandbox, or OS user), one
  `HOME`, one process tree, and one set of mounts per principal; the agent's
  profile and the provisioner's profile never share a credential directory.
  Separate OS users are the default. Under the shared-uid socket model the
  application and broker share a numeric uid and nothing else, and the
  application mounts the broker's runtime directory read-only. Host root can
  still read every boundary; no boundary is a secrecy boundary against the host.
- The renewal loop is the single writer of the agent's profile. Its agent-side
  half (status, request, activate) runs as the agent's OS user on a timer outside
  the agent's own control loop; its provisioner-side half (provision) runs as the
  provisioner. Both hold a lock while they run, update their state file atomically,
  and persist the agent's user id so renewal works after the current key has expired.
- Secrets go from `tk secret env` into the authorized process's environment.
  No file the agent can read holds a plaintext value; no transcript does.
- The public-key handoff from agent to provisioner is not secret but must
  be authenticated: the provisioner binds the request to the expected
  organization, agent user id, and lifetime before it mints anything.
- The SSH socket is signing authority. Bind it under the agent's `HOME`,
  mode-restricted to that OS user, or to a supplemental group when its
  clients run as another uid.
- The OpenPGP socket is signing authority too. The broker alone holds the signing
  profile, serves one fingerprint, and restarts after its own rotation. The agent's
  boundary gets the socket and the public key, never the broker's profile or
  registry, and the agent's own profile has no signing policy on that wallet.
- Alert on expiry from the loop, not from the agent: an expired agent cannot.
- A deployment that stages no provider secrets by hand still holds Turnkey
  credential files. Treat the host as secret-bearing.

## Instructions

Inputs: the agent profile (`agent`) and its persisted user id (`AGENT_USER_ID`), the
provisioner profile (`provisioner`) on the sidecar, the scope prefix (`service/`), the
chosen approval cell, and the key lifetime and renewal lead time. Prerequisites: the
agent and provisioner exist with their policies
([provisioning-session-agent](../provisioning-session-agent/SKILL.md)), and the
secrets are imported ([managing-secrets](../managing-secrets/SKILL.md)).

1. **Lay out the principals.** Decide, and record, which OS user, `HOME`,
   and profile each of these runs as: the agent process, the renewal loop
   (its agent half as `agent`, its provisioner half as `provisioner`), the
   SSH daemon (as `agent`), and the GPG broker (as `broker`). Install `tk` in
   the image or as a read-only host mount and check `tk --version` from each
   principal's shell; a missing binary at a bind-mount path becomes an empty
   directory, so check the file type, not just the path.

2. **Start the agent with its environment.** The agent's entrypoint runs,
   before the agent code starts:

   <!-- shared: secret-env-startup -->
   <!-- example: sidecar.startup-env -->
   ```sh
   tk --profile agent --message-format json secret env --name-prefix service/ --property consensus=unilateral
   ```

   Source `data.env` into the process and start it. Exit `1` with
   `approval_required` means an approval-gated secret is in the selection;
   keep those out of startup paths and fetch them on demand instead.

3. **Run the renewal loop.** On a timer shorter than the lifetime minus the
   lead time, once per expiring principal: `agent` and `broker` each run it
   as their own OS user with their own profile, state file, and lock. `status`,
   `request`, and `activate` run as that principal with its `HOME`; `provision`
   runs on the sidecar as the provisioner, reading the public key and user id
   from the handoff:

   <!-- example: sidecar.renew -->
   ```sh
   tk --message-format json session status --profile-name agent --warn-before 1h
   tk --message-format json session request --profile-name agent
   tk --profile provisioner --message-format json session provision --user-id AGENT_USER_ID --public-key PUBLIC_KEY --expires-in 4h
   tk --message-format json session activate --profile-name agent
   ```

   The tick is a state machine, not a script that runs all four lines:

   | Observed | Do |
   |---|---|
   | `session status` exits `0` | nothing; the key is healthy |
   | exits `1` with `session_expiring` and no pending request | `session request`; save `data.publicKey`; if `data.userId` is `null` use the persisted `AGENT_USER_ID` |
   | a pending request exists | `session provision`; `pending` means a human must approve; `alreadyRegistered: true` or `completed` means proceed |
   | provision completed | `session activate`, then `whoami` as that principal; for `broker`, restart the GPG broker (step 5) |
   | activate fails `unauthorized` | the key is not registered yet; leave the request in place and try next tick |
   | the mint activity was rejected | `session request --replace`, alert (step 6), start over next tick |

   Persist the state and the request's public key in one file written
   atomically; lock the whole tick so two timers cannot both request. Deleting
   an old key file locally revokes nothing; the anchor key stays.

4. **Serve SSH from a socket.** As the agent principal, in a directory only
   that user can enter, serving one pinned key:

   <!-- example: sidecar.ssh-agent -->
   ```sh
   install -d -m 0700 /run/agent
   tk --profile agent --message-format json ssh agent start --key SSH_FINGERPRINT --socket /run/agent/ssh.sock --pid-file /run/agent/ssh.pid
   # Clients under another uid: share the directory and socket with a supplemental group.
   install -d -m 0750 -g agents /run/agent
   tk --profile agent --message-format json ssh agent start --key SSH_FINGERPRINT --socket /run/agent/ssh.sock --pid-file /run/agent/ssh.pid --socket-mode 660
   ```

   Export `SSH_AUTH_SOCK=/run/agent/ssh.sock` in the agent's environment.
   The daemon picks up the key step 3 activates on its next signature.
   Registration is in [using-ssh](../using-ssh/SKILL.md).

5. **Sign commits through the broker.** Run `gpg agent serve` as `broker` per
   [deploying-signing-broker](../deploying-signing-broker/SKILL.md). It serves one
   `--key` on a socket in a runtime directory the agent side mounts read-only:
   `--socket-mode 660` shared through the agent's supplemental group, or `600` under
   the shared-uid model. The agent side gets `TK_GPG_AGENT_SOCK` and the public key,
   and none of the broker's profile, registry, or credential. A missing socket fails signing closed.

6. **Alert independently.** The loop, not the agent, raises an alert when
   `session status` reports `session_expiring` twice in a row, when a mint
   stays `pending` past the lead time, or when a mint is rejected. Include
   `details.publicKey`, `details.expiresAt`, and the activity id. The
   alert path uses no Turnkey credential.

7. **Gate the deployment.** Before the agent is left unattended, check by hand:

   | Check | Expect |
   |---|---|
   | separation | the model in force: separate OS users, or under the shared-uid model one uid for agent and broker with separate `HOME`s, process trees, and mounts |
   | `HOME`s | the agent's holds only its own profile; the sidecar's holds only the provisioner's |
   | SSH socket directory | `0700` to the agent's user, or `0750` to the shared group with a `0660` socket |
   | broker socket | its model: `0660` owned by the broker and the shared group, or `0600` owned by the shared uid |
   | timer | fires |
   | forced expiry (`--expires-in` shorter than the tick) | renews through the loop |
   | loop stopped | the alert fires |
   | `git commit -S` on the agent side | verifies with the broker up, fails with it stopped |
   | secrets | in the process environment and in no file |

8. **Hand off.** Report the principals table, the timer interval and lead
   time, the state file and lock paths, the socket path, the signing
   fingerprint, the alert channel, and the gate results. Stop.

## Runtime examples

These place steps, not requirements. Example: `systemd` timers run step 3 as one unit
per renewed principal, `User=agent` and `User=broker`, for status, request, and activate,
and one `User=provisioner` unit for provision. Example: a Docker Compose deployment gives
the agent and the sidecar separate services and `HOME` volumes, sharing one only for the
public handoff. Example: an LLM runtime hook runs step 2 as its secrets command.

## Verified by

| Examples | Test |
|---|---|
| sidecar.startup-env | secrets::managing_secrets_env_and_rotation |
| sidecar.renew | sessions::session_loop_rotates_an_agent_profile_and_reports_status |
| sidecar.renew | sessions::provisioning_session_agent_recovers_after_expiry |
| sidecar.renew | sessions::provisioning_session_agent_human_mint_unilateral_export |
| sidecar.ssh-agent | ssh_agent::using_ssh_register_serve_sign |

Step 7 is a manual deployment gate; the suite does not prove OS isolation,
timers, mounts, or alert delivery.

## Troubleshooting

- `session request` reports `data.userId: null`: the agent's key has already expired.
  Provision with the persisted `AGENT_USER_ID`; activation still verifies with the new key.
- `session request` fails `invalid_input` naming a pending request: a
  previous tick requested and did not finish. Provision that request; use
  `--replace` only after its activity was rejected.
- `whoami` succeeds from the shell but the agent process gets
  `unauthorized`: it runs with a different `HOME` or `TK_PROFILE`. Pin both.
- `secret env` exits `1` with `approval_required` at boot: an
  approval-gated secret matched the prefix. Add `--property consensus=unilateral`
  or move that secret to an on-demand export.
- Two ticks both requested keys: the loop passes `--replace` unconditionally.
  Add a lock and drop `--replace`; without `--replace` the second `session request` fails `invalid_input` while one is pending.

## Related Skills

- [provisioning-session-agent](../provisioning-session-agent/SKILL.md): the policies and the first provisioning this loop renews.
- [managing-secrets](../managing-secrets/SKILL.md): importing the values step 2 reads.
- [using-ssh](../using-ssh/SKILL.md): registering the key the socket serves.
- [deploying-signing-broker](../deploying-signing-broker/SKILL.md): the broker, its socket, and the client configuration behind step 5.
- [monitoring-activities](../monitoring-activities/SKILL.md): approving a pending mint the loop reports.
