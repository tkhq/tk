---
name: deploying-signing-broker
description: Deploy a credential-free application beside a single-key, GPG-only tk signing broker and a separate session provisioner, each in its own isolation boundary. Use when isolating OpenPGP Git signing so the application receives only a constrained Unix socket and public key, or when rotating the broker's expiring Turnkey credential; not for creating the signing key or choosing policies.
---

# Deploying a signing broker

Result: three isolation boundaries with separate authority. The application requests
signatures from one OpenPGP key through a Unix socket; the broker alone holds
that key's profile; the provisioner renews the broker's key but cannot sign.
This skill is GPG only. SSH through a broker runs [using-ssh](../using-ssh/SKILL.md)
as the broker principal; its broker rule lists the substitutions.

## Reference

- [GPG signing](../../docs/gpg-signing.md): key registration and export, the foreground agent, and the client socket.
- [git-signing](../../docs/git-signing.md): the Git configuration that points commit signing at `tk` as its GPG program.
- [resources](../../docs/resources.md): the `policy create` record.
- [sessions](../../docs/sessions.md): the request, provision, activate, and status records.

## Rules

- Three principals: application, GPG broker, provisioner. Separation means one
  boundary (a container, VM, sandbox, or OS user), one `HOME`, one process tree,
  and one set of mounts per principal. Separate OS users are the default; under
  the shared-uid socket model the application and broker share a numeric uid and
  nothing else, and the application mounts the runtime read-only. Publish no ports.
- The broker is its own principal: tag `BROKER_TAG`, profile `broker`, one
  signing ALLOW naming its user id and scoped to `WALLET_ID`, one credential
  DENY, no export policy.
- The application gets the runtime and public key read-only and never the broker's
  profile, registry, credential, or provisioner state; an application profile, if one
  exists, has no signing policy on this wallet. The provisioner gets neither the broker
  runtime nor the broker `HOME`, only the expected broker user id, the generated public API key, and the bounded lifetime.
- The broker serves one pinned fingerprint. Its socket grants signing authority: `0660`
  through the application's supplemental group, or `0600` when the application and broker run as one numeric uid.
- Drop capabilities, use a read-only root filesystem, and keep writable state in explicit bind mounts.
- Socket loss and broker failure fail closed: no fallback to an application credential or a second signing path.

## Instructions

Inputs: `WALLET_ID` and `FINGERPRINT` from
[signing-git-commits](../signing-git-commits/SKILL.md) steps 1 and 3 (skip its
agent policy), the broker tag (`BROKER_TAG`, created like the agent tag), the
`broker` and `provisioner` profiles, the socket model (group `10000` in step 3,
or a shared uid), and the session lifetime.

1. **Create and authorize the broker.** Before any broker key exists, root denies its tag credentials:

   <!-- example: signing-broker.policy-deny -->
   ```sh
   tk --profile admin --message-format json policy create --name brokers-no-credentials --effect deny \
     --consensus "approvers.any(user, user.tags.contains('BROKER_TAG'))" \
     --condition "activity.resource == 'CREDENTIAL'"
   ```

   Then create the broker user and provision its expiring key with [provisioning-session-agent](../provisioning-session-agent/SKILL.md)
   steps 1, 2, 4, and 5, tag `BROKER_TAG`, profile `broker`; save its user id as `BROKER_USER_ID`.
   Keep all three provisioner policies from its step 3 (`provisioners-mint-agent-keys` extended with
   `BROKER_USER_ID`, `provisioners-nothing-else`, `provisioners-no-self-keys`); skip only its export
   policy: the broker gets none. Root then completes the broker's GPG policy set:

   <!-- shared: brokers-sign-gpg -->
   <!-- example: signing-broker.policy-sign -->
   ```sh
   tk --profile admin --message-format json policy create --name brokers-sign-gpg --effect allow \
     --consensus "approvers.any(user, user.id == 'BROKER_USER_ID')" \
     --condition "activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2' && wallet.id == 'WALLET_ID'"
   ```

2. **Lay out host state.** Create mode-`0700` homes for the application, broker, and
   provisioner, owned by their uids; the application's writable worktree; a runtime directory
   owned by the broker uid (`0770` with the socket gid under the group model, `0700` under the
   shared uid); and a world-readable `/opt/tk-gpg-public` for the armored public key. Persist
   the broker user id outside the application.

3. **Define the boundaries.** Example: this Compose layout realizes the three boundaries
   under the group model. A VM or sandbox per principal substitutes for it when the runtime
   directory is the only shared mount. The application image needs `tk`, Git, and GnuPG. The
   `provisioner` service is the broker image as uid `10001` with `TK_PROFILE: provisioner`,
   only `/opt/tk-provisioner:/home/provisioner` mounted, and `command: [sleep, infinity]`.
   `depends_on` is not readiness: gate application startup on the socket path being a Unix
   socket with the model's owner, group, and mode.

   ```yaml
   services:
     app:
       image: your-agent@sha256:PINNED
       user: "1000:1000"
       group_add: ["10000"]
       environment:
         HOME: /home/app
         TK_GPG_AGENT_SOCK: /run/tk-gpg-agent/agent.sock
       volumes:
         - /opt/tk-app-home:/home/app
         - /opt/tk-app-workspace:/workspace
         - /opt/tk-gpg-runtime:/run/tk-gpg-agent:ro
         - /opt/tk-gpg-public:/opt/tk-gpg-public:ro
       read_only: true
       cap_drop: [ALL]
     gpg-broker:
       image: your-tk-image@sha256:PINNED
       user: "10000:10000"
       environment:
         HOME: /home/broker
         TK_PROFILE: broker
       command: [tk, gpg, agent, serve, --key, FINGERPRINT, --socket, /run/tk-gpg-agent/agent.sock, --socket-mode, "660", --non-interactive]
       volumes:
         - /opt/tk-gpg-broker:/home/broker
         - /opt/tk-gpg-runtime:/run/tk-gpg-agent
         - /opt/tk-gpg-public:/opt/tk-gpg-public
       read_only: true
       tmpfs: [/tmp]
       cap_drop: [ALL]
   ```

4. **Register and publish the key.** As `broker`, once, before serving. The
   export self-certifies with the key, so it proves the step 1 ALLOW holds:

   <!-- example: signing-broker.export -->
   ```sh
   tk --profile broker --message-format json gpg keys add --wallet-id WALLET_ID --key FINGERPRINT
   tk --profile broker gpg keys export --key FINGERPRINT > /opt/tk-gpg-public/FINGERPRINT.asc
   ```

5. **Start the broker.** Supervise it in the foreground; the step 3 Compose command is equivalent to:

   <!-- example: signing-broker.serve -->
   ```sh
   tk --profile broker gpg agent serve --key FINGERPRINT \
     --socket /run/tk-gpg-agent/agent.sock --socket-mode 660 --non-interactive
   ```

   SIGTERM must reach `tk`; after shutdown, require its owned socket to be gone before a replacement starts.

6. **Configure the application.** Stage the mounted armor with `show-only`. Each check exits
   before the import unless the staging holds exactly one `pub:` record, the `fpr:` directly after
   that `pub:` is `FINGERPRINT`, and no `sec:` or `ssb:` record. Only then import and point Git at the local `tk`:

   <!-- example: signing-broker.client -->
   ```sh
   gpg --with-colons --import-options show-only --import /opt/tk-gpg-public/FINGERPRINT.asc > "$HOME/staged-key.txt"
   test "$(grep -c '^pub:' "$HOME/staged-key.txt")" = 1 || exit 1
   grep -A1 '^pub:' "$HOME/staged-key.txt" | grep -qF 'fpr:::::::::FINGERPRINT:' || exit 1
   if grep -qE '^(sec|ssb):' "$HOME/staged-key.txt"; then exit 1; fi
   gpg --import /opt/tk-gpg-public/FINGERPRINT.asc
   gpg --with-colons --list-keys FINGERPRINT | grep -qF "fpr:::::::::FINGERPRINT:"
   export TK_GPG_AGENT_SOCK=/run/tk-gpg-agent/agent.sock
   git config --global gpg.format openpgp
   git config --global gpg.program tk
   git config --global user.signingkey FINGERPRINT
   git config --global commit.gpgsign true
   git commit -S --allow-empty -m test
   git verify-commit HEAD
   ```

   Signing needs no `TK_PROFILE` here: `tk` talks only to the socket. Pin
   `TK_GPG_PROGRAM` to the system GnuPG path when `gpg` is not on `PATH`.

7. **Rotate the broker session.** A host timer runs step 5 of
   [provisioning-session-agent](../provisioning-session-agent/SKILL.md) as a state machine: status,
   request, and activate execute in `gpg-broker`; provision executes in `provisioner`, bound to
   `BROKER_USER_ID` and the configured lifetime. After activation, restart `gpg-broker` so it builds a new API client.

8. **Gate the deployment.** Verify the separation of the model in force: three uids under
   the group model; under the shared uid, one uid for application and broker but separate
   `HOME`s, process trees, and mounts. Inspect mounts, not file contents: the application has
   only the read-only runtime and public key; the broker alone has its home and runtime
   writable; the provisioner alone has its home. Require a verified signed commit and a socket
   matching the model: `0660` owned by the broker uid and socket gid, or `0600` owned by the
   shared uid. Stop the broker; signing must fail. Start it, rotate, restart, sign again.

9. **Hand off.** Report image digests, uid/gid assignments, host mount paths, fingerprint, broker
   user id, policy ids, lifetime and timer, socket metadata, and gate results; no credential values or private material.

## Verified by

| Examples | Test |
|---|---|
| signing-broker.policy-sign, signing-broker.policy-deny, signing-broker.export, signing-broker.serve, signing-broker.client | gpg_agent::foreground_agent_signs_for_a_credential_free_git_client |

Mounts, ownership, supervision, broker loss, and rotation are manual gates. The test
proves that a broker holding only the two step 1 policies signs for a credential-free
client, refuses an unserved key, cannot register a credential, and removes its socket.

## Troubleshooting

- The application gets `permission denied`: its gid does not match the runtime
  and socket group, the runtime directory lacks group execute, or the two uids differ under the shared-uid model.
- Signing reports the agent is unavailable: the path is not a socket on both sides, or the broker left the foreground.
- `gpg keys export` or signing fails `unauthorized`: the ALLOW names another
  user id or another wallet. Do not export as root.
- `tk whoami` in the application resolves to the broker user, or it can sign
  or export with the broker's profile: the broker's credential crossed over.

## Related Skills

- [signing-git-commits](../signing-git-commits/SKILL.md): create the wallet and OpenPGP key.
- [provisioning-session-agent](../provisioning-session-agent/SKILL.md): create, provision, and rotate the broker user.
- [sidecar-patterns](../sidecar-patterns/SKILL.md): operate the general renewal loop and independent alert.
