# Approval models

Each workflow that grants an agent a capability asks the operator for its
part of this matrix: [managing-secrets](../managing-secrets/SKILL.md) the
export column, [provisioning-session-agent](../provisioning-session-agent/SKILL.md)
the minting row. Columns apply per secret (its `consensus` property); rows apply
to the minting policy for a provisioner and its target set. One agent can
hold unilateral configuration values and approval-gated credentials at the
same time.

## Contents

- [The matrix](#the-matrix)
- [Choosing a cell](#choosing-a-cell)
- [Approvals per day](#approvals-per-day)
- [Policy set per cell](#policy-set-per-cell)
- [What no cell gives you](#what-no-cell-gives-you)

## The matrix

| | Export needs a human | Export is unilateral |
|---|---|---|
| **Minting needs a human** | approval-gated exports and key registration | unattended exports; each new key needs human approval |
| **Minting is unilateral** | a provisioner renews without a human; each export needs approval | unattended registration and exports; the mint ALLOW pins target and lifetime |

An agent on the long-lived route has no minting row: its one key never
expires and only the export column applies.

## Choosing a cell

| Requirement | Pick |
|---|---|
| A person must see every use of a credential | export needs a human |
| The workload starts unattended and reads its configuration at boot | export is unilateral for those secrets |
| A person must see every new key the agent receives | minting needs a human |
| Renewal must survive nights and weekends | minting is unilateral, with the mint ALLOW pinned to target and lifetime |
| Git or SSH signing | resource-scoped unilateral ALLOW; these operations wait synchronously for a signature |

## Approvals per day

Approximate mint approvals per day as `24h / (lifetime - renewal lead time)`,
before outages or retries. A 4-hour key renewed 30 minutes early is about 7
approvals per day; a 7-day key renewed a day early is one per six days.
Export approvals count one per export activity, so an approval-gated secret
read at every start is one approval per start.

## Policy set per cell

Names refer to the commands in [policy-patterns.md](policy-patterns.md).

| Cell | Policies |
|---|---|
| exports need a human, minting needs a human | `agents-export-with-approval`, `agents-no-credentials`, `provisioners-mint-agent-keys` with the human clause, `provisioners-nothing-else` |
| exports unilateral, minting needs a human | `agents-export-unilateral`, `agents-no-credentials`, `provisioners-mint-agent-keys` with the human clause, `provisioners-nothing-else` |
| exports need a human, minting unilateral | `agents-export-with-approval`, `agents-no-credentials`, `provisioners-mint-agent-keys` without the human clause, `provisioners-nothing-else` |
| exports unilateral, minting unilateral | `agents-export-unilateral`, `agents-no-credentials`, `provisioners-mint-agent-keys` without the human clause, `provisioners-nothing-else` |

Organizations with both kinds of secrets apply both export policies; the
`consensus` property on each secret selects which one fires.

## What no cell gives you

- No cell stops a compromised provisioner credential from minting keys up to
  the cap for any allowed target. The lifetime clause bounds each key, not how
  many keys are minted; revoke them as in
  [revoking-agent-keys](../revoking-agent-keys/SKILL.md).
- No cell revokes an already exported value. Reducing access to a secret means
  rotating the credential at its provider, then replacing the secret.
- Tag and property selection is shared by every agent with that tag. Use a
  distinct tag and scope property per isolation boundary.
