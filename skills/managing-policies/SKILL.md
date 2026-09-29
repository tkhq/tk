---
name: managing-policies
description: Write, apply, inspect, update, and debug Turnkey policies with tk, including consensus that requires a human approver and policy evaluations for a denied activity. Use to grant or restrict what a tagged user may do or to explain a denial; not for choosing an approval model, which the bootstrap workflow covers.
---

# Managing policies

Result: a policy set that grants the intended access and nothing more, tested
from a non-root credential, with denials explained by `policy evaluations`.

## Reference

- [resources](../../docs/resources.md): `policy` command records and update field names.
- [activities](../../docs/activities.md): `policy evaluations` and consensus votes.

## Rules

- Write policies against tag ids and secret static properties. Name a user or
  resource id only where the reference says it is unavoidable.
- A DENY overrides every ALLOW. Never delete a containment DENY to make an
  activity succeed.
- Consensus must contain a clause the submitter satisfies, or the activity is
  denied at submission instead of waiting for approval.
- Test from the constrained credential. Root success proves nothing about
  agent access.
- Keep expressions in files or single-quoted arguments exactly as written;
  do not rebuild them in shell.

## Instructions

Inputs: the root profile (`admin`), the tag ids from the bootstrap, and the
approval cell. Read [policy-language.md](../references/policy-language.md)
for grammar and [policy-patterns.md](../references/policy-patterns.md) for
the policy set.

1. **State the change.** Before any mutation, write down effect, condition,
   consensus, and which users the consensus selects. If the request is "make
   this denied activity work", read the denial first (step 5) and return the
   smallest change that fits the requested access.

2. **Create a policy.** Root. Flags for one policy:

   <!-- example: policies.create -->
   ```sh
   tk --profile admin --message-format json policy create --name agents-export-unilateral --effect allow \
     --consensus "approvers.any(user, user.tags.contains('AGENT_TAG'))" \
     --condition "activity.type == 'ACTIVITY_TYPE_EXPORT_SECRETS' && secret.static_properties['consensus'] == 'unilateral'" \
     --notes "allow-always: agents read unilateral secrets alone"
   ```

   Save `data.activity.result.createPolicyResult.policyId`. For several
   policies at once, `policy create-batch --input-file ./policies.json` takes
   `{"policies":[...]}` with `policyName`, `effect`, `condition`, `consensus`,
   `notes`.

3. **Confirm what was stored.**

   <!-- example: policies.get -->
   ```sh
   tk --profile admin --message-format json policy get --id POLICY_ID
   tk --profile admin --message-format json policy list
   ```

   `data.policy.condition` and `data.policy.consensus` must equal the
   expressions from step 1 character for character.

4. **Test from the constrained credential.** Run the intended allowed
   operation and one operation that must be denied as the tagged user. The
   allowed one returns `status: "completed"` or, for allow-once, `pending`;
   the denied one fails with `unauthorized` and HTTP 403.

5. **Explain a denial or a pending vote.**

   <!-- example: policies.evaluations -->
   ```sh
   tk --profile admin --message-format json policy evaluations --activity-id ACTIVITY_ID
   ```

   `data.policyEvaluations[]` carries one entry per vote with
   `policyEvaluations[].policyId` and `outcome`. A DENY outcome names the
   policy to read; no ALLOW outcome means no policy matched. A 403 with no
   activity id means the request was refused before an activity existed;
   compare the submitter's tags against the consensus clauses.

6. **Update or delete.** Root. Updates use `policyId` with the `policy`-prefixed
   field names:

   <!-- example: policies.update -->
   ```sh
   tk --profile admin --message-format json policy update --input-json '{"policyId":"POLICY_ID","policyNotes":"revised"}'
   tk --profile admin --message-format json policy delete --id POLICY_ID
   ```

   Re-run step 3 after an update. Deleting an ALLOW removes access
   immediately; deleting a DENY may widen access, so re-run step 4.

7. **Hand off.** Report each policy id with its name, effect, condition, and
   consensus, and the allowed and denied operations that were tested. Stop.

## Verified by

| Examples | Test |
|---|---|
| policies.create, policies.get, policies.evaluations, policies.update | policies::managing_policies_crud_and_evaluations |
| policies.evaluations | policies::quorum_approval_completes_and_rejection_fails_a_consensus_activity |

## Troubleshooting

- `policy create` fails with `usage_error`: `--name` needs `--effect` and at
  least one of `--condition` or `--consensus`.
- `policy update` fails with `invalid_input` naming an unsupported field:
  updates use `policyEffect`, `policyCondition`, `policyConsensus`, and
  `policyNotes`, not the create names.
- The constrained user gets `unauthorized` on an operation the ALLOW covers:
  check `activity.type` spelling against the table in
  [policy-language.md](../references/policy-language.md), and check that the
  user actually carries the tag with `tk --profile admin --message-format json user get --id USER_ID`.
- The activity is `pending` when it should complete: the consensus names a
  second party. That is allow-once behavior; approve it, or change the
  consensus if unilateral was intended.
- The activity is denied when it should be `pending`: no consensus clause is
  satisfiable by the submitter. Add the submitter's tag clause.
- A root user approves and everything passes: the root quorum bypassed the
  policies. Repeat the test with a non-root approver.

## Related Skills

- [monitoring-activities](../monitoring-activities/SKILL.md): approve, reject,
  and inspect the activities these policies gate.
- [managing-identities](../managing-identities/SKILL.md): attach or remove the
  tags the policies select.
- [managing-secrets](../managing-secrets/SKILL.md): the property-based export
  policies in practice.
