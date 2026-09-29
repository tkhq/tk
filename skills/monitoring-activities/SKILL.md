---
name: monitoring-activities
description: Inspect, approve, reject, and wait for Turnkey activities with tk, and resume a mutation that returned pending, timed out, or reported an unknown outcome. Use when a command says pending, when a human must approve an agent's request, or when an outcome is uncertain; not for writing the policies that require the approval.
---

# Monitoring activities

Every mutation is an activity. This workflow resumes one by id, casts a vote
on it, and reads who voted. Resuming never resubmits the original command.

## Reference

- [activities](../../docs/activities.md): `activity` command records and exit codes.
- [secrets](../../docs/secrets.md): the two commands that are rerun rather than resumed.

## Rules

- Resume by activity id. The only mutations that are rerun are
  `secret export`, `secret env`, and `session provision`, which detect their
  own pending work.
- Before approving, verify the target: the organization, the activity type,
  and the parameters (for a key registration, the target `userId`, the
  `publicKey`, and the lifetime). Target tags and lifetimes are not
  policy-visible, so the approver is the check.
- Rejection is final. A rejected activity cannot be approved later; the
  submitter runs a new one.
- Approve as the intended approver identity. A root approval also satisfies
  the root quorum and proves nothing about the policy.

## Instructions

Inputs: the activity id from the pending record, and the approver's profile
(`approver`). The submitter's profile is `agent`.

1. **Find the activity.** Any identity in the organization.

   <!-- example: activities.get -->
   ```sh
   tk --profile approver --message-format json activity get --id ACTIVITY_ID
   ```

   `status` is the record status; `data.activity.status` the raw value
   (`ACTIVITY_STATUS_CONSENSUS_NEEDED` while approvals are outstanding).
   `data.activity.type` and `data.activity.intent` describe the request;
   `data.activity.votes[]` lists votes with `userId` and `selection`.

   Without an id, page through recent activities:

   <!-- example: activities.list -->
   ```sh
   tk --profile approver --message-format json activity list --limit 50
   tk --profile approver --message-format json activity list --limit 50 --cursor ACTIVITY_ID
   ```

   `data.items[]` is one page, newest first; `data.nextCursor` is the id to
   pass as `--cursor` for the next page, or `null` on the last page. Filter
   by `status` and `type` locally; the command has no filters.

2. **Approve or reject.** Approver.

   <!-- example: activities.vote -->
   ```sh
   tk --profile approver --message-format json activity approve --id ACTIVITY_ID
   tk --profile approver --message-format json activity reject --id ACTIVITY_ID
   ```

   `approve` returns `command: "activity.approve"` with `status`
   `completed`, or `pending` when more votes are needed. `reject` returns
   `status: "rejected"`. Both name the target under `activity.id`.

3. **Wait as the submitter.**

   <!-- example: activities.wait -->
   ```sh
   tk --profile agent --message-format json activity wait --id ACTIVITY_ID --timeout 60
   ```

   Exit `0` with `status: "completed"` ends the wait; the result is under
   `data.activity.result`. Exit `1` with `code: "wait_timeout"` means run the
   same command again. Exit `1` with `code: "api_error"` and
   `details.activity.status` of `ACTIVITY_STATUS_REJECTED` or `_FAILED` is
   final; report it and stop.

4. **Reconcile an unknown outcome.** When a mutation failed with
   `submission_unknown` or `network_uncertain`, list activities as in step 1,
   match by `data.items[].type` and the intent's parameters, and continue
   with step 3 on the match. Resubmit only when no matching activity exists.

5. **Hand off.** Report the activity id, its final status, and any result ids
   under `data.activity.result`. A `pending` handoff names who still has to
   vote. Stop.

## Verified by

| Examples | Test |
|---|---|
| activities.get, activities.list, activities.vote, activities.wait | activities::monitoring_activities_approve_reject_wait |
| activities.get, activities.wait | activities::activity_list_paginates_and_get_and_wait_inspect_a_completed_activity |

## Troubleshooting

- `activity approve` fails with `unauthorized`: this identity is not selected
  by the policy's consensus, or the activity is no longer pending. Check
  `data.activity.votes` and the consensus expression.
- `activity approve` returns `pending`: the policy requires more approvers
  than this vote. `policy evaluations --activity-id ACTIVITY_ID` shows which clause is
  unsatisfied.
- `activity wait` returns `wait_timeout` repeatedly: the activity is waiting
  for a human. Report the id and the missing approver; do not resubmit.
- `activity get` fails with `not_found`: the id belongs to another
  organization or was mistyped. Check `--profile` and the id.
- A `secret export` or `secret env` is pending: do not `activity wait` it to
  completion and expect the value. Approve it, then rerun the same
  `secret` command from the same credential and home directory.

## Related Skills

- [managing-policies](../managing-policies/SKILL.md): read the policy behind a
  pending or denied activity.
- [managing-secrets](../managing-secrets/SKILL.md): finish a pending export
  after approval.
- [managing-identities](../managing-identities/SKILL.md): approve a key
  registration, then let the user switch to it.
