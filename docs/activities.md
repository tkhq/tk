# Activities

Every mutation is an activity. Inspect, vote on, and wait for them.

Follow [authentication](./authentication.md) first.

```bash
tk activity list --limit 50
tk activity list --limit 50 --cursor ACTIVITY_ID
# Keep only pending activities; repeat --status for more than one status.
tk activity list --status pending
# Keep only one activity type; repeat --type for more than one type.
tk activity list --type 'ACTIVITY_TYPE_CREATE_USER_TAG'
# Keep only activities created in the last day.
tk activity list --since 24h --limit 100
tk activity get --id ACTIVITY_ID
```

Consensus:

```bash
# Approver: one vote per command.
tk --profile approver activity approve --id ACTIVITY_ID
tk --profile approver activity reject --id ACTIVITY_ID

# Submitter: block until the activity ends.
tk activity wait --id ACTIVITY_ID --timeout 60
```

`wait` fails with `api_error` when the activity ends rejected or failed and
with `wait_timeout` when time runs out. Run it again with the same ID to
resume.

To see which policies decided an activity:

```bash
tk policy evaluations --activity-id ACTIVITY_ID
```

## Skills

- [monitoring-activities](../skills/monitoring-activities/SKILL.md): approving, rejecting, waiting, and reconciling an unknown outcome.
- [managing-policies](../skills/managing-policies/SKILL.md): reading `policy evaluations` for a denial.
- [inspecting-agents](../skills/inspecting-agents/SKILL.md): paging pending activities, votes, and mint attribution with jq.
- [provisioning-agent-identity](../skills/provisioning-agent-identity/SKILL.md): approving the agent's gated `secret export` and reading the denial that fences it.
- [provisioning-session-agent](../skills/provisioning-session-agent/SKILL.md): approving a pending mint and inspecting it with `activity get` when activation fails.
- [signing-git-commits](../skills/signing-git-commits/SKILL.md): waiting on a `pending` wallet creation before scoping the signing policy.
- [using-ssh](../skills/using-ssh/SKILL.md): locating a failed signing activity with `activity list` and reading its `policy evaluations`.
