# Secrets

Values are UTF-8 text. One trailing newline is stripped on import.

## Basics

```sh
# value piped on stdin
echo -n "$API_TOKEN" | tk secret import api-token
# value read from a file
tk secret import db-password --from-file ./password.txt
# no value given, so tk prompts with input hidden
tk secret import ssh-passphrase
```

```sh
# first page of metadata: names, IDs, properties, never values
tk secret list
# the next page, continuing after the previous nextCursor
tk secret list --limit 100 --cursor SECRET_ID
```

```sh
# look the secret up by name and print its value
tk secret export --name api-token
# the same, by secret ID, when a name is ambiguous
tk secret export --id 0b3c1d2e-....
```

## Scripting

```sh
API_TOKEN=$(tk secret export --name api-token)
# new file, mode 0600
tk secret export --name db-password --out ./password.txt
tk secret export --name api-token --message-format json | jq -r .data.value
```

## Policy-visible metadata

Static properties are bound to the secret forever and appear in `tk secret list`.

```sh
echo -n "$TOKEN" | tk secret import api-token --property env=prod --property team=payments
```

Request context is attached to one export request only.

```sh
tk secret export --name api-token --context purpose=deploy --context ticket=OPS-123
```

## Consensus

Submitter:

```sh
tk secret export --name prod-signing-key
# status: pending, activity ID printed, nothing written yet
```

Approver:

```sh
tk activity list --limit 20
tk activity approve ACTIVITY_ID
```

Submitter, again, same command:

```sh
tk secret export --name prod-signing-key
# prints the value
```

A rejected export fails with `api_error`; running the command again starts a
new export.

The re-run works because the value is encrypted to a single-use recipient key
that only the submitting run holds. Once the API answers `pending`, that key is
written under
`~/.config/turnkey/tk/secrets/pending/<organization>/<credential>/<secret>.json`,
where the next run picks it up. It is deleted once the value is delivered or
its activity ends, and swept after 8 hours.

Nothing is written before the API answers. An export that fails to submit, or
whose response is lost, leaves no key and no state: run the command again. The
one gap is a crash between the API accepting the activity and the key reaching
disk, which strands an activity whose value can never be decrypted — reject it
and run a new export.

State belongs to the credential that created it. Two profiles on one machine
each get their own export of the same secret; neither resumes the other's.

## Abandoning a pending export

There is no `tk secret export --abort`. A pending export is abandoned by
ending its activity:

```sh
# any approver, before the export is approved
tk activity reject ACTIVITY_ID
# fails with api_error and clears the stale key
tk secret export --name prod-signing-key
# submits a new export
tk secret export --name prod-signing-key
```

Leaving it alone works too: the recovery key is swept after 8 hours and the
activity expires after 24, after which the same command starts fresh.
