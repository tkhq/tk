# Signing

Sign with a wallet account. Inputs follow the [resources](./resources.md)
conventions.

Follow [authentication](./authentication.md) first.

```bash
# Sign a 32-byte digest as is. Encoding and hash function are always explicit.
tk sign payload --sign-with 0xYourAddress --payload 0x… \
  --encoding hexadecimal --hash-function no_op

# Hash text before signing.
tk sign payload --sign-with 0xYourAddress --payload hello \
  --encoding text_utf8 --hash-function keccak256

# Read the payload verbatim from a file, or - for stdin.
tk sign payload --sign-with 0xYourAddress --payload-file ./message.txt \
  --encoding text_utf8 --hash-function sha256

# Sign a serialized transaction. tk does not broadcast it.
tk sign transaction --sign-with 0xYourAddress --unsigned-transaction 02… \
  --type ethereum

# Raw parameters, for anything the flags cannot express.
tk sign payload --input-json '{
  "signWith": "0xYourAddress",
  "payload": "0x…",
  "encoding": "PAYLOAD_ENCODING_HEXADECIMAL",
  "hashFunction": "HASH_FUNCTION_NO_OP"
}'
```

`--sign-with` takes a wallet account address or a private key ID. Encoding,
hash function, and transaction type take the API enum names, such as
`PAYLOAD_ENCODING_HEXADECIMAL`, case-insensitively and with or without the
prefix. They have no defaults, because a silent hash function changes which
digest is signed; the command exits with `usage_error` when one is missing.
`--payload-file` keeps a trailing newline as part of the payload;
`--unsigned-transaction-file` trims surrounding whitespace. Flags and
`--input-json`/`--input-file` are mutually exclusive.

Scripting:

```bash
tk sign payload --input-file ./sign.json --message-format json \
  | jq -r '.data.activity.result.signRawPayloadResult'
```

When a policy requires approval the command exits zero with status `pending`.
Have an approver run `tk activity approve`, then collect the result with
`tk activity wait`; see [activities](./activities.md).

For Git commits, SSH, and OpenPGP, see [git signing](./git-signing.md),
[SSH](./ssh-agent.md), and [GPG signing](./gpg-signing.md).
