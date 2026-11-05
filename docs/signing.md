# Signing

Sign with a wallet account. Inputs follow the [resources](./resources.md)
conventions.

Follow [authentication](./authentication.md) first.

```bash
# Sign a 32-byte digest as is. Encoding and hash function are always explicit.
tk sign payload --sign-with 0xYourAddress --payload 0x… \
  --encoding hexadecimal --hash-function no-op

# Hash text before signing.
tk sign payload --sign-with 0xYourAddress --payload hello \
  --encoding text-utf8 --hash-function keccak256

# Read the payload from a file, or - for stdin.
tk sign payload --sign-with 0xYourAddress --payload-file ./message.txt \
  --encoding text-utf8 --hash-function sha256

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
hash function, and transaction type have no defaults, because a silent hash
function changes which digest is signed; the command exits with `usage_error`
when one is missing. `--payload-file` drops one trailing newline, so `echo` and
saved editor files sign the text you see; `--unsigned-transaction-file` trims
surrounding whitespace.

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
