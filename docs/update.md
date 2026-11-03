# Update

`tk update` installs a verified release without Turnkey credentials.

```bash
# Installs the latest release if it is newer.
tk update

# Installs a specific signed release, including an older version.
tk update --tag vX.Y.Z
```

Direct updates require
[Cosign](https://docs.sigstore.dev/cosign/system_config/installation/) on PATH.
They check the checksum and signed provenance for the exact release workflow
and tag before running downloaded code.
See [manual installation](../README.md#manual-installation) for manual verification.
Cargo installations return the package manager command instead.
That path and `already_up_to_date` checks do not require Cosign.
