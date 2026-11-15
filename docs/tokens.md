# Access tokens

`tk token` gets an OAuth access token for another service, such as an MCP server, as the profile's user, with the client credentials grant. The token is for that service; `tk` keeps signing its own Turnkey requests with the profile's key.

Follow [authentication](./authentication.md) first.

```bash
# Get a token for an MCP server, bound to the profile's key with DPoP.
tk token --resource https://mcp.example.com/mcp --parent-organization-id PARENT_ORG_UUID --scope mcp

# Get a bearer token instead, for a service that cannot check DPoP proofs.
tk token --resource https://mcp.example.com/mcp --parent-organization-id PARENT_ORG_UUID --bearer
```

The profile's user must be in a sub-organization of `PARENT_ORG_UUID` and registered with the identity service as a client; its client id is `urn:turnkey:user:USER_ID`. `tk` signs a client assertion with the profile's key and, unless `--bearer`, a DPoP proof, retrying once with the nonce the identity service names. The record carries `accessToken`, `tokenType` (`DPoP` or `Bearer`) and `expiresIn`; human output is the token alone. A DPoP-bound token is useful only to a caller that can sign proofs with the same key. A refused client exits with `unauthorized`. `TK_IDENTITY_ORIGIN` or `--identity-origin` points at another identity service, such as `https://id.dev.turnkey.engineering`.
