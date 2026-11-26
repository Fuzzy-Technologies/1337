# fuzzy1337.mcp_metadata_http

The Experimental first-party collector reads declared MCP metadata from one
explicitly approved literal-IP endpoint over Streamable HTTP. It checks the
existing Workbench scope and the exact SAFE capability in the current impact
policy before sending requests. HTTPS verifies the literal IP identity against
platform trust. Plain HTTP is limited to unauthenticated loopback.

`CollectMcpMetadataHttp` obtains an opaque optional bearer from a trusted
local resolver and makes only the bounded initialization and list requests.
`MCP_METADATA_CAPABILITY` identifies the provider and exact capability
permission. The result contains the redacted declaration inventory and fixed
diagnostics. Evidence and model publication use their existing owners.

::: fuzzy1337.mcp_metadata_http
