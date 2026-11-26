# fuzzy1337.mcp_metadata

The Experimental SDK protocol collects declarations from one explicitly selected
MCP Streamable HTTP 2025-11-25 endpoint. It checks current scope membership,
requires explicit operator approval and consumes a separately governed
`McpMetadataExchange`. The first-party transport is documented in
[fuzzy1337.mcp_metadata_http](fuzzy1337.mcp_metadata_http.md).

The result contains the source and scope references, the scope revision, the
negotiated protocol revision, a redacted offline-profile projection when
available, and fixed diagnostics for incompleteness. The workflow enumerates
advertised tools, prompts, resources and templates without interacting with
their execution or content surfaces.

::: fuzzy1337.mcp_metadata
