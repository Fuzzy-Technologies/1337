# MCP metadata collection protocol

The Experimental collection SDK implements the metadata portion of MCP
Streamable HTTP revision `2025-11-25`. `CollectMcpMetadataHttp` takes a single
explicitly selected endpoint, current Workbench scope with granted consent,
separate operator opt-in, and the current capability policy. The lower-level
`CollectMcpMetadata` protocol also supports scripted exchange fixtures.

## Scope and exchange

The endpoint must be an exact literal-IP HTTPS URL, or HTTP on
`127.0.0.1` or `::1`. The existing native endpoint parser rejects userinfo,
query parameters and fragments. The Workbench scope must register and allow
both the exact URL and its literal destination address. The provider uses
`PolicyEngine.CheckSafeCapability` to require an exact SAFE permission for
`mcp.metadata-collection` on `native.mcp-metadata`. It pins both the scope and
policy snapshots and rechecks them before connecting and at the final send.

The provider uses a direct literal socket, verifies its actual peer and port,
and on HTTPS validates the certificate against platform trust and the selected
IP identity. No DNS, proxy, follow-up on redirect, service link resolution or
transport fallback is used. A trusted bounded local credential resolver may
supply one TLS bearer value. Plain loopback HTTP accepts no bearer value, and
the provider keeps credentials in memory. It disables ambient TLS key logging
and refuses known bearer echoes in decoded JSON or session headers.

## Wire behavior and results

Each POST accepts JSON or a bounded SSE transcript from that same POST.
The direct exchange accepts HTTP/1.0 or HTTP/1.1 final responses with
bounded headers, fixed-length or close-delimited bodies and simple chunked
transfer framing. It refuses compressed content, duplicate selected headers,
conflicting length and transfer fields, chunk extensions and trailers.
The collector negotiates `2025-11-25`, advertises empty client capabilities,
sends `notifications/initialized`, and then selects only advertised families
among `tools/list`, `resources/list`, `resources/templates/list` and
`prompts/list`. It uses the negotiated version and any initialization session
header on subsequent requests. Server requests on an SSE stream do not
trigger execution or client replies. SSE resumption, session restart and
teardown, OAuth discovery, legacy transport discovery and subprocess-based
transports are outside this collection profile.

Pagination cursors are opaque and local to each list. A repeated cursor or
invalid page stops collection and preserves earlier accepted pages. List
replies must fit both the per-POST and total response-body ceilings. The bounds
also cap per-POST and whole-collection time and the number of pages per list.
Defaults are 3 seconds per exchange and 30 seconds total, 64 KiB per reply and
256 KiB total, and eight pages per section. Hard ceilings are 10 seconds per
exchange and 60 seconds total, 256 KiB total, and sixteen pages per section.
The [offline inventory profile](MCP_INVENTORY.md) independently bounds the
declarations, strings and JSON structure in each candidate snapshot.

A successful result contains the endpoint reference, scope reference and
revision, protocol revision, and the exact redacted `ParseMcpInventory`
projection. A failed initialization can report an issue without an inventory.
Unadvertised families remain incomplete with explicit diagnostics. Only an
accepted list result with no continuation cursor completes its section. A
failure during pagination retains prior valid pages and leaves unvisited
sections incomplete. Diagnostics contain fixed section names and reasons.

Instructions, descriptions and other declared metadata are treated according
to the offline profile. HTTP response bytes, credentials, session IDs and
cursors remain transient. Use [`CollectAndImportMcpMetadata`](MCP_INVENTORY.md#retain-an-approved-http-metadata-acquisition)
to retain the normalized inventory with its exact scope, consent and source
references in the shared model. The [declaration review](MCP_DECLARATION_REVIEW.md)
uses the same server identity for offline and HTTP snapshots.

## Verification

The scripted tests verify the contract without connecting to a listener. The
owned loopback fixture also exercises the first-party connection and compares
the retained HTTPS acquisition with an approved baseline from the checked-in
offline catalog. Its method-only log records which declarations the provider
requested.

```bash
uv run --locked --extra dev pytest --no-cov -n 2 tests/integration/test_mcp_metadata_http_loopback.py
```

See [ADR 0159](adr/0159-governed-mcp-metadata-http.md) for the policy boundary.

Protocol references include the [MCP transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports),
[MCP lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)
and [MCP pagination](https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/pagination).
