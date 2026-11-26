# MCP metadata collection protocol

The Experimental collection SDK implements the metadata portion of MCP
Streamable HTTP revision `2025-11-25`. It takes a single explicitly selected
endpoint, current Workbench scope with granted consent, separate operator
opt-in, and a trusted exchange. The default exchange is unavailable. No live
network provider or operator command is registered for this SDK.

## Scope and exchange

The endpoint must be an exact literal-IP HTTPS URL, or HTTP on
`127.0.0.1` or `::1`. The existing native endpoint parser rejects userinfo,
query parameters and fragments. The Workbench scope must register and allow
both the exact URL and its literal destination address. The collector rereads
consent and pins the scope snapshot before every exchange. Scope membership
does not itself issue execution authority.

The exchange interface receives the exact URL, one POST body with fixed
metadata headers and the remaining time and response-byte budgets.
A live implementation requires a separate Workbench policy decision for
metadata-only POST and final send authorization. The native HTTP discovery
provider is approved for a credential-free GET and records only a status.
The intelligence acquisition receiver is approved for pinned source GETs
with original-byte custody. Neither provides this exchange.

Before enabling live execution, the reviewed transport must bind the actual
connected peer to the exact authorized destination, verify HTTPS certificates,
refuse redirects and response encodings requiring decompression, enforce hard
connection and body deadlines and bound headers and runtime resources. It must
keep any separately resolved authorization material in memory and reject
known credential echoes before submitting a reply to the SDK. Duplicate
content-type and session headers are invalid before conversion into the SDK's
single-value framing. A host must bind the exchange to its approved provider;
file, CLI and server data cannot select executable code.

## Wire behavior and results

Each POST accepts JSON or a bounded SSE transcript from that same POST.
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
cursors have no retained transcript or storage path. The result's inventory
is normalized data. A future model integration can pass it to a shared
in-memory publication function for the existing inventory evidence and model
owners, bound to the acquisition's source and consent. It should never write
the temporary document or re-import the normalized projection as raw input.

## Verification

The scripted peer exercises workspace consent, initialization, session
framing, JSON and SSE, opaque pagination, body and time ceilings, and partial
results. It compares the accepted redacted inventory with the checked-in
offline catalog. Its method log and socket, DNS and subprocess tripwires
verify the boundary without a network service.

```bash
uv run --locked --extra dev pytest --no-cov -n 2 tests/contract/test_mcp_metadata_contract.py
```

Protocol references include the [MCP transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports),
[MCP lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)
and [MCP pagination](https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/pagination).
