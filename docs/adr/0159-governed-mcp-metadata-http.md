# ADR 0159: Governed MCP metadata over Streamable HTTP

- Status: Accepted for the governed MCP metadata SDK
- Date: 2026-11-26
- Related work: #549, #551, ADR 0036, ADR 0158

## Decision

Introduce an opt-in first-party Streamable HTTP SDK for a single operator-owned
MCP endpoint. Use the existing exact literal-IP endpoint validator, requiring
HTTPS outside `127.0.0.1` and `::1`. Scope must register and allow the precise URL
and the actual IP separately under current consent. The effective Workbench
policy must explicitly admit capability `mcp.metadata-collection` on provider
`native.mcp-metadata` at SAFE impact. The SDK requires a separate positive
operator decision for each collection.

Reuse the existing policy checks for scope, literal destination, exact provider
identity, impact ceilings, and required privileges. A first-party in-process
SAFE check uses the same admission function as `PolicyEngine.Plan`, with a
trusted capability descriptor and no executable or synthetic invocation.
The provider binds one immutable authority snapshot and checks current scope
and policy before each connection and at the final application send boundary.
Policy and credential readers are trusted, bounded local functions. A denied
or changed authority aborts the collection.

The provider opens one direct HTTP/1.x connection per declared MCP POST, checks
the peer IP and port, and verifies TLS using platform trust and literal IP
identity. It constructs requests only for initialization, its initialized
notification and the four declared list procedures. The provider does not
start local processes, use DNS or proxy settings, follow redirects or inspect
service-provided target URLs. It has no generic HTTP send API.

Use the existing monotonic remaining-deadline primitive and the 16 KiB
native HTTP header ceiling. Bound the original body, chunk count, cursor
pagination, RPC data, and whole-collection time. Admit fixed-length,
close-delimited and simple chunked responses with JSON or SSE. A decisive
SSE event may end the collection's read even when the peer leaves its stream
open. Require a complete event and valid framing of the containing chunk.
Count already-read transfer-decoded payload, including bytes after that
event in its block, against the collection budget. Raw framing read-ahead
uses at most one separately bounded 4 KiB socket block before length checks.
Refuse duplicate framing headers, conflicting lengths, compression, chunk
extensions, trailers, unsupported transport and broken frames. Stop after a
timeout, mismatch, invalid page, or unsupported response, retaining only
previously accepted metadata.

A trusted optional credential resolver supplies one memory-only TLS bearer
value. The client transmits it only on the selected HTTPS endpoint after
certificate verification and the final authority check. It does not consume
ambient authorization settings or enable TLS key logging. Session IDs and
cursors remain memory-only, with no restart or resumption. The provider rejects
known bearer echoes in decoded JSON and session headers. Outward errors and
partial outcomes carry fixed messages without transport exceptions or
credential-bearing stack frames.

The result uses the existing bounded redacted inventory profile and source and
scope attribution. The transport has no storage or report authority. Any
publication of its normalized result belongs to the existing evidence/model
owner under its own publication controls.

## Verification

Compare the known owned catalog over HTTP and HTTPS to ADR 0158's offline
fixture. Verify exact method sequence, chunked SSE completion, TLS IP identity
and certificate refusal, malformed and slow responses, bearer echoes, scope
revocation and policy changes, and byte ceilings. The synthetic server uses
a loopback listener and records only method names. Scripted unit tests
exercise the same entry point without socket connections.
