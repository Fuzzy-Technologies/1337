# ADR 0140: Opt-in ZIP transport media gate

Status: Accepted for this bounded implementation.

## Context

The internal isolated receiver currently carries JSON and gzip resources for
owning typed intelligence profiles. Bounded selected CWE ZIP/XML decoding and
local custody already exist, but those capabilities do not establish a remote
CWE source, SDK, CLI or genuine HTTPS acceptance. A future remote consumer needs
an explicit ZIP transport prerequisite without changing older source contracts.

## Decision

Add only the internal `accept_kind="zip"` selection and optional worker `zip`
argument. It requests `Accept: application/zip, application/octet-stream`, keeps
HTTP encoding identity and retains original resource bytes. Do not decompress,
parse ZIP/XML, grant source authority, follow redirects or introduce retries.

After the existing observed-status and framing/declared-size gates, but before
any body `read1`, require exactly one parsed `Content-Type` field using
`response.headers.get_all("Content-Type", [])`. Its value must be an exact string,
ASCII and at most 128 bytes including retained edge whitespace. Strip only edge
SP/HTAB, then compare ASCII lowercase with exactly `application/zip` or
`application/octet-stream`. Refuse missing, duplicate, comma-joined, parameterized,
folded, non-ASCII, embedded-whitespace or other control-bearing values. A refusal
returns the existing format exit with observed status and no body. This is a
semantic value bound after standard-library header parsing, not a cap on total
header parsing or allocation.

Keep JSON's original four-element worker argv and gzip's optional fifth `gzip`
argument. Their exact headers, missing/malformed-media behavior and body bytes
are unchanged. Preserve the three-item bytes/state/status result, status-only
pipe framing, existing status/framing refusals, finite byte/deadline limits and
kill/drain ownership. No literal response media telemetry is added.

## Consequences

Deterministic wire fixtures exercise the actual standard-library HTTP response
parser, including duplicate and folded fields; real isolated workers exercise
argv, status-only protocol and deadline cleanup without external requests.
This prerequisite adds no typed remote CWE SDK, custody family, CLI command,
source acquisition or genuine product HTTPS acceptance. #43/#47 remain open.
