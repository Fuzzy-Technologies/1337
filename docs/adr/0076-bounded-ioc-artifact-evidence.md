# ADR 0076: Bounded explicit IOC artifact evidence

- Status: Accepted for the first IOC slice; wider DFIR modeling remains undecided
- Date: 2026-10-14
- Related work: Task #85, Feature #83, M8

## Context

Task #85 needs attributable DFIR inputs without treating supplied indicators as
proof of an incident, maliciousness, observed attack paths or scan authority.
The current Core has typed security objects but no accepted incident/event or
process timeline schema. Introducing those kinds, or using Assets as event
proxies, would decide a separate architectural fork prematurely.

## Decision

Add an experimental offline `ioc_artifacts` API for explicitly supplied,
caller-owned non-secret bytes. The first closed profile is ASCII TSV with literal
IPv4, literal unscoped IPv6, fully qualified ASCII DNS names and SHA-256 tokens.
Every physical nonempty line contains either two fields (`kind`, `token`) or four
fields (also an original offset-bearing timestamp and its exact timezone suffix).
LF and CRLF are allowed; no header, comments, quoting, escaping, blank lines,
Unicode/IDNA conversion, URL/hash inference or network resolution is performed.

Normalization preserves each occurrence in source order, its exact raw token,
logical source locator, physical line, byte range and optional original timestamp
and timezone. A canonical UTC timestamp is a derived convenience only. Duplicate
candidates remain distinct evidence occurrences. A source-declared observation
time is never the receiver-observed acquisition clock and may be in the future;
its truth and publisher authenticity are not assessed.

Finite caller limits cannot exceed 64 KiB source, 256 lines/items, 512 bytes per
line or token, or JSON metadata depth eight. The parser/version, profile/family,
source/version/license/expected digest, budgets, workspace/scope and original raw
manifest identity are pinned in an immutable acquisition receipt. Raw, receipt
and derived snapshot use the existing local evidence owner. Parse or digest
refusal retains bounded original raw bytes and a refusal receipt. Oversize input
is rejected before acquisition and is never silently truncated.

Replay requires an independent caller-retained original acquisition receipt
record or manifest identity alongside the selected snapshot. It never derives
that trusted anchor from a candidate snapshot's receipt pointer. Replay loads
the exact owning manifests, checks consumer role/media/size budgets
before eager raw reads, verifies receipt/provenance bindings, and reparses original
bytes. It rejects altered snapshots even when their public hashes are recomputed.
The independent original receipt anchor rejects coherently rehashed alternative
receipts and snapshots that reuse the original raw acquisition. Its canonical
request digest describes source/profile/parser/budget selection within the
receipt; execution and invocation provenance remain None for this offline API.
This is local integrity and attribution, not publisher signature verification or protection
against an actor replacing an entire trusted chain and its trusted identifiers.
Replay needs no original path and survives workspace relocation. Exact first-party
runtime types and reconstruction checks reject subclass and frozen-object field
substitutions at public boundaries.

## Consequences

The slice provides supplied IOC candidates and portable provenance, without
mutating the canonical model, generating Findings, launching processes, resolving
names or probing hosts. Incident/event/entity/process schemas, Core correlation,
log parsers and wider Task #85 acceptance remain open owner decisions. No optional
Core matching API is added until its descriptive semantics have a reviewed owner.
