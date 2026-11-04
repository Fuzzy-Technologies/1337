# ADR 0141: Selected CWE HTTPS custody

## Status

Proposed implementation decision for #43/#47. Integration requires accepted
ADR 0140 ZIP transport. This decision does not establish remote availability,
installed acceptance or completed implementation.

## Context

The accepted local selected-CWE decoder and custody family preserve complete
original ZIP bytes and bounded selected records. A local importer cannot prove
HTTPS acquisition. A new source family must bind its own request, observed
transport result and independent evidence publication acknowledgements without
changing existing local or JSON/gzip contracts.

## Decision

Add an experimental SDK family in `intelligence_cwe_remote.py`. Source versions
are exactly `5.0` and `4.21`; each derives its fixed query-free URL under
`https://cwe.mitre.org/data/xml/`. Require an explicit lowercase SHA-256 pin and
the unchanged complete `CweNoticeBundle`/notice profile. Accept no arbitrary URL,
headers, callback, alternate notice, retry or local fallback.

Requests select a canonical immutable tuple of 1..64 CWE identifiers. The
effective retained ZIP bound is an exact integer from 1 through 4 MiB. Timeout
is an exact integer or float, excluding bool, from 0.05 through 60 seconds;
reject out-of-range huge integers before float conversion, reject nonfinite
values and normalize accepted values to float. Thus 15 and 15.0 share identity.
The unchanged isolated receiver is called once with `accept_kind="zip"`.

Reuse family-neutral ZIP/XML selection and notice helpers. Preserve the local
importer, local record validator and local acquisition interfaces unchanged.
Use the existing 32 MiB decoded XML, 1 MiB selected JSON and 64-ID ceilings;
bound serialized notice/source/envelope/receipt at 16 KiB/32 KiB/2 MiB/64 KiB.
Do not raise the shared 16 MiB receiver bound. The existing bounded JSON parser
provides byte, duplicate-key, numeric, UTF-8 and depth guards, not separate
node-count or per-string guarantees. Validate exact nested shapes, finite
selection partitions and serialized subdocument bounds before reconstruction.

Use profile `cwe-https-selected-acquisition` version 1, importer
`cwe-https-selected-acquisition` version `1`, and transport profile
`cwe-https-zip-identity-v1`. Evidence roles are `cwe-https-zip-source`,
`cwe-https-zip-partial`, `cwe-https-selected-envelope`, and
`cwe-https-selected-acquisition`. The outer reference uses
`cwe-https-selection:`; the inner `cwe-selection:` contract is unchanged.

Bind full source/notice, requested IDs, matched and unmatched partitions,
original evidence manifest/provenance, effective limits and canonical timeout,
profile/transport identity, observed status/completeness/count and selected
DTO/reference into both envelope and receipt. Do not invent the observed literal
HTTP Content-Type: the existing transport returns bytes, state and status only.

Retain actual bounded partial bytes, including empty results, for transport
failures. Complete HTTP 200 responses with a wrong pin or invalid ZIP/XML retain
their complete original bytes with explicit digest/parse failure. Raw source,
envelope and receipt publication have independent `not-attempted`, `unknown`
and `confirmed` acknowledgement states. Serialize before attempting publication;
set unknown immediately before `Put`, and confirm only a returned handle.
Storage failure removes the usable selection envelope while preserving earlier
known handles and possible committed-but-unacknowledged objects.

The read-only loader validates exact family, limits, canonical identity,
original references and receipt/envelope/raw joins, verifies original bytes and
reparses them through the unchanged selected decoder. Relocation preserves the
result; missing, mixed, mutated or corrupted original custody fails closed.
Replay never acquires network resources, publishes evidence or mutates a model.

## Verification and limits

Exercise malformed sources/requests, bounded actual transport partials, complete
pin/parser refusal, every publication failure/lost acknowledgement, independently
tampered request/provenance/reference/receipt and relocated read-only replay.
Retained genuine catalog fixtures may prove decoding for their pinned bytes;
they cannot prove a fresh HTTPS GET. Known original selectors are CWE-79/89
Weakness, CWE-1000 View and an explicit unmatched identifier; synthetic category
or grouping cases must retain their synthetic provenance.

CLI acquisition and installed/genuine HTTPS acceptance are subsequent slices.
No publisher authentication, legal entitlement, full XSD validation, whole
normalized catalog coverage, target applicability or contextual risk is inferred.
Unmatched and unknown data remain explicit. #43/#47 remain open.
