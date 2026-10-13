# ADR 0060: Bounded intelligence snapshot acquisition

- Status: Accepted implementation decision under ADRs 0023 and 0041
- Date: 2026-10-13
- Related work: #43, #47, #276

## Decision

An Experimental library acquisition boundary receives explicitly selected local
source bytes for the four existing vulnerability-intelligence formats, or one
exact commit of the official CISA KEV GitHub mirror. It uses the existing
`LocalEvidenceStore`, parser, portable `IntelligenceSnapshot`, and verified
finding-enrichment consumer. It creates no second canonical model or mutable
latest-catalog index. Source knowledge never changes finding triage or grants
execution authority.

Caller declarations identify feed, catalog/model version, source origin,
publisher, URL, license, and an optional byte digest. The receiver observes its
own acquisition start/finish times; acquisition time is not accepted from the
caller. A downloaded commit locator and catalogVersion describe different
identities. HTTPS certificate validation authenticates the transport endpoint
according to the platform trust configuration; it is not verification of a CISA
signature, source correctness, license entitlement, or finding applicability.

Remote acquisition is a single uncredentialed HTTPS GET to the exact pinned
`raw.githubusercontent.com/cisagov/kev-data/<40-hex-commit>/known_exploited_vulnerabilities.json`
locator. Moving references, arbitrary URLs, redirects, unsupported response
framing, non-200 responses, and compressed content are refused. There is no
automatic retry, provider discovery, crawling, cache fallback, or latest-version
selection.

A stdlib-only receiver process has an empty environment, Python isolated mode,
and disabled site initialization (`-I -S`). The parent deadline starts before process creation
and includes receiver
startup, DNS, connection, TLS, headers, and body reads. Timeout or caller
interruption kills and joins this owned process. Socket inactivity bounds are
additional safeguards. The receiver emits at most the configured body bound
plus one small controlled status header; no unbounded third-party stdout or
exception text enters evidence. This process boundary provides deadline and
cleanup ownership, not a CPU, memory, filesystem, or network sandbox.

## Publication and failure semantics

Original received bytes are published first, then a strictly parsed portable
snapshot, then a terminal acquisition receipt. Each uses the existing atomic
no-overwrite content-addressed evidence publisher. Complete source bytes keep
the `intelligence-source` role; captured incomplete bytes use
`intelligence-partial` and never supply a usable parsed snapshot. Parsing and
expected-digest failures retain complete original bytes and an explicit failed
receipt. Network failures can retain only bytes actually delivered to the parent,
never a reconstructed or invented response.

The three publications are not one transaction. Storage failure can leave an
immutable orphan blob or already-published raw/snapshot record. Returned state
is `storage-failed`, with the records whose publication returned successfully;
no cleanup deletes historical evidence and no success is fabricated. A receipt
cannot self-reference its own content identity. It records the selected source,
observed clocks/status, body completeness, original evidence, snapshot record,
the actual local/HTTPS transport selection and receiver limits, and the explicit
unassessed publisher-authentication boundary.

Explicit sync processes one to sixteen requests in caller order, retaining every
terminal outcome and a succeeded/partial/failed summary. It never rolls back a
successful independent source or overwrites an earlier revision. Invalid batch
selection is rejected before acquisition. Loading a snapshot checks owning
and original raw manifest attribution, original byte integrity, the complete-source
role, and an exact reparse before handing it to the existing verified consumer.
The source importer/version and acquired_at must match receiver provenance, and
the raw record must have the exact same owning collection context as its snapshot
record. Recomputed public hashes or a surviving blob cannot replace lost or
changed acquisition attribution. Canonical
model persistence remains an explicit caller decision using the existing CAS.

## Validation and remaining scope

Deterministic tests exercise the actual import/sync API, immutable raw/snapshot
and receipt publication, parser/version refusal, expected digest mismatch,
partial transport results, no retries, storage failure, relocation, corruption,
foreign attribution, and the existing canonical enrichment consumer. Owned
connection and real subprocess fixtures verify redirects, framing, size,
timeout, interruption, empty environment, and worker cleanup without remote
network requests. This evidence does not claim live official-feed acceptance.

Automatic refresh scheduling, incremental/full corpus ingestion, new upstream
formats, other production HTTPS providers, publisher signatures, license
decisions, feed health monitoring, applicability/CPE/version matching, CLI/shell
commands, and risk calculations remain separate work in #47 and neighboring
tasks. This bounded slice does not close the full intelligence milestone.
