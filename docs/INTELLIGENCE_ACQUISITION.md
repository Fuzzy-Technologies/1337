# Bounded intelligence snapshot acquisition

`fuzzy1337.intelligence_acquisition` is an Experimental schema-v1 library under
[ADR 0060](adr/0060-bounded-intelligence-snapshot-acquisition.md). It provides a
production import/sync path to the existing [intelligence parser and verified
finding consumer](INTELLIGENCE.md), using the owning workspace's immutable raw
evidence. It does not create vulnerabilities, approve applicability, alter
operator triage, scan targets, or write canonical model state.

The documented surface is `SnapshotSource`, `SnapshotRequest`, `AcquisitionState`,
`AcquisitionOutcome`, `SyncState`, `SyncOutcome`, `CisaKevSource`,
`AcquireIntelligenceSnapshot`, `SyncIntelligenceSnapshots`, and
`LoadAcquiredSnapshot`. `fuzzy1337.intelligence_transport` and acquisition
validation/transport helpers are Internal.

## Explicit source selection

Local import requires explicitly supplied authorized uncompressed UTF-8 bytes,
typed feed and origin, exact catalog/model version, declared publisher/source
URL/license, and an optional expected SHA-256. It supports the existing bounded
CVE Record JSON, CWE XML, CISA KEV JSON, and FIRST EPSS CSV parsers. Publisher and
license statements remain attributed caller declarations. The importer records
its own identity/version and observes UTC acquisition start and finish; callers
cannot substitute a historical or future acquisition clock.

Remote acquisition currently accepts only `CisaKevSource(commit, catalog_version)`
with an exact lowercase 40-hex commit in the official `cisagov/kev-data` mirror.
The JSON `catalogVersion` must match the supplied catalog version; the Git commit
pins source bytes independently. The selected URL is the same-revision raw JSON
file, and license attribution points to that revision's `LICENSE` as `CC0-1.0`.
An optional expected SHA-256 checks the exact body. No current official corpus or
license text is bundled or inferred from a fabricated fixture.

The [CISA mirror's official README](https://github.com/cisagov/kev-data) describes
the JSON file, its CISA origin and CC0 licensing. The mirror can lag the canonical
catalog. A selected historical revision does not claim current coverage. Choosing
the commit and catalog version is an explicit operator workflow; this interface
does not query a moving branch or discover a latest release.

HTTPS uses platform certificate verification and no inherited proxy, cookie,
credential, or trust-store environment variables. Transport TLS and byte hashes
do not verify publisher signatures, catalog correctness, redistribution rights,
or source applicability. `scope_reference` attributes collection and grants no
scan authority. No API key or paid provider is involved.

## Bounds and lifecycle

`SnapshotRequest` defaults to 16 MiB and 30 seconds; a caller may narrow the byte
limit and select a finite 0.05–60 second remote acquisition deadline. Local bytes
are already supplied by the caller; the deadline bounds the isolated HTTPS
receiver, not caller-owned file reads, parsing, evidence publication, or sync's
whole batch. Batch size is one to sixteen explicitly ordered requests.

The HTTPS receiver uses a fresh stdlib-only Python process in isolated mode with
an empty environment and disabled site initialization (`-I -S`). The parent's
total deadline starts before process creation
and covers receiver startup, DNS, connection, TLS, headers, and body reads.
Timeout and caller interruption kill and join the receiver; socket timeouts are
an additional inactivity bound. This is resource cleanup ownership rather than
an execution sandbox. The receiver creates no descendants and stderr is discarded
instead of exposing local paths or arbitrary exception text.
Caller interruption propagates after receiver cleanup; it does not manufacture
a completed acquisition receipt or erase earlier independent publications.

One GET is permitted. Redirects are refused without following `Location`, and
only status 200, identity encoding, and supported HTTP framing can succeed. The
receiver never decompresses or retries. Body storage stays within the configured
bound. Captured incomplete evidence contains only bytes actually emitted by the
receiver; a declared overlarge Content-Length can be refused before any body is
read, leaving no captured body. Metadata and partial bytes never become a parsed
source just because they form syntactically valid JSON.

## Immutable outcomes

The importer publishes original raw bytes, a successfully parsed snapshot, and
a terminal receipt through the existing no-overwrite content-addressed store.
The receiver's finish time becomes `ReferenceSource.acquired_at`; effective
publisher times remain unchanged in parsed records. Snapshot provenance retains
the source URL, version, license, byte hash, importer, and original evidence.

`AcquisitionState.SUCCEEDED` requires successful raw, snapshot, and receipt
publication. Digest or parser failure retains original complete bytes and a
failed receipt. Redirect, HTTP, framing, size, transport, and timeout states stay
distinct. Available incomplete bytes use `intelligence-partial`; they provide no
snapshot. A receipt records `body_complete` separately from interpretation
success, the actual local/HTTPS transport selection, selected byte/deadline
bounds, and `publisher_authentication="not-assessed"`.

These publications are individually atomic, rather than one filesystem
transaction. Storage failure returns `storage-failed`, `snapshot=None`, and the
raw/snapshot records known to have published successfully. An orphan blob or
published snapshot may remain after a later failure. No prior evidence is deleted
or replaced, and no failed publication is reported as successful. Receipt content
omits its own identity to avoid circular hashing.

`SyncIntelligenceSnapshots` performs each selected acquisition once, in caller
order. Its state is succeeded when every item succeeds, partial when some succeed,
and failed when none succeed. Every returned item retains its own terminal facts;
there is no hidden retry, rollback, stale cache fallback, or clean-scan assertion.

## Local import and verified replay

```python
from pathlib import Path

from fuzzy1337.intel_references import SourceOrigin
from fuzzy1337.intelligence import IntelligenceFeed
from fuzzy1337.intelligence_acquisition import (
    AcquireIntelligenceSnapshot, AcquisitionState, LoadAcquiredSnapshot,
    SnapshotRequest, SnapshotSource,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

root = Path("owned-intelligence-workspace")
LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned Intel example"), "example")
raw = (b"#model_version:synthetic-1,score_date:2026-10-12T00:00:00Z\n"
       b"cve,epss,percentile\nCVE-1900-9999,0.2,0.8\n")
source = SnapshotSource(
    IntelligenceFeed.EPSS, "synthetic-1", SourceOrigin.SYNTHETIC,
    "1337 synthetic fixture", "https://example.invalid/scores.csv",
    "Apache-2.0 (synthetic fixture only)", "https://example.invalid/LICENSE",
)
outcome = AcquireIntelligenceSnapshot(
    root, SnapshotRequest(source, payload=raw), scope_reference="scope:owned",
)

if outcome.state is AcquisitionState.SUCCEEDED and outcome.snapshot_record is not None:
    snapshot = LoadAcquiredSnapshot(root, outcome.snapshot_record.evidence_id)
```

This example imports owned synthetic data and contacts no URL. Use an existing
owned workspace in a real application. Replay verifies both the owning snapshot
and original raw acquisition manifests, complete-source role, original byte
digest/length, and exact reparse. Source importer/version and acquisition time
must match the original receiver provenance; rehashed source metadata cannot
replace those observed facts. Snapshot and raw manifests must retain the exact
same owning collection context. A surviving blob without its original acquisition
manifest is insufficient.
It remains portable across workspace relocation. Missing/corrupt artifacts,
foreign workspace attribution, wrong roles, and forged normalized interpretations
fail rather than yield a partial usable snapshot.

The returned snapshot can be passed to `ApplyVerifiedEnrichment` with an existing
canonical finding, explicit identifiers, caller interpretation provenance/time,
and a freshness budget. That consumer retains its original evidence verification,
candidate association, triage preservation, and explicit model CAS contracts.

## Evidence and remaining work

Deterministic functional tests execute import/sync, immutable publication and
portable replay, then the actual verified canonical finding consumer. Owned
connection and subprocess fixtures cover framing, refusals, bounds, partial
bytes, empty environment, timeout, and caller-interruption cleanup without
contacting a live publisher. No live official-feed acceptance is claimed.

Automatic refresh scheduling, broader provider acquisition, incremental/full
corpus support, publisher signatures, license decisions, feed monitoring,
applicability/CPE/version matching, risk calculation, and CLI/shell commands remain
separate scope. #47 remains open for its remaining intelligence acceptance.
