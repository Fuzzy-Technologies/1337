# Explicit IOC artifact candidates

The experimental `fuzzy1337.ioc_artifacts` API accepts explicitly supplied,
caller-owned non-secret bytes. This is the first IOC evidence slice of Task #85
under Feature #83. Wider log/file/entity/process normalization and incident/event
modeling remain open. Supplied indicators are candidates: they do not establish
maliciousness, an incident, an observed attack path or current scope authority.
The API never resolves names, probes addresses, launches processes, fetches
locators, creates Findings or writes the canonical Core model.

## Closed input profile

`ascii-ioc-tsv-v1` uses ASCII bytes and LF or CRLF physical line endings. The
final line may omit its ending. Each nonempty physical line contains exactly two
or four tab-separated fields. There is no header, comment, quoting, escaping,
blank line, Unicode/IDNA conversion or inferred token type.

```text
ipv4<TAB>192.0.2.7
ipv6<TAB>2001:0DB8::1
dns<TAB>EXAMPLE.Invalid.
sha256<TAB>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
dns<TAB>example.invalid<TAB>2026-10-12T12:34:56+05:30<TAB>+05:30
```

Replace `<TAB>` with an actual tab byte. Supported kinds are:

| Kind     | Accepted token                                      | Normalization                                |
| -------- | --------------------------------------------------- | -------------------------------------------- |
| `ipv4`   | Literal IPv4, without ambiguous leading zero octets | Standard decimal octets                      |
| `ipv6`   | Literal IPv6, including mapped addresses; no zones  | Lowercase hextets; first longest zero run    |
| `dns`    | At least two ASCII labels; letters/digits/hyphens   | Lowercase; removes one optional terminal dot |
| `sha256` | Exactly 64 ASCII hexadecimal characters             | Lowercase hexadecimal                        |

DNS labels contain 1–63 characters and cannot begin or end with a hyphen. Names
contain at most 253 characters after removal of the terminal dot. Numeric-only
labels cannot masquerade as a DNS address. ASCII `xn--` labels remain literal
ASCII labels; the parser does not decode or authenticate them. SHA-256 tokens
refer to declared candidate file hashes; the parser never reads a corresponding
file. Mapped IPv6 normalization uses fixed hextet rules across supported Python
versions rather than runtime-dependent dotted presentation.

Four-field records carry an original ISO timestamp and its exact suffix: `Z` or
`+HH:MM`/`-HH:MM`. Dates/times are valid calendar values, seconds are required,
fractional seconds contain at most six digits, and unknown `-00:00` is rejected.
The original timestamp/timezone is preserved alongside derived UTC. An untimed
record remains untimed. Source-declared future observations remain declarations;
they never replace the separately observed acquisition clock.

`IocLimits` defaults are also the hard ceilings: 65,536 source bytes, 256 physical
lines, 256 items, 512 bytes per physical line excluding its ending, and 512 bytes
per token. Callers may lower each limit. Limits require exact positive integers;
booleans and expanded ceilings are rejected. Metadata JSON is separately bounded
to depth eight, 8 KiB acquisition receipts and 512 KiB snapshots. Source line/item
limits are checked before allocating split records; replay applies the original
source byte budget before the evidence owner's eager blob read.

## Acquisition and replay

The following example uses only owned synthetic data and a new local workspace.
Source and license locators are opaque attribution strings and are never read.

```python
import hashlib
from pathlib import Path

from fuzzy1337.ioc_artifacts import (
    AcquireIocArtifact, IocRequest, IocSource, LoadIocArtifact,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

root = Path("owned-ioc-workspace")
LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned IOC sample"), "owned-ioc")
payload = b"dns\tEXAMPLE.Invalid.\nipv4\t192.0.2.7\n"
source = IocSource(
    "owned.synthetic", "fixture-1", "owned:case.tsv", "Apache-2.0",
    "owned:LICENSE", hashlib.sha256(payload).hexdigest(),
)
outcome = AcquireIocArtifact(root, IocRequest(payload, source), scope_reference="scope:owned")
assert outcome.state == "succeeded", "Owned acquisition did not accept the explicit profile"
assert outcome.snapshot_record is not None, "Successful acquisition did not retain its snapshot"
replayed = LoadIocArtifact(root, outcome.snapshot_record.evidence_id, outcome.receipt.evidence_id)
assert replayed.candidates[0].normalized_token == "example.invalid", "Replay changed the candidate"
```

A successful acquisition publishes three immutable owning evidence records:
`ioc-source`, `ioc-acquisition` and `ioc-snapshot`. The receipt pins the original
raw manifest identity, exact source/version/license/digest selection, profile,
parser/version, finite budgets, workspace/scope and receiver-observed collection
window and a canonical source/profile/parser/budget request digest. Offline
execution and invocation provenance remain None. A snapshot pins the receipt
and raw identities and preserves each raw
token, logical locator, physical line number, byte offset and byte length.
Offsets are zero-based positions in the original source bytes; line numbers are
one-based. Duplicate occurrences remain in original order.

Empty, malformed or partial supplied data publishes original bounded bytes and a
`parse-rejected` receipt with no snapshot. A wrong expected digest yields
`digest-rejected`, preserving both the declared pin and actual raw evidence.
Oversize requests are rejected before storage and are never silently truncated.
Storage failures raise the existing evidence-owner exceptions; immutable orphan
records may remain and no successful result is returned.

`ReplayIocArtifact` accepts an exact typed snapshot record plus an independent
caller-retained original acquisition receipt record. `LoadIocArtifact` accepts
the two corresponding manifest identities. Retain the original receipt anchor
when selecting or inspecting snapshots; never take it from the candidate snapshot
being inspected. Both reopen the owning
workspace, verify exact manifests and source/parser/time/budget bindings, and
independently reparse the raw source. Rehashed altered snapshots and individually
substituted raw/receipt/derived manifests fail the original agreement checks.
Even coherent receipt and snapshot rewrites cannot alter source/license/budgets
while borrowing original raw bytes when the caller retains the original anchor.
Frozen-object field mutations and foreign typed subclasses are revalidated and
rejected at public boundaries. Original input paths are unused during replay,
including Windows-form logical locators, so moving the owning workspace preserves
historical evidence without reviving scan authority.

These are local integrity and attribution guarantees. Publisher authenticity,
source truth, licensing approval and maliciousness are not assessed. Public
hashes are not signatures. Preserve the independently trusted original acquisition
receipt and its manifest identity;
replacing an entire chain together with its trusted identifiers is outside this
local evidence-integrity guarantee.

See [ADR 0076](adr/0076-bounded-ioc-artifact-evidence.md) for the bounded decision
and the incident/event/Core modeling fork left open for its owner.
