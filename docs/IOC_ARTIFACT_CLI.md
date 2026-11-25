# Explicit local IOC artifact commands

`1337 trace ioc` is an Experimental version-one product interface over the
accepted offline ASCII TSV artifact profile. It records supplied candidates and
original evidence. It does not establish maliciousness, create Findings, mutate
Core or authorize a scan. Use only explicitly owned non-secret files.

## Import one selected file

Create the owning workspace through the existing `workspace create` command.
Supply an absolute physical source path and independently known lowercase byte
SHA-256. Every source/version/license field is declared, not authenticated.
Logical source/license locators are opaque data; they are never opened or fetched.

```bash
1337 trace ioc import /owned/case-workspace \
  --file /owned/case.tsv \
  --source-id owned.case --source-version export-1 \
  --source-locator owned:case.tsv \
  --license-name owned-permission --license-locator owned:permission-record \
  --expected-sha256 <64-lowercase-hex-byte-digest> \
  --scope scope:owned-collection --owner owner:collector \
  --read-consent-reference read:owned-non-secret \
  --max-bytes 65536 --max-lines 256 --max-items 256 \
  --max-line-bytes 512 --max-token-bytes 512 --json
```

Replace the digest placeholder with the exact source byte pin; it is not a
manifest identifier or proof of publisher authenticity. The five shown limits
are the accepted defaults and hard ceilings. Callers may reduce each limit but
cannot expand it. Oversize files fail before acquisition, without truncation.

The file must be physical, regular, singly linked, within the byte limit and
stable across observed path/handle reads. Relative paths, traversal, links,
reparse points and observed replacement/mutation are refused. The explicit owner
and read references declare selected-file permission; they are not signatures
or assessment grants. They do not add new fields to the unchanged acquisition
receipt. Collection `--scope` is opaque attribution, not a current target grant.

Each nonempty ASCII TSV line contains `kind<TAB>token`, optionally followed by
`<TAB>original-offset-bearing-timestamp<TAB>exact-timezone-suffix`. Supported
literal kinds are `ipv4`, unscoped `ipv6`, `dns` and `sha256`. There is no header,
blank line, comment, quoting, URL inference, IDNA conversion or DNS resolution.
Duplicates retain their separate original occurrences. Source-declared future
timestamps remain source facts and do not replace the receiver acquisition clock.

Successful import retains three immutable owning records: original raw bytes,
terminal acquisition receipt and derived snapshot. Keep the returned independent
`receipt_id` and `snapshot_id` from that original acquisition. Terminal JSON
contains only counts, observed source hash/length, acquisition times and evidence
identifiers. It excludes original tokens, physical paths and declared read/source
references. Supplied candidate data remains in the explicit evidence owner and
the existing `LoadIocArtifact` API.

## Inspect original evidence

```bash
1337 trace ioc inspect /owned/case-workspace \
  --snapshot sha256:<original-snapshot-manifest-digest> \
  --receipt sha256:<independently-retained-original-receipt-manifest-digest> --json
```

Both identifiers are mandatory original manifest identities, not raw byte hashes.
Never obtain the trusted receipt pin from a snapshot being inspected. Inspection
checks the owning manifests, role/media/size limits, complete original bindings
and independent original-byte reparse. Altered candidate metadata is refused
even when alternative public hashes are recomputed.

Omit `--json` to see the verified original evidence manifest ID, source SHA-256
and byte length in the text summary. The manifest ID identifies the original TSV
record in the relocated workspace. For `sha256:<digest>`, see
`evidence/records/<digest>.json` and its blob locator. The source SHA-256 is the
checksum of the retained TSV bytes.

Inspection works after moving the owning workspace and deleting the source file.
It performs no save/acquisition, source rediscovery, network or process action.
It accepts no source/license/consent overrides. The same explicit commands work
in the foreground shell; the protected `trace` namespace is not retained for
history/replay, including malformed input.

## Locate occurrences of a supplied IOC

Use `--match KIND TOKEN` once with a known non-secret literal in text mode.

```bash
1337 trace ioc inspect /owned/case-workspace \
  --snapshot 'sha256:<original-snapshot-manifest-digest>' \
  --receipt 'sha256:<independently-retained-original-receipt-manifest-digest>' \
  --match dns example.invalid
```

After verifying both manifest selections, the command compares the kind and
normalized token using the same literal grammar as import. It prints the
original evidence manifest ID and every matching occurrence in source order,
including duplicates. Each occurrence gives the one-based physical line,
zero-based byte offset and byte length of the original token. The source-declared
time and timezone use their original spelling or appear as `unknown` when absent.
Use the manifest ID and byte range to retrieve the exact token from the
retained TSV.

Zero matching occurrences is a successful verified lookup. An integrity refusal
returns exit 4 with empty stdout. `--match` requires text mode. Use ordinary
inspection with `--json` for the schema-one summary.

## Export verified normalized candidates

Explicitly request a machine handoff of the owned non-secret candidate data:

```bash
1337 trace ioc inspect /owned/case-workspace \
  --snapshot 'sha256:<original-snapshot-manifest-digest>' \
  --receipt 'sha256:<independently-retained-original-receipt-manifest-digest>' \
  --export-candidates --json
```

On success, the usual schema-one terminal result also contains
`candidate_export`: the unchanged schema-one normalized snapshot document. It
includes every candidate in source order, original and normalized tokens,
physical line/byte coordinates, source-declared timestamps/timezones, original
raw/receipt manifest identities, source/version/license attribution, parser
identity/version and original limits. Duplicate occurrences remain separate.
The surrounding result retains the original acquisition clock and the selected
snapshot manifest ID, separately from source-declared observation times.

This flag explicitly discloses original tokens and declared source/license
locators to stdout. Use it only for the owned non-secret data selected at import;
handle redirected output with the same care as that data. Default inspection
continues to emit only its summary. Export requires `--json`, cannot be combined
with `--match`, and is unavailable during import. Invalid combinations fail
before storage access. Any replay or integrity refusal omits `candidate_export`
entirely and emits no partial candidates.

Export uses the same independent original receipt anchor and retained-byte
reparse, including after relocation and source deletion. It creates no output
file and performs no acquisition or Core/workspace save. An ordinary shell may
redirect its stdout when a local file is needed. It never resolves or assesses
the exported indicators. See [ADR 0148](adr/0148-verified-ioc-candidate-export.md).

## Inspect one normalized occurrence

Use the Python SDK with the `snapshot_id` and independent `receipt_id` saved from
the original import. Select a one-based physical line in the original TSV. A
line identifies an occurrence even when several lines normalize to the same value.

Save this example as `inspect_ioc_candidate.py` in your local working directory.

```python
import json
import sys
from pathlib import Path

from fuzzy1337.ioc_artifacts import LoadIocArtifact

workspace, snapshotId, receiptId, line = sys.argv[1:]
lineNumber = int(line)
snapshot = LoadIocArtifact(Path(workspace), snapshotId, receiptId)
candidate = next((item for item in snapshot.candidates if item.line_number == lineNumber), None)

if candidate is None:
    raise SystemExit(f"No supplied candidate at source line {lineNumber}.")

metadata = json.loads(snapshot.Serialize())
print(json.dumps({
    "candidate": candidate.ToDict(),
    "raw_evidence_id": snapshot.raw_evidence_id,
    "source_id": snapshot.source.source_id,
    "source_version": snapshot.source.source_version,
    "parser_id": metadata["parser_id"],
    "parser_version": metadata["parser_version"],
}, indent=2))
```

```bash
python inspect_ioc_candidate.py /owned/case-workspace \
  'sha256:<snapshot-manifest-digest>' 'sha256:<original-receipt-manifest-digest>' 2
```

The example prints one verified occurrence, including its normalized and original
tokens, logical source locator, and source-declared timestamp and timezone when
present. The zero-based `byte_offset` and `byte_length` locate its original token
in the retained TSV identified by `raw_evidence_id`.

## Outcomes

Without `--json`, a refusal includes the same fixed failure category as the
machine result. Categories distinguish invalid configuration from retained
evidence integrity failures without echoing rejected values or physical paths.

| Exit | Meaning                                                           |
| ---- | ----------------------------------------------------------------- |
| 0    | Acquisition or independently anchored replay verified             |
| 2    | Invalid explicit grammar, declarations, limits or selected file   |
| 4    | Refused acquisition, integrity/storage failure or unknown outcome |
| 130  | Interrupted operation                                             |

Digest/parse refusal retains original raw and terminal receipt identifiers,
reports `evidence_commit: confirmed`, and returns no usable snapshot. A storage
error/interruption after acquisition begins reports `unknown`: records may have
been published without acknowledgement. There is no rollback claim or atomic
three-record transaction. Inspect uses `not-attempted` because it does not write.
The command never changes workspace/Core state. Generic diagnostics do not copy
rejected argument values, physical names or source bodies.

This slice does not complete wider DFIR ingestion. Logs, process/entity evidence,
custody/collector contracts, Core investigation/timeline semantics and observed
attack paths remain separate work. See [ADR 0076](adr/0076-bounded-ioc-artifact-evidence.md)
and [ADR 0080](adr/0080-explicit-local-ioc-cli.md).
