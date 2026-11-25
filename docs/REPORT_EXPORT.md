# Offline report export

The current development candidate exposes the accepted report SDK through one
Experimental product command. [ADR 0049](adr/0049-offline-product-report-export.md)
defines the owning read/publication boundary;
[ADR 0077](adr/0077-explicit-html-junit-report-export.md) adds HTML and JUnit:

```bash
uv run --locked 1337 report export owned-workspace --format json --output report.json --json
uv run --locked 1337 report export owned-workspace --format sarif --output report.sarif.json
uv run --locked 1337 report export owned-workspace --format html --output report.html --json
uv run --locked 1337 report export owned-workspace --format junit --output report.junit.xml --json
```

The selected workspace must already exist and contain a saved canonical model.
The output parent must already exist and the selected file must be absent, outside
the source workspace. `--format` and `--output` are required. Use `report export
<workspace> --format <json|sarif|html|junit> --output <new-file>` inside the shell; the shell
uses the same foreground consumer and retains only `report` in history/replay.
That protection also covers malformed punctuation, missing spaces and quoting;
the namespace is sanitized before dispatch, including during empty-line replay.
Owned terminal input loops apply the same rule to newly appended native
readline/libedit entries before dispatch, so arrow recall cannot recover the
arguments. Prior caller entries, disabled automatic history, queued/stream input
and direct command calls retain their existing ownership. The loop preserves
caller completion/settings and restores its cursor on EOF or interruption;
it neither clears history nor reads/writes history files. Native absolute-index
identification uses at most 100 starting positions; an unidentifiable backend
fails before accepting input instead of guessing or rewriting prior entries.
Later boundaries identify at most 100 new absolute positions, with one end probe
and fixed live-range checks. Retired prefix gaps in a capped GNU buffer advance
the cursor without changing handler-owned additions. Excess or unidentifiable
retirement stops the loop before another input can be accepted.
Observation after a command can also re-identify at most 100 previous positions
when GNU cap introduction renumbers the tip backward. This changes only the
cursor, never caller entries; actual input cannot claim an earlier native tip.
An opened shell model or selected object supplies no implicit workspace.
`1337 report --help` describes the command without opening a workspace.

The command reopens workspace/model/scope through their owning stores. It verifies
every retained acquisition and raw reference, including older acquisitions unused
by the model, then verifies all report-linked bytes with `VerifyReportEvidence`.
Missing, corrupt, foreign or unsafe input fails before publication. Valid revoked
or expired scope metadata remains historical context; report reading grants no
execution approval and does not replace original source attribution with current
scope revisions. Empty saved workspaces need no scope.

The JSON report embeds the exact saved model and its digest/revision. The SARIF
adapter preserves the existing active/closed finding semantics. HTML and JUnit
use the same accepted pure renderers over that exact owner-verified saved snapshot,
as defined by [ADR 0077](adr/0077-explicit-html-junit-report-export.md).
All four formats keep failed source outcomes and operator triage. Reports include
links/metadata, never acquired raw bytes or local workspace paths. Metadata must already satisfy the model's
non-secret input contract; this reader does not discover or redact secrets.
See [report semantics](REPORTING.md) for the distinction between byte integrity,
source claims and finding interpretations.

HTML is the existing self-contained dark report with escaped text, native
disclosures and canonical evidence/object fragments. It includes no scripts,
remote assets or acquired raw bytes. Selected native HTML reflection and SQL
sampling observations link to their retained response evidence. These rows
report lexical marker observations and individual samples separately from
browser execution and injection assessment. JUnit XML retains one case per Finding:
open/confirmed dispositions fail and dismissed/resolved dispositions skip.
An empty snapshot has zero cases, without inventing passed security checks.
Report metadata retains original source failures, verified byte references,
snapshot identity and `scan_completeness: not-assessed` in every format.
These are presentation semantics. A successfully published JUnit report exits
zero even when it contains failure cases; `report export` does not apply finding
thresholds or run a CI gate. The emitted report remains a pinned historical
artifact after later model changes. A new explicit export selects the later
saved snapshot; it cannot rewrite the prior output.

## Review a handed-off HTML report

Save the JSON outcome printed by the HTML export command above as
`report-export.json` and hand it off with `report.html`. Both paths must
refer to regular files. Run the check from the directory containing them.

For other filenames or locations, use
`python - 'delivery/received report.html' 'delivery/export receipt.json' <<'PY'`
as the first line. Pass the HTML report path first and the JSON outcome path
second.

```bash
python - <<'PY'
from hashlib import file_digest
from json import loads
from os import fstat
from pathlib import Path
from re import fullmatch
from stat import S_ISREG
from sys import argv


def UniqueFields(pairs):
    """Read a JSON object with one value per field."""

    fields = dict(pairs)

    if len(fields) != len(pairs):
        raise ValueError("Duplicate JSON field.")

    return fields


paths = argv[1:]

if len(paths) not in (0, 2):
    raise SystemExit("Supply the HTML report path and the JSON outcome path together or omit both.")

reportPath, outcomePath = map(Path, paths or ("report.html", "report-export.json"))
reportLabel = "HTML report" if paths else "report.html"
outcomeLabel = "JSON outcome" if paths else "report-export.json"

try:
    if not S_ISREG(outcomePath.stat().st_mode):
        raise SystemExit(f"{outcomeLabel} must be a regular file.")

    outcome = loads(
        outcomePath.read_text(encoding="utf-8"),
        object_pairs_hook=UniqueFields,
    )

except (OSError, ValueError, RecursionError):
    raise SystemExit(f"Could not read {outcomeLabel} as JSON.")

if not isinstance(outcome, dict):
    raise SystemExit("Expected an export outcome JSON object.")

schemaVersion = outcome.get("schema_version")

if (
    type(schemaVersion) is not int or schemaVersion != 1
    or outcome.get("command") != "report.export"
    or outcome.get("status") != "completed"
    or outcome.get("format") != "html"
    or outcome.get("output_published") is not True
):
    raise SystemExit("Expected a completed, published schema-v1 HTML export.")

sizeBytes = outcome.get("size_bytes")
reportSha256 = outcome.get("report_sha256")

if type(sizeBytes) is not int or not 0 <= sizeBytes <= 32 * 1024 * 1024:
    raise SystemExit("Invalid size_bytes in the export outcome.")

if not isinstance(reportSha256, str) or not fullmatch(r"[0-9a-f]{64}", reportSha256):
    raise SystemExit("Invalid report_sha256 in the export outcome.")

try:
    if not S_ISREG(reportPath.stat().st_mode):
        raise SystemExit(f"{reportLabel} must be a regular file.")

    with reportPath.open("rb") as stream:
        if fstat(stream.fileno()).st_size != sizeBytes:
            raise SystemExit(f"{reportLabel} differs from the recorded byte size.")

        if file_digest(stream, "sha256").hexdigest() != reportSha256:
            raise SystemExit(f"{reportLabel} differs from the recorded SHA-256.")

except OSError:
    raise SystemExit(f"Could not read {reportLabel}.")

print(f"{reportLabel} matches the export outcome's size and SHA-256.")
PY
```

The check confirms byte consistency with the supplied outcome. Publisher
authenticity requires independently trusted provenance for the files.
Compare the report header's saved revision with `model_revision`. In **Overview**,
open **Snapshot identity and technical summary** and compare **Canonical
snapshot** with `snapshot_sha256`, the digest of the saved model.

1. Open **Recorded operations** and use **Execution attribution** for a source's
   saved outcome. Failed records remain visible. When execution records are
   absent, which checks ran remains unknown. In **Assets**, **Not recorded**
   marks an unknown inventory value.
2. In **Findings**, use a finding's **Subject** link to locate the saved object.
   Follow a link under **Evidence for this interpretation** to its row in
   **Evidence and byte integrity**. Evidence numbers on finding cards match their
   rows in the Evidence table. Open **Digest and metadata** for the exact reference.
3. To direct another reader to the same row, cite the evidence link's fragment
   with this report. `verified bytes` records the integrity check at export
   time. The row contains reference metadata. Independent acquisition
   verification uses the workspace's [owning evidence store](EVIDENCE.md).

## Bounds and output truth

The consumer accepts at most 1,024 retained acquisition manifests, 1,024 distinct
raw blobs, 32 MiB per blob, 128 MiB distinct raw bytes and 256 referenced scopes.
Actual stored sizes are checked before owning raw reads. Existing metadata/model
limits remain in their owners; complete serialized output is limited to 32 MiB.
These checks pin one owner-read snapshot, rather than monitoring filesystem
freshness. A once-reopened workspace/model comparison rejects cooperative source
changes before publication.

Publication uses a private same-directory file, flush/fsync, atomic no-clobber
hard link and owned temporary cleanup; POSIX also synchronizes the parent.
Existing files and concurrent creators are preserved. Links/reparse points,
traversal, missing parents and unsupported hard-link filesystems fail explicitly.
Physical directory identities also reject source aliases such as alternate case
or short names; unavailable identities fail configuration. If a link commits
before an interrupt or failure is acknowledged, only the exact original private
file's device/inode/size can confirm publication. Equal foreign bytes, directories
and observed links never count, and competing selected files are never removed.
Exclude hostile concurrent filesystem writers as required by the owning stores.
If synchronization or cleanup fails after the atomic link, the command reports
failure while preserving the complete output and `output_published: true`.

| Exit | Meaning                                                                |
| ---- | ---------------------------------------------------------------------- |
| 0    | Export completed; findings and failed source executions remain visible |
| 2    | Invalid explicit command or selected path configuration                |
| 4    | Input integrity/change, quota, rendering or publication failure        |
| 130  | Interrupted; any confirmed complete publication remains explicit       |

`--json` writes only the command outcome to the terminal. Its schema is
[`report-export-result.schema.json`](../contracts/report-export-result.schema.json).
It records format, saved model digest/revision, report size/hash, checked reference
counts and confirmed publication. Report bytes go only to the selected file.
Diagnostics use fixed categories without rejected arguments or exception text.
Export success is independent of source success, and `scan_completeness` remains
`not-assessed`. Zero findings do not establish a clean scan.

This command opens no job, starts no provider/process and contacts no target.
Inferred reference context, raw evidence bundles,
concurrent TUI, scanner enrichment and release acceptance remain separate work.
Task #40 remains open. `fuzzy1337.report_commands`, including its house-style
helpers, is Internal CLI implementation; this adds no authoritative storage API.

## Verification

```bash
uv run --locked python -m pytest -q --no-cov \
  tests/unit/test_report_commands.py tests/integration/test_report_export.py \
  tests/unit/test_shell.py tests/e2e/test_shell_history.py
```

Tests use real owned stores and deny process/network operations on product paths.
They cover triage/failed acquisitions, corrupt/foreign/missing input, quotas before
both raw-read paths, relocation, changed snapshots, links, output races, safe
diagnostics, interrupted cleanup and complete post-publication failure truth.
Fresh owned POSIX PTYs exercise the available libedit/GNU backends, native arrow
and empty replay, disabled/preexisting/queued history, interruption and GNU EOF.
Optional unavailable native backends skip explicitly; stream EOF and command
ownership remain covered independently. The GNU oracle also preserves a cap
established before or during the loop, using its advancing absolute history base.
Actual cap1 handler additions exercise retired gaps, privacy before consumer
dispatch, exact 100-position recovery and 101-position refusal.
The HTML/JUnit addition also exercises actual installed-module console commands
for workspace creation and all four exports over retained owned synthetic
evidence/model facts. Independent literal HTML/XML assertions cover inert hostile
markup, visible controls, resolved fragments, failed source facts, all four
Finding dispositions and zero-case output. Relocation, historical revoked scope,
later model mutation, corrupt unused evidence and foreground shell keep the same
snapshot/ownership boundary. Actual no-clobber links and deterministic failure
injection verify complete publication, competing creators, interruption and lost
acknowledgements without changing renderer or source state.
Both new formats also reject renderer exceptions, cooperative full workspace/model
changes between rendering and publication, and actual complete output above the
existing product quota. These checks retain original selected snapshot facts,
fixed safe diagnostics and confirmed publication truth.

```bash
uv run --locked --extra dev pytest tests/contract/test_report_export_formats_contract.py tests/e2e/test_html_junit_cli_exports.py -n 2 --no-cov
```
