# Offline report export

The current development candidate exposes the accepted report SDK through one
Experimental product command, defined by [ADR 0049](adr/0049-offline-product-report-export.md):

```bash
uv run --locked 1337 report export owned-workspace --format json --output report.json --json
uv run --locked 1337 report export owned-workspace --format sarif --output report.sarif.json
```

The selected workspace must already exist and contain a saved canonical model.
The output parent must already exist and the selected file must be absent, outside
the source workspace. `--format` and `--output` are required. Use `report export
<workspace> --format <json|sarif> --output <new-file>` inside the shell; the shell
uses the same foreground consumer and retains only `report` in history/replay.
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
adapter preserves the existing active/closed finding semantics. Both keep failed
source outcomes and operator triage. Reports include links/metadata, never acquired
raw bytes or local workspace paths. Metadata must already satisfy the model's
non-secret input contract; this reader does not discover or redact secrets.
See [report semantics](REPORTING.md) for the distinction between byte integrity,
source claims and finding interpretations.

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
HTML/JUnit product commands, inferred reference context, raw evidence bundles,
concurrent TUI, scanner enrichment and release acceptance remain separate work.
Task #40 remains open. `fuzzy1337.report_commands`, including its house-style
helpers, is Internal CLI implementation; this adds no authoritative storage API.

## Verification

```bash
uv run --locked python -m pytest -q --no-cov \
  tests/unit/test_report_commands.py tests/integration/test_report_export.py
```

Tests use real owned stores and deny process/network operations on product paths.
They cover triage/failed acquisitions, corrupt/foreign/missing input, quotas before
both raw-read paths, relocation, changed snapshots, links, output races, safe
diagnostics, interrupted cleanup and complete post-publication failure truth.
