# ADR 0049: Offline product report export

## Status

Proposed — 2026-10-13. Related acceptance: #40; report SDK: ADR 0039.
Root review of this design precedes consumer behavior changes.

## Decision

Expose the accepted report projection through one explicit product command:

```text
1337 report export <existing-workspace> --format <json|sarif> --output <new-file>
```

`--format` and `--output` are required. The foreground shell uses the same
command, registry and argument rules. An optional `--json` emits a small command
outcome, not report bytes. Shell history/empty-line replay retains only the
`report` namespace, following the workspace/scope/scan convention. There is no
scan, job, subprocess, network call, source synchronization or implicit workspace.

Open the explicitly selected workspace and model through `LocalWorkspaceStore`
and `LocalModelStore`. Open every scope named by workspace references, model
provenance or retained acquisitions through `LocalScopeStore`; missing, corrupt,
foreign or malformed context fails. Historical reporting requires valid owning
scope metadata, not current scan consent: revoked/expired consent never starts
new work or rewrites the original acquisition. Empty workspaces need no scope.

Verify all retained workspace raw references and acquisition manifests through
`LocalEvidenceStore`, including unused older acquisitions and their workspace
binding. A private consumer reader applies quotas before the owner's `Get`/`Read`
loads raw bytes; schema, hashing and path checks remain in the existing owner.
It introduces no new storage format or authoritative store.

Create `ReportSnapshot` from the exact saved model, verify its linked bytes using
`VerifyReportEvidence`, and call only `SerializeJson` or `SerializeSarif`.
Before publication reopen workspace/model and reject a changed revision/content;
the selected snapshot digest and revision remain explicit. No source/model/scope,
artifact, reference context, finding disposition or execution outcome is changed.

## Bounds and publication

The input document limits remain owned by the existing SDKs. The consumer adds:

| Boundary                         | Fixed initial limit |
| -------------------------------- | ------------------- |
| Retained acquisition manifests   | 1,024               |
| Unique linked/retained raw blobs | 1,024               |
| One raw blob                     | 32 MiB              |
| Total distinct raw blob bytes    | 128 MiB             |
| Referenced scopes                | 256                 |
| Complete serialized report       | 32 MiB              |

The output's physical parent must already exist and the selected filename must
be absent. Reject traversal, observed links/reparse points, non-directory parents
and output inside the source workspace. No overwrite, automatic directory creation
or raw-evidence copying is provided. This keeps the source workspace unchanged.

Serialize completely before publication. Write a private same-directory temporary
file, flush/fsync it, publish with an atomic no-clobber hard link, then remove only
the owned temporary file. Preserve a concurrent creator's existing destination.
POSIX additionally synchronizes the selected parent; other platforms retain file
synchronization and atomic publication. Unsupported filesystem hard-link support
fails explicitly. No fallback may expose a partial file or overwrite existing data.
A post-publication synchronization/cleanup error reports failure even when a
complete output already exists; it never removes or mislabels that output.
The operator must exclude hostile concurrent filesystem writers, as for the stores.

## Outcome and acceptance

Exit `0` means report export completed, regardless of findings or retained failed
executions. Exit `2` means invalid explicit configuration; exit `4` means integrity,
changed input, rendering/limit or publication failure. Diagnostics expose fixed
safe categories without exception text or rejected arguments. The JSON outcome
binds format, saved model revision/digest, serialized size/hash and explicit
`scan_completeness: not-assessed`; it contains no local workspace path or raw bytes.
Zero findings never means a clean scan. SARIF keeps the accepted active/closed
disposition and original provenance semantics. No finding threshold is introduced.

Tests use real owned stores and product CLI/shell interfaces. Cover malformed,
missing, corrupt and foreign scope/evidence, older unused acquisitions, triage,
empty/failed-source reports, relocation, exact schemas/digests, quotas, changed
inputs, atomic failures/concurrent creation and unchanged source bytes. Deny any
process/network operation in consumer tests; no browser or external target is used.
Static documentation/locales and the canonical locked full gate remain required.

This slice advances #40's machine-output path. Concurrent TUI, scanner enrichment,
onboarding/CI walkthroughs, package/release/PyPI delivery and full #40 acceptance
remain separate; #40 stays open. HTML/JUnit commands, context inference and raw
evidence bundles are outside this initial command.
