# Transfer one retained IOC acquisition

The Experimental offline IOC bundle transfers one successful original
acquisition. It contains its original TSV, acquisition receipt and derived
snapshot with their original manifests. Use only owned non-secret evidence:
the explicit file export includes unredacted tokens and declared source/license
locators. It sends nothing and does not modify the source workspace.

## Export explicitly selected originals

Keep the independent original `receipt_id` and `snapshot_id` returned by
`trace ioc import`. Select them explicitly and opt in to original-byte disclosure:

```bash
1337 trace ioc export-bundle /owned/case-workspace \
  --snapshot sha256:ORIGINAL_SNAPSHOT_MANIFEST_DIGEST \
  --receipt sha256:INDEPENDENT_ORIGINAL_RECEIPT_MANIFEST_DIGEST \
  --include-originals --output /owned/handoff/selected-ioc.json --json
```

Replace both placeholders with the complete original manifest IDs. The output
parent must already exist. The new output must be outside the selected workspace;
existing files, links, missing parents and concurrent creators are refused.
No original filename is rediscovered and no other workspace acquisition is
included. Unrelated damaged evidence does not replace the selected chain.

Retain the terminal `bundle_sha256` and `receipt_id` separately from the file.
`bundle_sha256` is the lowercase SHA-256 of the complete delivered JSON file;
it is distinct from the original TSV checksum and manifest IDs. The outcome also
reports the original `raw_id`, `snapshot_id`, size and candidate count. Identical
selected originals produce identical bundle bytes regardless of output filename.
Independent acquisitions retain their independent manifest identities.

## Verify without the source workspace

The recipient needs the file and the two independently retained pins:

```bash
1337 trace ioc verify-bundle /owned/handoff/selected-ioc.json \
  --receipt sha256:INDEPENDENT_ORIGINAL_RECEIPT_MANIFEST_DIGEST \
  --expected-sha256 COMPLETE_BUNDLE_SHA256 --json
```

Do not obtain trusted pins from the candidate file being verified. This action
checks the transfer digest, all three canonical manifests and their exact
payloads, common acquisition/parser provenance, original receipt/source/budget
bindings and original-byte reparse. It works after deleting the original
workspace and input TSV. Verification writes no files; its default summary prints
no original tokens.
The returned IDs identify the same original acquisition and derived snapshot.

Original timestamps/timezones, byte coordinates and duplicate occurrences remain
unchanged. Receiver acquisition clocks remain their original recorded values.
The result establishes local integrity against the separately retained pins.
It authenticates neither the publisher nor the investigator and makes no claim
about maliciousness, an incident, an attack path or legal admissibility.

## Read verified candidates without the workspace

To receive the already supported normalized candidate DTO through the installed
CLI, explicitly select machine disclosure after the same independent checks:

```bash
1337 trace ioc verify-bundle /owned/handoff/selected-ioc.json \
  --receipt sha256:INDEPENDENT_ORIGINAL_RECEIPT_MANIFEST_DIGEST \
  --expected-sha256 COMPLETE_BUNDLE_SHA256 --export-candidates --json
```

On success the existing verification result additionally contains
`candidate_export`, the unchanged schema-one `IocSnapshot.Serialize()` document
already available from workspace-bound `inspect --export-candidates --json`.
It retains source order and duplicate occurrences, original/normalized tokens,
byte coordinates, declared timestamps/timezones, source/license declarations,
parser identity/version, limits and original raw/receipt identities. The selected
snapshot manifest ID remains in the surrounding result. Acquisition clocks remain
in the original bundle manifests; verification introduces no new observation time.

The original TSV and workspace can both be absent. No import, extraction,
acquisition, workspace/model save or output file is needed. The option explicitly
discloses supplied tokens and declared source/license locators to stdout. Default
verification continues to emit its original summary. Text mode, `--match` and
`export-bundle --export-candidates` are refused before evidence access. A failed
pin, original-role or reparse check emits no `candidate_export` or partial list.
Keep both trusted pins separately from the file being checked.

This extends presentation of the accepted IOC profile. Broader log, artifact,
identity/process and Core investigation/timeline work remains open under #85.

## Format, bounds and refusal

The canonical JSON profile has `schema_version: 1`,
`family: ioc-evidence-bundle-v1`, `snapshot_id`, `receipt_id` and exactly three
`records` in source/receipt/snapshot order. Each record has `manifest_base64` and
`payload_base64` containing its original canonical manifest and exact original
payload. No archive extraction, path interpretation or new custody record occurs.

The complete ceiling is 4,992,042 bytes, derived from all existing owning manifest
and payload ceilings plus exact encoding overhead. Each manifest/payload retains
its own original smaller limit; the source also obeys its receipt's selected
budget. Oversize data is refused rather than truncated.

Exit `0` confirms export or detached verification, `2` invalid selections, `4`
integrity/source-change/publication refusal and `130` interruption. Diagnostics
never echo original text or physical filenames. A pre-publication failure leaves
the selected output absent and removes private staging. If a complete atomic
publication preceded a later acknowledgement failure, the nonzero result
truthfully reports `output_published: true` with the verified transfer pins.
Existing competing files remain untouched. A successful verification reports
`output_published: false`, `evidence_commit: not-attempted` and `core_mutation: none`.

See [ADR 0151](adr/0151-selected-ioc-evidence-bundle.md) and the
[original IOC command contract](IOC_ARTIFACT_CLI.md).
