# Import an existing saved SARIF report

The Experimental IMPORT-only bridge reads one caller-owned, non-sensitive SARIF
2.1.0 JSON file. It retains its exact original bytes and a product receipt, then
shows bounded source assertions. It runs no analyzer and creates no target,
canonical Finding, risk score or model/workspace update.
[ADR 0157](adr/0157-owned-saved-sarif-import.md) defines the finite profile.

The workspace and scope must already exist. Use an actual lowercase SHA-256 of
the saved report; actor/read-consent references are explicit non-secret
descriptions, not credentials or signatures.

```bash
1337 bridge sarif import ./workspace ./external.sarif \
  --scope owned --owner operator:owned --read-consent-reference consent:saved-report \
  --expected-sha256 ORIGINAL_HEX_SHA256 --json
```

Keep the returned `original_id`, `receipt_id` and independent original SHA.
Each ID is `sha256:` plus 64 lowercase hexadecimal digits. Copy or move the
complete workspace and delete the caller file; then verify/reparse the original:

```bash
1337 bridge sarif inspect ./copied-workspace \
  --original sha256:ORIGINAL_MANIFEST_DIGEST --receipt sha256:RECEIPT_MANIFEST_DIGEST \
  --expected-sha256 ORIGINAL_HEX_SHA256 --json
```

The same commands work through the foreground shell. Shell context supplies no
workspace, scope, file, receipt, pin or read authority, and history/replay retains
only `bridge`. `1337 bridge sarif import --help` and `inspect --help` read no
workspace and perform no tool-health check.

## Source facts and unknowns

The version-one `bridge-sarif-source-cli-v1` outcome returns `projection.runs`
in original order and every inline result in source order, including duplicates.
The handwritten external sample oracle is ESLint's `no-unused-vars`, declared
`error`, literal Windows file URI, line 1 and column 5. Tool version, column kind,
end position and omitted kind stay null; no value is borrowed from installation
or a default. Indices stay zero-based; line/column values stay one-based.

`rule_id` can be supplied by a same-driver descriptor index; `declared_rule_id`
preserves whether the source actually spelled it. `descriptor_id` and
`rule_index` keep the same-document relationship explicit. Duplicate descriptor
IDs do not permit a first-ID match. One additional hierarchical slash component
is retained as part of the source result's literal ID.

Physical locations keep `uri`, `uri_base_id`, `artifact_index` and original
line/column fields. `declared_uri` and `declared_uri_base_id` distinguish direct
source text from an in-document artifact-table join. No URI/path/base ID is
resolved or opened, including a local file that actually exists. Relative paths
never borrow the importing process's CWD. The producer's schema/help URLs are
not fetched.

`source_level`, `source_kind`, `baseline_state`, suppressions and declared
invocation success remain producer claims. Omitted source fields stay null.
Missing/null result sets remain unknown; an explicit empty array means only
that this source reported no entries. Neither is a clean-state or completeness
claim. Markdown and message IDs remain inert declarations; templates are not
expanded. Source snippets, contents, commands, fixes and code flows remain only
in the unchanged raw original.

This is consumed-field normalization, not full SARIF conformance checking.
The existing 1337 SARIF exporter remains outbound-only and is unchanged.
ToolAdapter executor authority and canonical Finding mappings are separate.

## Limits, acknowledgements and refusals

Original bytes are capped at 1 MiB; projected facts at 1 MiB; receipt at 64 KiB;
complete terminal output at 2 MiB after ASCII-safe escaping. Further fixed
tree/run/result/rule/artifact/location/string bounds are in ADR 0157. No caller
can increase them. Nonempty tool extensions, component-rule references and
external/inline property files are unsupported; the bridge never follows them.
Negative artifact indices refuse explicitly rather than indexing from the end.
Contradictory direct/indexed literal URI/base-ID pairs also refuse.

All pin/format/file checks precede immutable publication. Unsupported input leaves
no published original/receipt. Original and receipt publication are separate:
`original_commit` and `receipt_commit` each report `not-attempted`, `confirmed`
or `unknown`. A failed return can follow actual publication; it does not prove
rollback. A confirmed original with failed/unknown receipt is not successful
import custody. Correct/repeat the explicit file operation when a usable receipt
was never returned; do not pretend a raw record alone authorizes replay.

Successful inspection uses `ack_basis=verified-present`; it does not rewrite
lost historical acknowledgements. Source hash/size refer to the confirmed or
verified original, not an inferred remote source. `model_commit` and
`workspace_commit` remain `not-attempted`; `canonical_findings=not-created`.
Publisher authentication and scan completeness remain not assessed.

Exit 0 means help or complete verified custody, 2 invalid grammar/metadata, 4 a
source/integrity/parse/storage/presentation refusal, and 130 interruption.
A refused outcome contains no `projection`. Presentation failure can follow
confirmed original custody; actual handles/acknowledgements remain visible.
A short or failed caller-stream write raises after one attempt without retry.
Inspection changes no owning bytes, performs no current clock call, and needs no
external file. Original reports are not redacted: supply only authorized,
non-sensitive saved material.

## Standard and external sample

The field meanings come from
[OASIS SARIF 2.1.0 with Errata 01](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).
This profile preserves explicitly declared fields instead of computing SARIF
effective defaults or assigning contextual severity.

The integration fixture is the unmodified
[Microsoft SARIF tutorial ESLint sample](https://github.com/microsoft/sarif-tutorials/blob/819b0f62f47ecde9a8f24dfc387c41926f5edabe/samples/1-Introduction/simple-example.sarif).
Its upstream provenance, license text and attribution are retained beside the
fixture. No analyzer execution, source-code acquisition or remote integration
is needed to consume this file.
