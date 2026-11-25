# Local intelligence commands

`1337 intel` is an experimental offline product interface. It imports one
explicit local CVE, CWE, KEV or EPSS document and retains original evidence,
normalized snapshot and terminal receipt in an existing workspace. It does not
fetch declared URLs, discover a latest source or automatically enrich findings.

The separate [selected EPSS gzip profile](INTELLIGENCE_EPSS_SELECTION.md) adds
`intel epss import|inspect` with explicit selected IDs and independent custody
references. Its receipts do not enter the legacy snapshot/apply path below.
The additive [pinned HTTPS profile](INTELLIGENCE_EPSS_HTTPS.md) uses the separate
`intel epss https fetch|inspect` namespace and original remote custody.
The separate [selected CVE HTTPS profile](INTELLIGENCE_CVE_HTTPS.md) exposes
`intel cve https fetch|inspect` for one explicitly pinned published 5.2 record.

Create a workspace first with `1337 workspace create`. Import requires all source
attribution to be supplied explicitly. For an owned synthetic EPSS fixture:

```bash
1337 intel import ./workspace ./owned-scores.csv \
  --feed first-epss-csv --catalog-version synthetic-1 --origin synthetic \
  --publisher 'Owned synthetic fixture' --source-url https://example.invalid/scores.csv \
  --license-name 'Apache-2.0 synthetic fixture' \
  --license-url https://example.invalid/LICENSE --scope scope:owned \
  --max-bytes 1048576 --json
```

Supported feed names are `cve-record-5`, `cwe-xml-7`, `cisa-kev-json` and
`first-epss-csv`. `--catalog-version` must match the selected parser's version
contract. `--origin` is `synthetic` or `external`; attribution is caller-declared
and does not authenticate a publisher. `--expected-sha256` optionally pins the
exact selected file bytes. The positive `--max-bytes` ceiling defaults to 16 MiB
and cannot exceed that bound. An oversized file produces a failure receipt and
at most the selected ceiling of retained original bytes. Receiver timestamps are
observed during import and cannot be supplied by the operator.

Keep the successful output's `snapshot_id` and `receipt_id`. Both are immutable
acquisition manifest identifiers of the form `sha256:<64 lowercase hex digits>`.
Select both explicitly to verify the original source and receipt:

```bash
1337 intel inspect ./workspace --snapshot sha256:SNAPSHOT_DIGEST \
  --receipt sha256:RECEIPT_DIGEST --json
```

Replace the placeholders with the complete reported digests. Inspection checks
the owning workspace, exact raw manifests/bytes and source reparse, as well as
the selected successful local receipt. It writes no state. Moving the whole
workspace preserves these identities; copying its artifacts to a different
workspace does not transfer ownership. Failed imports report their terminal
state and retained record identifiers; they do not provide a successfully
verified selection for `inspect`, `preview` or `apply`.

`inspect`, `preview` and `apply` first select and read the snapshot and receipt through
the existing byte-bounded store. Before explicitly retrieving the original raw
record with `Get` or invoking the SDK's original-source reparse, selection checks
the receipt's integer byte ceiling (1 through 16 MiB), finite receiver timeout
(0.05 through 60 seconds), optional expected SHA-256 pin and the snapshot's
declared original-reference size against that ceiling. These preliminary checks
do not replace the owning raw manifest, byte-integrity and exact reparse checks.

## Selected source details

Default inspection keeps its existing bounded terminal summary. Select one or
more exact CVE/CWE identifiers to inspect source assertions without dumping the
whole catalog:

```bash
1337 intel inspect ./workspace --snapshot sha256:SNAPSHOT_DIGEST \
  --receipt sha256:RECEIPT_DIGEST --identifier CVE-1900-9999 --json
```

Repeat `--identifier` for up to 64 unique identifiers. IDs are case-sensitive;
malformed, duplicate or excessive selections fail before source verification.
The complete selected detail document has a 1 MiB ceiling; excessive output
fails with `inspection-limit` rather than silently truncating records. No
identifier is inferred from a product, banner, description or another record.

Only selected inspection adds the Experimental `details` profile `1` to terminal
JSON. It retains the original snapshot reference, source/license/import
attribution once, requested and unmatched identifiers, and selected normalized
records. `target_applicability="not-evaluated"` and
`publisher_authentication="not-assessed"` remain explicit. Missing catalog
membership is not evidence of no vulnerability, exploitation or risk. Omit
`--json` for a source summary that explains each feed's meaning.

When at least one identifier matches, the text summary shows the verified
SHA-256 of the retained original source bytes, also available as
`source_sha256` in JSON. The `raw_id` identifies the retained evidence manifest.

For a matched EPSS record, the text summary shows the publisher's score
timestamp normalized to UTC alongside its probability and percentile. This
timestamp comes from the record's `effective_at` field.
For a matched KEV record, the text summary shows the catalog's remediation due
date alongside the required action. The date comes from the record's `due_date`
field.

For a selected CVE Record `5.2`/`5.2.0`, `cve_source_profiles` exposes the existing
independent inspection results without repeating snapshots:

- `applicability.containers` retains ordered CNA/ADP providers and source product
  declarations, including exact `affected`, `unaffected` and `unknown` statuses.
  These are source statements about versions, not a verdict about the target.
- `cvss2.assessments` retains source wrappers and asserted scores;
  `cvss2.base_calculations` separately links the existing exact base arithmetic
  through `assessment_index`, `algorithm` and integer `base_score_tenths`.
  A calculated score never overwrites or corrects the source's score.
- CVSS 3/4 source assessments remain separate in `records[].data.cvss`, retaining
  each version, vector, source base score and assessor. They are not combined.

Older supported CVE formats keep their ordinary assertions and report the extra
profiles as `unsupported-format`. A strict additional reader may report
`unsupported-content` without declarations when the source exceeds that reader's
supported structure; the independent other reader and verified base assertions
remain available. This does not declare the whole publisher document invalid.
Rejected CVEs expose no positive product or scoring assessments. An unmatched
CVE selection discloses no unrelated product/scoring profile.

Inspection writes no model state and grants no applicability review or execution
approval. It works after relocating the owning workspace and needs no network.

Preview a selected snapshot against an existing evidence-linked finding before
saving its candidate observation:

```bash
1337 intel preview ./workspace --snapshot sha256:SNAPSHOT_DIGEST \
  --receipt sha256:RECEIPT_DIGEST --finding object:FINDING_DIGEST \
  --identifier CVE-1900-9999 --identifier CWE-89 --expected-revision 3 \
  --as-of 2026-10-15T00:00:00Z --max-age-seconds 86400 \
  --scope scope:owned --run run:explicit-review --json
```

Preview verifies the original source/receipt, selected saved finding and expected
revision, then runs the same proposal owner as apply. Its `preview` profile lists
new candidate observations with exact source/evidence links, explicit unmatched
IDs, age and staleness. EPSS freshness uses its score timestamp; the other feeds
use source acquisition time. This read-only result keeps `model_commit` at
`not-attempted` and `model_revision` at the saved revision; `proposed_revision`
describes the unsaved proposal. A repeated unsaved preview is deterministic.
An identical already-saved interpretation reports `already_applied=true` and no
new observations. Excessive output fails without partial printing.

Preview accepts the same original local snapshot family as apply. It works with
retained sources after relocation and never refreshes a source. Its revision
check reserves no future write: apply verifies the revision again before saving.

Apply a selected snapshot only to an existing evidence-linked finding, with
explicit interpretation and model concurrency inputs:

```bash
1337 intel apply ./workspace --snapshot sha256:SNAPSHOT_DIGEST \
  --receipt sha256:RECEIPT_DIGEST --finding object:FINDING_DIGEST \
  --identifier CVE-1900-9999 --expected-revision 3 \
  --as-of 2026-10-15T00:00:00Z --max-age-seconds 86400 \
  --scope scope:owned --run run:explicit-review --json
```

Replace the identifiers, interpretation time and revision with actual selected
values. Repeat `--identifier` for additional exact identifiers, up to the existing
64-selection bound. `--as-of` needs a full timestamp with an explicit UTC offset
and cannot precede source acquisition. The freshness budget is explicit, from
zero to ten years in seconds. Stale and unmatched identifiers remain visible in
the saved observation; they do not become exploit applicability or reviewed
associations. Applying preserves finding severity, confidence, disposition and
original evidence. An identical interpretation replay is a no-op.

The same commands work in `1337 shell`, with complete explicit arguments. Shell
selection never supplies a workspace, finding, source or approval implicitly.
History retains only the `intel` namespace. Use `1337 intel import --help`,
`inspect --help`, `preview --help` or `apply --help` for the action's required arguments.

JSON mode prints one schema-v1 terminal document. Successful commands exit zero;
invalid setup exits two; failed acquisition, integrity or model storage exits
four; interruption exits 130. Output includes acquisition record IDs, source
digest/count and actual timestamps, and a confirmed model revision when saved.
It omits source bodies and filenames. A model save can finish before its
acknowledgement fails: `model_commit: unknown` means reopen the saved model before
retrying. A reported failure never implies that all evidence publication was
rolled back.

See [ADR 0069](adr/0069-explicit-local-intelligence-cli.md) and the
[acquisition contract](adr/0060-bounded-intelligence-snapshot-acquisition.md).
[ADR 0123](adr/0123-selected-intelligence-inspection.md) defines selected details
and their finite source/output boundaries.
[ADR 0149](adr/0149-read-only-finding-intelligence-preview.md) defines the unsaved
finding preview and its equality with the apply proposal.


## One combined preview and save from several originals

Experimental `intel preview-set|apply-set` exposes the existing multiple-snapshot
SDK operation. It accepts two to sixteen explicit original successful **local**
snapshot/receipt pairs from `intel import`. The separate selected EPSS gzip, CWE
ZIP and HTTPS families retain their own contracts and are not converted here.

After importing each original file with its explicit source/version/license
metadata, retain the returned independent snapshot and receipt manifest IDs.
Delete the caller files and copy the complete workspace if desired, then use:

```text
1337 intel preview-set /absolute/copied-workspace \
  --selection sha256:CVE_SNAPSHOT sha256:CVE_RECEIPT \
  --selection sha256:CWE_SNAPSHOT sha256:CWE_RECEIPT \
  --selection sha256:KEV_SNAPSHOT sha256:KEV_RECEIPT \
  --selection sha256:EPSS_SNAPSHOT sha256:EPSS_RECEIPT \
  --finding object:EXISTING_FINDING \
  --identifier CVE-1900-9999 --identifier CWE-89 \
  --expected-revision 3 --as-of 2026-11-25T13:00:00Z \
  --max-age-seconds 86400 --scope scope:owned --run run:explicit-review --json
```

Replace every placeholder, synthetic identifier, revision and time with your
actual independent selections. Each root is a full lowercase manifest identity.
Both snapshot roots and receipt roots must be unique. No source, association,
finding or interpretation input is inferred from another record or shell context.

Every pair passes the existing complete receipt/original-source verifier.
One unchanged `ApplyVerifiedEnrichment` call then constructs one candidate
observation, with original source/license/time/evidence references, canonical
URLs, stale flags and unmatched IDs. Source CVSS assessments remain attributed;
KEV membership is not target exploitation, CWE is not verified applicability,
and EPSS freshness still uses its score clock rather than acquisition time.
All associations remain `candidate` with `review: null`. Finding severity,
confidence, remediation and operator disposition are preserved.

The distinct schema-one terminal profile `local-intelligence-set-cli-v1` contains
`selections` (verified original IDs, feed/catalog, raw SHA/length and count) and
the existing version-one `preview` shape (complete new observations/content
references, `proposed_revision` and `already_applied`). Selection metadata follows
caller pair order; SDK assertions follow canonical snapshot content-reference
order. Permuting the same input pairs preserves the candidate observation.
Repeated unsaved preview with the same inputs returns identical output and
performs no write or interpretation-clock refresh.

To save that candidate, replace `preview-set` with `apply-set` and repeat all
pins and interpretation inputs. Apply reopens/verifies again and calls the
existing CAS **once**, rather than saving each source independently. Preview
reserves no revision and grants no approval. A changed revision refuses the
whole set. Exact already-saved replay is idempotent, including after later triage.

### Whole-set limits and refusal

Canonical owning manifests first establish total snapshot payload <=16 MiB and
receipt payload <=512 KiB, before any selected body read. Receipts individually
retain their 32 KiB limit. Bounded snapshot decoding then establishes total
original raw bytes <=16 MiB **before any original reparse**. Totals count each
selected root's declared bytes, without silently deduplicating shared content.
This preflight does not replace original verification.

The existing SDK allows at most 64 requested unique IDs and separately at most
64 **matched source assertions** across all selected snapshots. One ID matched
in CVE, KEV and EPSS contributes three assertions. The existing 64 KiB model
attribute cap also applies: a count-admitted complete observation may still
exceed its byte bound and is refused without truncation. Sixty-four is an upper
count ceiling, not guaranteed capacity. All original parser/source/model bounds
remain unchanged. Preview is <=1 MiB; the whole ASCII-safe response is <=2 MiB.
Complete output is checked before apply can save.

A missing/corrupt/foreign source, mismatched receipt at any position, chronology,
limit or revision refusal exposes neither partial `selections` nor `preview`
and saves no valid prefix. Generic diagnostics exclude rejected arguments,
filenames and exception text. Source strings are JSON escaped, including human
output. One terminal write is checked and is never retried.

Preview reports `model_commit: not-attempted` and the read saved revision.
Successful apply reports the confirmed returned revision. Both report
`evidence_commit: not-attempted`. Invalid selection exits `2`, verification/limit/
save/output refusal `4`, interruption `130` and complete success `0`.

A save can commit before its reply is lost: `model_commit: unknown` and unknown
`model_revision` claim no rollback. Reopen the model, select its actual current
revision and deliberately replay the same interpretation through the existing
idempotent owner. Known CAS conflict/busy ownership reports `not-committed`.
A late output failure preserves an already confirmed save acknowledgement.

This operation adds no acquisition, live provider, automatic matching, refresh,
applicability verdict, risk policy or Core/receipt format. Its source-shaped
synthetic acceptance fixtures prove supported formats and original-byte custody,
not authentic publisher data or signature verification.
See [ADR 0159](adr/0159-combined-local-intelligence-enrichment.md).
