# Local intelligence commands

`1337 intel` is an experimental offline product interface. It imports one
explicit local CVE, CWE, KEV or EPSS document and retains original evidence,
normalized snapshot and terminal receipt in an existing workspace. It does not
fetch declared URLs, discover a latest source or automatically enrich findings.

The separate [selected EPSS gzip profile](INTELLIGENCE_EPSS_SELECTION.md) adds
`intel epss import|inspect` with explicit selected IDs and independent custody
references. Its receipts do not enter the legacy snapshot/apply path below.

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
verified selection for `inspect` or `apply`.

Both `inspect` and `apply` first select and read the snapshot and receipt through
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
`inspect --help` or `apply --help` for the action's required arguments.

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
