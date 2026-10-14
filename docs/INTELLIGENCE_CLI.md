# Local intelligence commands

`1337 intel` is an experimental offline product interface. It imports one
explicit local CVE, CWE, KEV or EPSS document and retains original evidence,
normalized snapshot and terminal receipt in an existing workspace. It does not
fetch declared URLs, discover a latest source or automatically enrich findings.

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
