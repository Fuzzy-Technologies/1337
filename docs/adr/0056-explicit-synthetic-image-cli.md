# ADR 0056: Explicit closed synthetic image CLI

## Status

Accepted bounded consumer decision — 2026-10-13. Task #142; assembled workflow
foundation #305 remains the sole execution, persistence and export owner.

## Decision

Expose the accepted closed workflow through Experimental
`1337 scan image <workspace> --profile synthetic`. The profile is mandatory and
admits only the existing reviewed `synthetic.trivy` family. Native Trivy execution,
registry or daemon inputs, arbitrary scripts, flags and implicit runtime discovery
remain outside this entry point.

The operator explicitly selects an existing workspace and current ARTIFACT scope,
owner, absolute archive, current trusted CPython, pinned reviewed worker, synthetic
material policy and selected-file read-consent record. `--approve-safe-image` is
an explicit SAFE capability opt-in; read consent and a supplied profile never
replace current scope authorization or the artifact SDK's fresh paired checks.
The CLI directly calls `RunSyntheticImageScan` without a second executor,
importer, grant path or model writer. Its integer `--timeout` retains the SDK's
one-through-sixty-second SCAN bounds and independent fixed VERSION limits.

Add explicit `--allow-artifact` and `--exclude-artifact` rules to the existing
`scope create` command. Their values are canonical
`manifest-sha256:<64 lowercase hex>` targets validated by the current scope model.
They perform no discovery or selected-file read. The artifact manifest digest
must be supplied by the operator; archive byte hashes, OCI identities and file
paths do not substitute for that manifest target. Existing explicit consent,
validity and finite rule-count checks remain unchanged.

`--json` emits the existing versioned synthetic workflow summary once.
`--events-json` emits unchanged ordered job events followed by one terminal
summary; the two presentation options are mutually exclusive. Human output names
the synthetic workflow. Global CLI and foreground shell retain their existing
scan dispatch and use this same consumer. Paired `--report-format <json|sarif>`
and `--report-output <new-file>` request existing exact-snapshot export. Parse
and selection validation reject incomplete or unsupported inputs without echoing
untrusted values. A paired but invalid report destination remains a separate
export failure after actual completed scan/model persistence.

Exit statuses retain the workflow contract: zero for completed scan/export,
two for invalid setup, three for authorization denial, four for scan/storage/export
failure and 130 for cancellation. Separate export failure preserves actual
completed scan/model facts and never overwrites an existing destination.

## Acceptance and limits

Contract tests cover required profile/selection/consent, generic diagnostic
redaction, manifest syntax, unknown consent and invalid SDK bounds. Product E2E
tests create workspace/scope through the CLI, run actual independent VERSION/SCAN
over reviewed owned fixtures, reopen committed evidence/model, export JSON/SARIF,
exercise no-findings inventory, current denial and no-clobber export failure, and
reuse the foreground shell dispatch.

Synthetic findings retain the accepted fixed family and never enter native state.
Every summary/report preserves `scan_completeness: not-assessed`. This consumer
does not claim genuine Trivy/database/detection acceptance, publisher or principal
authentication, OS isolation, installation, PyPI publication or Task #142 closure.
The reviewed fixture source and independent oracle are unchanged.
