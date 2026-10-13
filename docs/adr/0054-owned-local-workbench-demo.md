# ADR 0054: Owned local Workbench demo

- Status: Accepted
- Date: 2026-10-13
- Decision owners: Fuzzy Technologies
- Related work: #40

## Context

The accepted Quick Scan and offline export interfaces are independently usable,
but a reproducible first Workbench experience still requires manual target,
workspace, consent, lifecycle and output setup. A bounded local composition can
demonstrate the current product without waiting for the broader attack-path-mini
showcase or silently inventing missing scanner capabilities.

## Decision

Add an Experimental `1337 demo local <new-output-root>` command. Without the
explicit `--approve-safe-http` switch it displays a fixed plan, returns denial
status 3 and performs no filesystem mutation, server startup or network work.
The switch authorizes only the command-owned synthetic localhost service and
native SAFE endpoint discovery. It records fixed non-secret operator/consent
references with a short validity window through the ordinary scope command; it
does not supply external-target, scanner-installation or higher-impact approval.

An approved run requires a new output directory beneath an existing physical
parent. Existing roots, symlinks/reparse points, traversal and control-bearing
paths reject before target startup. The command owns a service bound exclusively
to `127.0.0.1` on an operating-system-selected ephemeral port. It supplies three
exact HTTP URLs: `/`, `/health` and `/redirect`. Redirect targets and unselected
routes are never followed. Startup retains the numeric bind identity without
consulting reverse DNS. Startup, listening identity and teardown belong to
the command. Teardown is attempted after every success, failure and interruption;
a failed teardown can never be reported as success.

Use the existing product workspace/scope/scan commands and report export command.
The ordinary governed executor, current scope/consent, explicit capability
approval, jobs, raw evidence admission, model normalization and persistence remain
authoritative. The demo never writes Findings, model objects, connectivity edges,
scope snapshots or acquisition records directly. Actual ordered job events and
terminal summaries are retained, followed by an independent workspace reopen and
JSON/SARIF export from that saved workspace. Derived report files are siblings of
the workspace, using the report owner's no-clobber publication boundary.

Retain a concise evidence index that references the real owner-read acquisition
IDs, raw digests/sizes and material paths relative to the output root. Command
receipts, scan summary, target lifecycle receipt and final demo outcome are derived
artifacts, not another authoritative store. Existing report publication failures,
including a confirmed output published before a later failure, remain visible in
the demo outcome. Partial output and evidence remain available after failure or
cancellation. Re-running against an existing root must not alter any prior bytes.
Job/event history is saved as presentation evidence for this composition; it does
not introduce persistent job recovery or resumable scan semantics.

## Validation and limits

Unit tests cover pure plan/path/parser handling, exact composition and truthful
failure/publication reporting. Product E2E tests own actual localhost execution
and verify durable inventory, evidence hashes, unchanged saved-workspace report
projection, independent reopen, denial/no-clobber, failure and interruption
cleanup. A development-source subprocess run provides measured evidence, and a
clean built wheel must expose the same CLI where the build tools are available.

The output contains discovered endpoints and acquisition provenance, with zero
synthetic Findings. Native HTTP version 1 collects response status only; response
bodies, cookies, browser rendering, page traversal, vulnerabilities and attack
paths are outside this command. Nuclei, Trivy, Nmap, webengine page capture,
external targets and PyPI publication are separate work. This is one local
onboarding/demo slice of #40; the M4 attack-path-mini tasks #118–#125 remain open.

## References

- [Demo guide](../DEMO.md)
- [Quick Scan](../QUICK_SCAN.md)
- [Report export decision](0049-offline-product-report-export.md)
