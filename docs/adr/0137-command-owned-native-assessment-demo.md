# ADR 0137: Command-owned 1337Scope assessment demo

## Status

Accepted design — 2026-11-03, preparatory slice of #123 and #125.
The full canonical attack-path showcase remains separate.

## Decision

Add `1337 demo assessment <new-output-root> --approve-standard-http` as an
Experimental composition over existing workspace, consent, native scanning,
evidence, Finding and report interfaces. Keep `demo local` and its SAFE-only
approval semantics unchanged.

The command accepts no target URL. It owns two fixed loopback routes: an inert
Git HEAD response and a separate fixed 404 endpoint. Explicit exact-boolean
STANDARD approval is required before creating files, starting a target or making
contact. Without approval, print the finite two-request plan and refuse execution.
SAFE approval cannot authorize this action, and the STANDARD flag cannot alter
the existing local demo's policy.

For each endpoint, use the ordinary current consent/scope/policy check, actual
native plan and its separate exact confirmation intent. The native workflow
retains its existing one-GET, timeout, evidence and model contracts. Bind the
observed LOW Finding to the exposed endpoint, current successful provider job,
scope and original worker report. The distinct negative endpoint must add no
Finding and cannot mark the original Finding remediated.

Stop the owned target before reopening the workspace and exporting JSON, SARIF
and human-readable HTML. Reports describe the retained real result and the
limited negative control. Response-body retention, browser execution, Intel
applicability and attack-path results are not inferred from this demo.

## Failure and acceptance

Existing output and evidence must never be overwritten. Startup, policy,
execution, custody, persistence, report and teardown failures must remain
observable with truthful nonzero outcomes. Cleanup runs on unsuccessful paths;
successful partial artifacts cannot turn a failed demo into PASS.

Verify the actual installed CLI, exact real requests and per-endpoint
confirmations, original Finding/evidence joins, target shutdown before offline
reports, no-contact refusal, no-clobber and failure cleanup. Preserve existing
`demo local` regressions. This command does not close the broader canonical
showcase tasks or replace their independent oracle.
