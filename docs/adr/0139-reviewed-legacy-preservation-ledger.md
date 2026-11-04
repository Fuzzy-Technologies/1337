# ADR 0139: Reviewed legacy detector and scenario identities

Status: Accepted for this data-only development snapshot.

## Context

Existing native canary checks and modern QA foundations do not prove conservation
of historical detector semantics or the authored scanner test design. The reviewed
engine and QA inputs contain 19 behavior families and 60 numbered XSS rows, with
historical readiness annotations that must not become current passing results.

## Decision

Keep a strict, versioned development fixture containing original input/page/file
content identities, representative source line anchors, distinctive requirements,
owning issues, narrow existing code/test references and explicit runtime gaps.
Use original row numbers for stable XSS case IDs and hash exact extracted source
labels without publishing old code, payloads, credentials or target addresses.

Record each XSS row as planned and not run. Retain historical target/autotest-ready
flags separately; keep current test and evidence handles null. Preserve additional
mindmap groups and QA dimensions as requirements rather than fabricated executed
cases. A hash records source identity, not source correctness or executable recovery.

Validate conservation, referential integrity and current test symbols through
deterministic contract tests. Reuse existing functional-metrics projections with
no run objects to prove that historical designs render as not run without accuracy.
Check the readable family table against the same manifest.

## Consequences

This adds no product command, public API, runtime parser, execution authority or
detector. It does not import either historical archive or claim full issue #409
completion. Actual result-bundle comparison, every modern test mapping and complete
mindmap expansion remain separately reviewed continuations. Ordinary final shared
CI and independent review remain required before integration.
