# ADR 0068: Accepted synthetic configuration evidence workflow

## Status

Accepted implementation decision — 2026-10-14. Advances #158; native configuration
acceptance remains separate.

## Decision

Use the registered SCAN-only five-case configuration family through the existing
artifact policy and executor. Preserve original stdout, stderr, detached original
request/stage/receipt and the exact selected source as immutable evidence. A
separate read-only verifier checks owning manifests, bytes, receipt, original
factory grammar and provenance. Historical verification requires no original
physical paths and supplies no current authorization or model application.

Live application additionally requires the exact typed original run and fresh
canonical SDK acceptance. Normalize only the closed reviewed wire: every selected
file is explicitly processed, known checks retain exact source line/document/
selector coordinates and high severity. Private source text and arbitrary output
extensions remain raw evidence. No Dockerfile build, Kubernetes workload, image
reference resolution or native scanner claim is inferred.

Configuration asset keys are `synthetic:configuration:<input-manifest-sha>:<path>`.
They are separate from native and synthetic image keys. Findings use existing
subject/check/location fingerprints. Existing colliding foreign assets/findings
are refused atomically; re-detection preserves operator triage. Deterministic
rule classifications are synthetic configuration categories, not invented CWE or
standards mappings.

The job runs actual prepare, grant, execute and fresh acceptance, then verifies
canonical evidence and saves one model transition with optimistic revision
checking. Workspace reference persistence precedes the model-delta event. Failure
and cancellation retain acquired evidence, without a successful model delta.
Existing report interfaces project the exact saved state as JSON or SARIF;
requested export failure remains distinct from completed scan facts.

## Boundaries

This adds no CLI, grant issuer, policy relaxation, native profile, arbitrary source
parser or schema change. Zero synthetic findings retains `not-assessed` scan
completeness. Source files are evidence and are not included in normalized state
or reports. The whole #158 task remains open for native acceptance and other
required consumers.
