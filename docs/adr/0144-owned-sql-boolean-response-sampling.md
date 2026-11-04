# ADR 0144: Owned SQL boolean response sampling

## Status

Experimental design — 2026-11-04, first slice of #410 and #411.

## Decision

Add `scan web --check sql-boolean-sample` with capability
`web.sql-boolean-sample`. The native workflow allows only explicit loopback
URLs from a closed read-only SQLite fixture. Every request is independently
planned, authorized and confirmed. A complete bounded HTTP 200 JSON response
produces its original worker record, media type, status, length and body digest.
Bodies are transient. A sample has `matched: null` and produces no Finding.

The target uses actual SQLite queries on non-secret fixture data. Its oracle
defines baseline, true and false responses for both the intentionally vulnerable
query and the parameterized control. Repeated baseline and control comparisons
are tested through the installed worker. Unexpected status, malformed
transport or invalid JSON leaves a failed job with original diagnostics.

A future SQL assessment must bind all samples to the same approved request
coordinate and current assessment, preserve partial execution, and recheck
authority before each target request. It must distinguish unstable baseline,
reflected input and unsupported responses from a genuine differential.

## Verification

Verify exact-plan refusal before contact, known rows and digests, real query
parameterization, no Finding from a single sample, and independent broken
target controls. Fixtures and samples establish only this finite profile.
