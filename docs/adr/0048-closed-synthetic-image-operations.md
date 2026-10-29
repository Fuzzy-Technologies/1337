# ADR 0048: Closed synthetic image VERSION and SCAN operations

## Status

Accepted — 2026-10-13. Task #142; related work #138, #140, #141 and #278.
The accepted Task #278 foundation now has a closed operation-aware SDK extension
for the reviewed synthetic image family, with schema-2 execution metadata and
strict original schema-1 replay. Its initial lifecycle producer remains SCAN-only.
Importer/workflow acceptance and genuine native scanner capability remain
separate; this SDK change authorizes no native execution.

## Context

[ADR 0045](0045-bounded-local-image-scan-workflow.md) requires independent observed
version evidence before image interpretation. The reviewed richer image worker
already supports a closed version wire, but the initial artifact factory emits
only image/configuration requests. A declared stage version or image JSON cannot
substitute for executing that version request.

The existing native image importer intentionally accepts version evidence with
no scan invocation or execution. An actual governed synthetic probe has its own
invocation, terminal result and receipt. Removing those facts to fit the native
importer would lose provenance and weaken its accepted source boundary.

## Decision

After the first accepted Task #278 foundation, extend its closed factory with
`ArtifactOperation.VERSION = "version"` and `ArtifactOperation.SCAN = "scan"`.
New requests default to SCAN; VERSION is available only for the reviewed richer
image family under `synthetic.image-archive-offline.v1`, provider
`synthetic.trivy`, SAFE capability `image.archive-vulnerabilities`.

The source-owned family is `owned-synthetic-image-wire-v1`. Its producer SHA256 is
`afb5b935f151fb9780feee28eda0fbf13ddc6d721e6f7cc55e753aa32e4cfa53`.
Its exact four-field material policy and argv are specified in
[the operation contract](../SYNTHETIC_IMAGE_OPERATIONS_DESIGN.md). Family selection
is derived from the closed profile/producer catalog and verified bytes. Callers
cannot register hashes, scripts, interpreters, families, policies or flags.
The lifecycle producer retains its current policy and SCAN ordering; admitting
the richer hash into a generic allowlist is insufficient.

VERSION runs with a fixed 3-second execution deadline and 16-KiB limits for each
raw stream. SCAN uses the richer worker's exact archive argv, memory cache,
1–60-second execution deadline, 4-MiB stdout and 1-MiB stderr ceilings. Each
operation uses trusted current CPython with `-I -S` and a pinned staged worker.
The scanner, input and material are immutable selected snapshots; cwd/home/cache
and temporary paths belong to that operation's fresh scratch partition.

VERSION and SCAN require separate fresh physical stages, stage leases, grants,
run identifiers, launch markers, actual raw results and acceptance receipts.
The physical marker and receipt bind the same original run and grant; a different
grant identifier or chronology cannot reuse a previous physical execution.
Their input/scanner/material content manifests, provider/profile/family,
selected executable identity, workspace and owner agree exactly. Stage roots,
physical staged-copy identities, cwd/cache paths and invocation digests differ
by design and are independently verified. Neither run reuses the other stage,
scratch, request, grant or receipt.

Operation and derived producer family become mandatory request/plan bindings,
included in the canonical intent and grant envelope digests. Operation-aware
execution metadata uses schema 2. Selected-byte manifest schema remains 1.
The immutable `ArtifactVersionProof` retains the actual original VERSION
outcome/request/stage and its exact observed successful JSON. Richer SCAN requires
this original prerequisite before planning or issuance. Its request and plan also
bind `version_run_id`, `version_grant_id` and `version_prerequisite_sha256`, with
explicit null values only for VERSION and lifecycle SCAN. The prerequisite digest
commits original VERSION metadata and detached prepared/stage payloads; another
valid same-material VERSION cannot be substituted into an existing SCAN grant.
This implements the stronger prerequisite decision from the proposed import
design alongside this SDK slice rather than implying earlier runtime support.
The original schema-1 field shape and hashing remain explicit for read-only
legacy SCAN replay. Adding fields to a current dataclass must not change the
canonical digest used to verify saved schema-1 intent or authorization.
Legacy bytes never become a schema-2 grant, inferred VERSION or relabelled source.

The consumer retains six distinct evidence roles: `provider-version`,
`provider-version-stderr`, `stdout`, `stderr`, `artifact-version-receipt` and
`artifact-scan-receipt`. Both version streams keep the actual VERSION invocation
digest, execution and observed collection window. The scan streams retain their
own actual SCAN facts. Each receipt role captures original SDK metadata plus the
exact detached prepared and stage payloads, whose hashes match the original
grant. Existing evidence schema/store remain unchanged; selected-input/scanner/
material acquisitions remain separate from this six-role interpretation bundle.

A future explicit `ApplyVerifiedSyntheticTrivyImages` boundary verifies both
canonical outcomes and record bundles, then freshly validates both original runs
against current authority and material before one atomic model proposal. VERSION
must succeed and be accepted before SCAN authorization. New model acceptance
also requires both grants to remain valid after SCAN. Refusal retains the actual
raw results and previous canonical model without rewriting process execution.

The synthetic candidate graph uses the fixed prefix
`synthetic.trivy:owned-synthetic-image-wire-v1:` for every config/manifest image,
package, OS, layer and license natural key, and
`synthetic.supply-chain.vulnerability` for Finding checks. All relation,
observation and Finding references, including `image_reference` attributes, stay
within that family. Entire colliding native objects, provenance and triage remain
unchanged. Hints never promote a fixture identity to a native one.

The native `ApplyVerifiedTrivyImages` signature, exact `native.trivy` guard,
three-role evidence contract and no-execution version check remain unchanged.
The synthetic path independently verifies execution-bearing version evidence;
it never strips facts or passes relabelled evidence through the native guard.
Historical verification is a separate read-only path over original saved facts
and records. It neither calls a live Apply boundary nor revives a grant, inspects
a relocated stage as current authority, or launches either operation.

## Consequences and implementation order

1. Accept the initial Task #278 foundation without adding this moving operation
   contract to its current source freeze.
2. Review the closed family/policy dispatcher, operation-aware schema-2 binding
   and strict legacy schema-1 verification under the artifact SDK owner.
3. Implement and independently review the image owner's separate synthetic
   evidence/import boundary, retaining native behavior and full collision tests.
4. Assemble the two operations, durable model/workspace saves and existing report
   exporters under the image workflow owner; publish a delta only after save.

The current SDK slice delivers step 2 and preserves the unchanged reviewed worker
and independent oracle. Actual owned VERSION/SCAN process tests exercise exact
wire/resource limits, original prerequisite binding, fresh pair acceptance, raw
failure/refusal retention and strict schema-specific replay. Steps 3 and 4 remain
separate consumer/workflow acceptance. Native profile IDs remain metadata-only
and cannot receive VERSION or SCAN grants. Genuine
Trivy compatibility, database freshness, detection accuracy, publisher or
principal authentication and OS CPU/memory/network/write isolation are not proved.
Task #142 remains open. No installation, download or PyPI work is included.

## References

- [Concrete synthetic image operation contract](../SYNTHETIC_IMAGE_OPERATIONS_DESIGN.md)
- [Reviewed image wire fixtures](../../tests/fixtures/image_scan/README.md)
- [Verified image/package normalization](0040-verified-image-package-normalization.md)
- [Evidence-linked report projections](0039-evidence-linked-report-projections.md)
- Task #278 / ADR 0044: future accepted artifact foundation prerequisite
