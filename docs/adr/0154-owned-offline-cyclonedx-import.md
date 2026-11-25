# ADR 0154: Owned offline CycloneDX inventory import

## Status

Accepted bounded owner-authorized M4 Task #377 implementation decision.

## Context

ADR 0040 already accepts verified CycloneDX 1.6 inventory with an explicit
config/manifest image binding. The operator importer exposes only the SPDX graph
profile. ADR 0082 deliberately refuses arbitrary SDK raw-only evidence as
original product replay: it contains no product image/run/read custody.
Workspace references cannot manufacture that missing historical operation.

## Decision

Add Experimental `sbom import cyclonedx WORKSPACE` as a direct application of
the existing SPDX operator input and persistence flow to the unchanged
`ApplyVerifiedCycloneDx` SDK. Original file mode requires `--file`, actor and
read-consent descriptions, source ID/version, optional declared provider version,
and a mandatory lowercase `--expected-sha256` for the exact source bytes. Image
digest/kind, existing offline scope, run and both saved revision bases remain
explicit. Validate the byte-pin grammar and all metadata before source reads;
verify the complete byte pin before evidence publication. Retain the established
four-MiB, physical file, descriptor ownership and alias checks.

The actual successful operator file operation creates its own
`sbom-import-source` fact with profile `cyclonedx` and the same original-read
description fields as SPDX. Original source/version/provider/read clocks and the
operator's image/run mapping stay distinct. The SDK validates only its existing
finite CycloneDX 1.6 inventory; no broad format, layer, license-compliance or
vulnerability interpretation is added.

Retained mode accepts only `--evidence` naming that original product acquisition.
Its exact profile, image digest/kind, run, scope, original source and read
descriptions must agree before selected raw reads. New source/read metadata or a
replacement expected hash is forbidden. Equal bytes, workspace reference lists
or independently normalized SDK objects do not replace a genuine original
product custody fact. Existing SDK raw-only semantics and SPDX admission remain
unchanged. Exact known original replay is a no-op after relocation and needs no
external source file or acquisition clock.

## Persistence and boundaries

Reuse the existing in-memory model transition and original-custody observation
within one revision, then the existing model CAS and independent workspace CAS.
Check both expected revisions, saved bases and scope between phases and before
success; retain previous model/evidence and operator triage. Each acquisition,
model and workspace acknowledgement remains independent. Lost responses remain
unknown, later failure preserves earlier durable state, and no cross-store atomic
transaction or rollback is claimed. Exit and fixed diagnostics follow ADR 0082.

No scanner, engine, network, archive extraction, layer attribution, license policy,
compliance verdict, new persistent model schema or public SDK is introduced.
The original `ApplyVerifiedCycloneDx` and all prior accepted SPDX calls remain
unchanged. The broader #377 task stays open.

Focused verification covers both image kinds, actual file custody, explicit hash
admission/mismatch, SDK raw-only refusal despite workspace references and existing
SDK inventory, exact closed replay, source substitution, finite-format failures,
independent lost acknowledgements, relocation and actual installed import/view.
