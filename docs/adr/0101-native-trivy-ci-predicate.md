# ADR 0101: Native Trivy CI finding predicate

## Status

Implementation authorized by the integration coordinator on 2026-10-28.
Refs Task #75. Genuine native CI acceptance remains unrun until the required
pinned provider and isolated owned runtime execute this exact revision.

## Decision

Add the explicit `native-trivy` profile to `1337 ci scan`. Reuse the accepted
`ScanNativeImage` workflow, its bounded local material observer, original
VERSION/SCAN pair, six persisted acquisitions, canonical admission, and report
owners. This adds no scanner, score, severity order, network target, download,
database update, target registration, or execution permission.

The caller selects an existing workspace, workspace-relative archive and cache
directory, absolute trusted executable, absolute policy file, recorded scope,
executing owner, independent read-consent reference and SAFE image approval.
The profile requires the existing explicit severity/status conjunction, finite
match limit, completeness acknowledgement, and three distinct new JSON/SARIF/
JUnit destinations. Synthetic producer/material/source/logical-path options and
configuration approval are incompatible. Native-only policy/cache options are
incompatible with synthetic profiles. Synthetic profiles and their defaults
remain unchanged. The existing CI timeout ceiling remains sixty seconds.

## Original acceptance bridge

Persisted replay verifies recorded source facts but grants no current
authority. Add an Internal, nonserialized acceptance handle to the native summary
with a compatibility default of `None`. Issue it only for a completed, certain
original workflow. Caller construction and copied/unissued handles are refused
through an identity-bound issuer association. The handle binds the exact original
VERSION and SCAN objects and retains the original engine, grants, claims,
observer-issued proof, fresh context provider and authority clock through the
workflow's existing validation closure.

`Validate` invokes the existing `ValidateNativeImagePairFresh` mechanism. It
does not authorize, claim, bind, retry, observe or launch anything. Current
scope/policy, grant expiry, original persistent control identities and selected
material metadata remain the existing authority owner's decisions. The handle
never appears in `ToDict`, reports or saved evidence. It is usable only while
the original in-process workflow association survives; reopening receipts cannot
reconstruct it.

CI requires the handle before evaluating the predicate and after all report
exports. A late refusal retains actual scan/report facts and returns nonzero.
No fresh grant or new material observation is issued to prolong success.

## Finding and report proof

Require exact original captures, the six original owning evidence records,
successful replay, complete saved-model digest/revision and original native
candidate reconstruction. Every current inventory object, relationship,
observation and finding detection must have its exact source provenance in the
saved model. Current saved status/reason remain authoritative; all other finding
facts must equal the original candidate. Only these current detections enter
the predicate. Absent historical findings and unrelated retained findings remain
in the complete reports without entering this source selection.

The criterion result additionally accepts the existing native source identity
`native-scan:<64 lowercase hexadecimal characters>`, alongside the unchanged
`artifact-run:<32 lowercase hexadecimal characters>` identity. Result shape,
explicit predicate semantics, per-artifact truth and exit meanings remain
unchanged. Exit zero establishes only acknowledged criterion satisfaction;
`scan_completeness` remains `not-assessed`.

## Validation

Focused deterministic tests cover exact handle origin/capture binding, native
argument exclusions, original receipt and complete saved-source proof, current
triage, historical absence, failed/uncertain execution, snapshot mutation,
partial report publication and late authority refusal. Existing synthetic CI
regressions remain selected. Provider/observer doubles are explicitly labeled
and never count as genuine Trivy acceptance.

Required genuine acceptance should reuse the existing pinned Trivy 0.75.0,
official database pin, two inert owned Docker-save archives and no-egress owned
Linux runtime. It must exercise the assembled CI command and independently
inspect the saved model and all three actual report artifacts. Missing provider,
database, provisioning or isolation prerequisites must fail a required CI lane;
optional local skips are not acceptance. Workflow enrollment remains owned by
the integration coordinator.
