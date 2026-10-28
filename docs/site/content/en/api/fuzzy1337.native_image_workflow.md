# Internal governed native image workflow

This assembled SDK offers `PlanNativeImageScan` and `ScanNativeImage` over explicit
local Trivy material. Material preview supplies the exact INPUT manifest/target
for operator registration; a scoped plan checks current authority without running
Trivy. Execution requires fresh native policy and separate SAFE workflow approval.

The workflow preserves original VERSION/SCAN receipts, one-use persistent claims,
job-owned acquisitions and current authority before canonical model/workspace CAS.
Failure summaries retain verified evidence and actual saved revisions, with a
separate export outcome. Historical reopen grants no new execution authority.

Completed certain workflows retain an optional Internal `NativeImageAcceptance`
association for same-process CI consumers. Its identity-bound issuer and exact
original capture objects preserve the original grant/claim/proof/context/clock
checks. Validation cannot issue another grant, reobserve material or replay an
execution. This handle is absent from `ToDict`, persisted evidence and reports;
its compatibility default is `None`.

Repeated caller cancellation waits for the one original cleanup task before the
public SDK settles. A cancelled cleanup task remains an unknown-cleanup failure;
it cannot supply an invented completion or replace an already committed revision.

See `docs/NATIVE_IMAGE_WORKFLOW.md`, `docs/NATIVE_IMAGE_AUTHORITY.md` and ADR 0093.
Genuine provider acceptance remains an explicit isolated CI requirement.

::: fuzzy1337.native_image_workflow
