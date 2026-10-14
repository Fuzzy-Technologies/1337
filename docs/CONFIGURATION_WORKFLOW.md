# Synthetic configuration evidence workflow

`RunSyntheticConfigurationScan` is an Experimental SDK workflow for the registered
closed synthetic Dockerfile/Kubernetes family. It supports the five reviewed
owned source specimens and fixed worker from ADR 0059. Native profiles and arbitrary
Dockerfile/YAML scanning remain unavailable.

Initialize a canonical workspace/model and store explicit current ARTIFACT
scope authorization for the exact selected input manifest. Supply a
`ConfigurationScanSelection` with the synthetic profile, logical file name,
absolute source/runtime/reviewed-worker/policy paths and `ArtifactReadConsent`.
Call `RunSyntheticConfigurationScan(root, scope_id, owner_reference, selection,
approve_safe_configuration=True)`. The owner must match the recorded current
scope authority. Explicit SAFE opt-in supplies a bounded operator policy; it
cannot grant missing scope consent or admit unknown bytes.

The actual job snapshots the input, creates the original governed request and
matching grant, runs the unchanged worker and preserves four acquisitions:
original stdout, stderr, source bytes and detached request/stage/receipt. It verifies
fresh current authority, exact processed source identity and source coordinates,
then saves canonical configuration ASSET and Finding objects with optimistic
revision checking. Workspace references are saved before a model-delta event.

Configuration keys bind the whole input manifest and logical path within
`synthetic:configuration:`. Existing native/image identities remain separate.
Known check IDs and line/document/selector coordinates form deterministic Finding
fingerprints. Re-detection preserves operator triage; missing findings do not
resolve older detections. Source snippets, hints, URLs and private comments remain
raw evidence. No runtime/image/workload relationship is invented.

`VerifySyntheticConfigurationReplay(records, root)` verifies original owning
manifests, bytes, provenance and receipt without original physical stage paths.
It survives relocation and retains original successful or refused execution facts.
Replay grants no launch, renewal or model authority. New proposals use
`ApplyVerifiedSyntheticConfiguration` with the exact typed original capture and
fresh canonical acceptance against current scope/material/lease.

Optional `report_format="json"` or `"sarif"` and an explicit new `report_output`
use existing report verification/serialization/publication contracts. The report
projects the actually saved snapshot. Export failure remains separate from the
completed job. `ConfigurationScanSummary.ToDict()` includes actual job/operation/
model facts and `scan_completeness="not-assessed"`; zero Findings is not a clean
scan or native compatibility statement. Exit values are 0 for completed scan and
requested export, 3 for authorization refusal, 4 for other failure and 130 for
cancellation/interruption.

Failure and cancellation retain acquired raw facts. Stale grants, changed source,
revoked/expired consent, foreign records, partial wire, output overflow or store
conflicts cannot publish a successful model delta. Model and workspace are distinct
existing stores: if model save succeeds and subsequent workspace save fails, the
summary honestly reports storage failure and the actual committed model revision.
There is no claim of a transaction spanning both stores.

## Functional evidence

The integration suite executes the actual registered worker through the production
SDK and job interface on all five unchanged independent cases, checking saved/reopened
Findings and exact source coordinates in JSON and SARIF. It also checks original
record provenance substitution, source/factory tampering, relocated read-only
replay, exact-replay deduplication, triage preservation, family collision refusal,
current-authority refusal, actual output overflow, cancellation and storage conflict.
Unit tests use explicitly declared process doubles and establish consumer/control
behavior only. They are separate from actual scanner/job functional evidence.

```bash
uv run --locked --extra dev pytest tests/unit/test_configuration_workflow.py tests/unit/test_configuration_sdk.py -n 2 --no-cov
uv run --locked --extra dev pytest tests/integration/test_configuration_workflow.py tests/integration/test_configuration_execution.py -n 2 --no-cov
```
