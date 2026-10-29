# Synthetic configuration evidence workflow

`RunSyntheticConfigurationScan` is an Experimental SDK workflow for the registered
closed synthetic Dockerfile/Kubernetes family. It supports the five reviewed
owned source specimens and fixed worker from ADR 0059. Native profiles and arbitrary
Dockerfile/YAML scanning remain unavailable.
The Experimental product entry is `1337 scan config --profile synthetic`; CLI
and foreground shell directly reuse this workflow.

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

## Explicit CLI and foreground shell

Use an initialized workspace and approved current ARTIFACT scope for the exact
canonical selected input manifest. The existing `scope create --allow-artifact`
and `--exclude-artifact` options accept `manifest-sha256:<64 lowercase hex>`;
paths and source byte hashes cannot substitute for that whole manifest identity.
Scope registration alone retains unknown consent. Explicit `--grant-consent`,
owner, consent reference and validity bounds record authority separately from
selected-file read consent and SAFE execution opt-in.

Require `--type dockerfile` or `--type kubernetes` and the exact `--logical-path`
from the reviewed case. Source bytes, policy and the fixed worker must match one
of the five existing independent fixtures:

| Source type | Reviewed case                       | Logical path |
| ----------- | ----------------------------------- | ------------ |
| dockerfile  | dockerfile.root-user                | Dockerfile   |
| dockerfile  | dockerfile.non-root-user            | Dockerfile   |
| kubernetes  | kubernetes.privileged-container     | unsafe.yaml  |
| kubernetes  | kubernetes.non-privileged-container | safe.yaml    |
| kubernetes  | kubernetes.second-document          | multi.yaml   |

After authorizing selected-file reads, the operator can derive the exact target
using the existing canonical manifest API; this calculation grants no execution
authority:

```python
import hashlib
from fuzzy1337.artifact_inputs import ArtifactFile, ArtifactManifest, ArtifactProfile, ArtifactRole

payload = selected_source.read_bytes()
target = ArtifactManifest(
    ArtifactProfile.SYNTHETIC_DOCKERFILE,
    ArtifactRole.INPUT,
    (ArtifactFile("Dockerfile", len(payload), hashlib.sha256(payload).hexdigest()),),
).Target()
print(target.value)
```

Supply the complete explicit selection:

```bash
1337 scan config /absolute/owned-workspace \
  --profile synthetic --type dockerfile --logical-path Dockerfile \
  --source /absolute/selected/Dockerfile \
  --scope config-scope --owner owner:operator \
  --executable /absolute/current-trusted-cpython \
  --producer /absolute/1337/tests/fixtures/configuration_scan/producer.py \
  --material /absolute/selected/policy.json \
  --read-consent-reference consent:explicit-selected-files \
  --approve-safe-configuration --timeout 30 \
  --report-format sarif --report-output /absolute/new-config-report.sarif \
  --json
```

All selected physical paths must be absolute. The executable is the explicitly
selected current trusted CPython. No source, worker, runtime or material is
discovered, installed or automatically selected. Omitting the SAFE opt-in denies
process authorization; current owner/scope/material checks still apply when it
is supplied. Integer `--timeout` is from 1 through 60 seconds, default 30.
Report format and new destination must be supplied together. An invalid paired
destination remains a separate export failure after the actual successful scan.

`--json` emits one original versioned workflow summary. `--events-json` instead
emits canonical events followed by one terminal summary; these modes cannot be
combined. Human output uses `Synthetic Configuration Scan`. The same `scan config`
command runs in the foreground shell with identically explicit arguments and
namespace-only history. Exit values are 0 for completed scan/requested export,
2 for invalid setup, 3 for authority refusal, 4 for execution/storage/export
failure and 130 for cancellation. See
[ADR 0072](adr/0072-explicit-synthetic-configuration-cli.md).

## Functional evidence

The integration suite executes the actual registered worker through the production
SDK and job interface on all five unchanged independent cases, checking saved/reopened
Findings and exact source coordinates in JSON and SARIF. It also checks original
record provenance substitution, source/factory tampering, relocated read-only
replay, exact-replay deduplication, triage preservation, family collision refusal,
current-authority refusal, actual output overflow, cancellation and storage conflict.
Unit tests use explicitly declared process doubles and establish consumer/control
behavior only. They are separate from actual scanner/job functional evidence.
Product E2E tests also run actual CLI subprocesses for workspace/scope setup and
all five cases, reopen/verify saved evidence, replay original acceptance and
check independent source coordinates in saved reports. Real workflow-boundary
tests cover foreground shell, current denial, cancellation, CAS conflict, lost
model/workspace acknowledgements and no-clobber/confirmed publication failures.

```bash
uv run --locked --extra dev pytest tests/unit/test_configuration_workflow.py tests/unit/test_configuration_sdk.py -n 2 --no-cov
uv run --locked --extra dev pytest tests/integration/test_configuration_model.py tests/integration/test_configuration_execution.py -n 2 --no-cov
uv run --locked --extra dev pytest tests/unit/test_configuration_commands.py tests/contract/test_configuration_cli_contract.py tests/e2e/test_synthetic_configuration_cli.py -n 2 --no-cov
```
