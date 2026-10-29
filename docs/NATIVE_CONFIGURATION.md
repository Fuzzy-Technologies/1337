# Native configuration scans

The native configuration SDK consumes one explicitly selected Dockerfile or
already-rendered Kubernetes `.yaml`/`.yml` file. The selected UTF-8 source is
limited to 4096 bytes. The Linux x86_64 provider is the checksum-pinned Trivy
0.75.0 executable used by the independent native compatibility oracle.

The source is a general selected file, not a specimen catalog member. Its logical
name must be `Dockerfile` for Dockerfile scanning, or a portable flat `.yaml` or
`.yml` name for Kubernetes. Provider configuration, ignore files, charts, values
and Kustomize control names are reserved. Render manifests before selecting them;
1337 supplies no Helm, Kustomize, template or YAML renderer. Native image scanning
and synthetic configuration scanning have separate authority and evidence.

## Select, preview and authorize

`NativeConfigurationSelection` records the native profile, logical name, absolute
source and executable paths, and explicit selected-read consent. Construction
performs no reads. `PlanNativeConfigurationScan` actually snapshots and verifies
those selected bytes through the installed bounded material helper. An unscoped
preview returns the exact manifest-derived ARTIFACT target for independent scope
registration. A scoped plan also checks current scope and operator policy, while
remaining descriptive. Neither planning mode executes Trivy or grants permission.

The existing workspace/model must already be initialized. Register the exact
previewed target and record independent scope consent through the ordinary scope
interfaces. Supply an explicit policy permission for
`config.dockerfile-misconfigurations` or `config.kubernetes-misconfigurations`,
adapter `native.trivy`, at SAFE impact. Selected-read consent, recorded target
consent, operator permission and `approve_safe_configuration=True` are separate
requirements. A preview, executable checksum or copied receipt supplies none of
the missing authority.

```python
from fuzzy1337.artifact_inputs import ArtifactProfile, ArtifactReadConsent
from fuzzy1337.native_configuration import NativeConfigurationSelection
from fuzzy1337.native_configuration_workflow import (
    PlanNativeConfigurationScan,
    ScanNativeConfiguration,
)

selection = NativeConfigurationSelection(
    ArtifactProfile.DOCKERFILE,
    "Dockerfile",
    selected_source,
    selected_trivy,
    ArtifactReadConsent(owner, "read:explicit-owned-configuration"),
)
preview = await PlanNativeConfigurationScan(workspace, owner, selection)
# Independently register preview.Target and record scope consent before scanning.
summary = await ScanNativeConfiguration(
    workspace,
    scope_id,
    owner,
    selection,
    current_operator_policy,
    approve_safe_configuration=True,
)
```

The CLI uses the same workflow and requires a selected strict operator policy:

```bash
1337 scan config /absolute/workspace --profile native --type dockerfile \
  --logical-path Dockerfile --source /absolute/owned/Dockerfile \
  --executable /absolute/reviewed/trivy --owner owner:example \
  --read-consent-reference read:explicit-owned-configuration --plan --json

1337 scan config /absolute/workspace --profile native --type dockerfile \
  --logical-path Dockerfile --source /absolute/owned/Dockerfile \
  --executable /absolute/reviewed/trivy --owner owner:example \
  --read-consent-reference read:explicit-owned-configuration \
  --scope approved-config --policy /absolute/operator-policy.json \
  --approve-safe-configuration --json
```

Use `--type kubernetes` with the selected rendered manifest name for Kubernetes.
`--timeout` bounds SCAN from one through sixty seconds. Optional
`--report-format json|sarif` and `--report-output` export the acknowledged saved
snapshot. A report publication failure remains distinct from a completed scan.

## Original provider and model evidence

Every scan executes an original governed VERSION followed by a separately granted
SCAN. VERSION starts with an unknown observed version. SCAN requires the exact
original accepted VERSION association from the same engine, owner, stage and pair.
Persistent exclusive claims prevent reusing an operation or material observation.
Both operations use fresh private scratch, controlled environment, bounded
streams, Linux descendant ownership and exact current authority checks. Three
installed material observations share one 45-second ledger and nine-second
finalization reserve; provider process deadlines have separate explicit allowances.

The workflow retains seven immutable original evidence roles: VERSION stdout,
stderr and receipt; SCAN stdout, stderr and receipt; and exact selected source.
SCAN stdout is the complete original provider JSON report. The receipt binds the
original fixed recipe, grant, full request, stream/event identities, terminal
process facts and confirmed cleanup. Unknown terminal custody retains original
private controls and staged material and cannot save model success.

Acceptance requires one positively processed selected native file and original
positive embedded-library/check loader diagnostics. A successful exit or empty
finding list alone is insufficient. All original native rows remain in evidence.
Failed rules become canonical Findings using lowercase namespaced machine IDs,
for example `configuration.native.ds-0002`. The location JSON retains the exact
original `native_check_id`, logical source name, and native line/resource metadata
where supplied. Missing coordinates remain absent. PASS rows never become
Findings. The inventory and summaries explicitly retain
`scan_completeness="not-assessed"`; this workflow makes no general clean or
whole-scanner accuracy claim.

`VerifyNativeConfigurationReplay(records, workspace)` verifies the seven owning
acquisitions, source digest, original factory/request/grant bindings, stream and
event facts, chronology, provenance and VERSION association. It works after
workspace relocation without the original executable, source or stage. Replay is
read-only historical interpretation and cannot issue execution or model-write
authority. Fresh model application also requires the exact original live engine,
claims, captures, current material proof and current scope/policy.

## Acceptance evidence

The ordinary installed functional suite is
`tests/functional/test_native_configuration_product.py`. Its dedicated preparation
helper builds one clean noneditable wheel outside the checkout, pins loaded
module hashes, copies the five unchanged owned specimens and independent native
oracle, and provisions the fixed release executable without an image database.
The execution lane runs isolated installed Python with loopback only and no
external route. Five cases each exercise SDK, CLI, raw native rule/location
assertions, seven-role custody, saved Findings, JSON export and relocated replay.
Five more cases refuse missing approval, missing scope allowance, invalid UTF-8,
oversized source and an unsupported executable before provider execution.

Absent optional local context is explicitly unexecuted acceptance. Required CI
preparation/execution/verification fails on missing prerequisites, skipped cases,
wrong source revision or missing original evidence. Deterministic unit doubles
exercise authority/custody failures and do not establish genuine native execution.
