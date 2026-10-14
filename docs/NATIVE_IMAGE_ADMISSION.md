# Original native image admission

The internal `fuzzy1337.native_image_admission` consumer connects the original
executed native Trivy VERSION/SCAN custody from ADR 0058 to the existing canonical
image, installed-package and Finding model. It starts no process and issues no
authorization. Native artifact-profile enrollment and the native CLI/job workflow
remain separate work.

`ApplyVerifiedNativeTrivyImages(state, version, scan, workspace_root)` requires
the original typed `NativeTrivyOperationCapture` pair. It verifies all six
immutable source manifests and retained bytes before producing one in-memory
model transition. Original VERSION stdout, stderr and receipt remain independent
from SCAN stdout, stderr and receipt. The observed supported version does not
rewrite VERSION's original `provider_version=None` invocation.

The pair must preserve exact original owner/read consent, target, scope, policy,
selected archive/binary/database facts, separate authorization and scratch
identities, operation times, request profiles and raw event histories. SCAN pins
the complete original VERSION receipt digest. Report parsing admits only bounded
schema-two container-image inventory with exact installed-package correlations.
Existing image/package identities and Finding triage are reused. A failed or
refused operation cannot create a successful empty inventory.

The returned `(proposal, delta)` is not a persistence acknowledgement. The caller
uses `LocalModelStore.Save(proposal, expected_revision=state.revision)` and updates
the owning workspace's object/evidence references through `LocalWorkspaceStore`.
No model save, evidence write or workspace update happens inside admission.

`VerifyNativeTrivyImageReplay(records, workspace_root)` verifies the six original
manifests and source receipts from an existing or relocated owning workspace. It
does not open historical selected files, consult live policy or execute Trivy.
It preserves refused or failed SCAN terminal facts without interpreting partial
stdout. Recorded requests and authorization references are descriptive original
facts, never current execution permission. Content addresses prove retained
consistency, not publisher authenticity or protection against an actor who can
replace every owning record coherently.

The legacy three-role `images.ApplyVerifiedTrivyImages` API still requires its
executionless VERSION health shape. Synthetic six-role images keep their
separate receipt roles, detector namespace and isolated asset identities. This
consumer never manufactures a legacy health acquisition from executed VERSION.

Focused development checks:

```bash
uv run --locked --extra dev python -m pytest -q \
  tests/unit/test_native_image_admission.py \
  tests/unit/test_native_image_capture.py \
  tests/integration/test_native_image_model.py -n 2 --no-cov
```

The owned integration wire fixture runs actual subprocesses through production
capture/admission/persistence interfaces but performs no image decoding. Genuine
pinned Trivy acceptance belongs to `tests/integration/test_trivy_native.py` in the
existing isolated CI lane. Its vulnerable/fixed package cases retain raw custody,
canonical model, workspace references and admission replay artifacts; local
absence of pinned native material is an explicit skip. General scan completeness
is not assessed by this package oracle.
