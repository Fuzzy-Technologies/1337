# ADR 0055: Explicit STANDARD Nuclei Workbench workflow

- Status: Accepted
- Related work: #37, #29

## Decision

Add an Experimental one-endpoint Nuclei orchestration consumer of the existing
adapter, impact policy, governed executor, owned job, immutable evidence, canonical
Finding Core, workspace and Security Object Model. `PlanNucleiScan` verifies local
profile material and probes only the operator-selected installed executable's
bounded version command. It presents the exact STANDARD policy intent and argv;
planning never contacts the target or grants execution authority.

`RunNucleiScan` rebuilds that exact plan and accepts an explicitly supplied existing
`PolicyConfirmation`. Current scope, consent, operator, policy and URL/IP membership
are reread at authorization and immediately before process creation. Exact template
and empty-configuration bytes are independently verified again at final launch.
The existing policy engine binds its unchanged digest to invocation, observed
provider version, finite profile digest, current scope/policy and actual destination.
An explicit policy grants only its declared capabilities and impact; there is no
generic approval flag, default STANDARD permission or alternate authorization engine.

After actual raw-evidence verification and pure finding projection, revalidate the
same launch grant with fresh scope/consent/actor/policy, current clock and selected
material immediately before the canonical model owner's Save. Revocation, expiry
or changed material prevents new canonical findings; already captured real raw
streams remain available with truthful failed state.

Expose the same boundary through `1337 scan nuclei`: `--plan` emits a complete
read-only JSON document, while execution accepts `--confirm-plan` with the exact
intent digest plus a non-secret `--confirmation-reference`. Operator-selected local
profile/policy JSON must match the existing typed objects' serialization exactly.
Reject unknown fields, duplicate keys, non-finite values, excessive structures,
filesystem links and implicit permissions. Each authority check reads the policy
file anew, including same-revision content edits.

The existing `LocalExecutionJob` captures actual terminal stdout/stderr through its
owned evidence store, including failed, timed-out or cancelled process outcomes.
Successful JSONL is normalized by the existing Nuclei adapter, then explicitly
converted to canonical findings through `ApplyVerifiedFindings`. SDK finding
envelopes are not silently discarded by `ApplyAdapterResult`. Repeat collection
retains canonical identities and operator triage while appending actual provenance.
Template metadata, review references and provider observations remain attributed
in the shared model, independently of current template files. The composite pure
model projection is committed through one model-owner CAS transition.

Workspace scope/job/object/evidence references are verified and saved before a
terminal completed job. Reopen and report evidence verification use the same
existing model and evidence boundaries without provider or target contact.

## Boundaries

The provider remains optional and independently usable through its familiar CLI.
This workflow never installs tools, downloads templates, discovers targets, resolves
DNS, follows redirects or accepts arbitrary provider options. It accepts exactly
one literal-IP HTTP(S) endpoint and one actually reviewed finite profile whose
templates each perform one GET against the exact URL. The review declaration is
operator-supplied metadata, not an automatic semantic review or authenticated consent.

Files and executable must be operator-owned and remain immutable through execution.
Digest checks detect observed replacement; they do not provide atomic binary
attestation, hostile-race protection or an OS network sandbox. STDOUT/stderr come
from the selected reviewed operation; no resolved credentials are supplied.
Zero matches mean no reported matches, without claiming template coverage or target
security. A match describes a selected template result, not automatic confirmation
of an exploitable vulnerability. Canonical finding confidence remains unknown.
Job/event history is in memory; model/raw evidence and acquisition references are
durable. Master publication and PyPI installation/release acceptance are separate.

The empty config overrides the main CLI configuration, not every upstream
filesystem operation. Pinned native v3.4.10 acceptance preserves the linked
Uncover v1.1.0 pathname-as-YAML initialization diagnostic and evaluates the exact
owned GET's actual exit/result oracle. No home configuration or upstream binary
is rewritten, and filesystem isolation is not claimed. See
[the workflow's pinned upstream references](../NUCLEI_WORKFLOW.md#acceptance-and-upstream-limits).

## Validation

Deterministic source-controlled owned producers exercise exact prepared flags,
current scope/actor/policy/material denial, stale/missing confirmation, evidence
integrity, failure/timeout/cancellation, normalized finding triage, Save/reopen and
report compatibility. These producers are explicitly synthetic and never count as
real scanner acceptance. A separate opt-in pytest lane uses a genuinely installed
compatible Nuclei 3.x binary against a pytest-owned loopback marker service and
reviewed local template, retaining actual version and raw evidence. Its absence
is a skip, never an invented native pass. No external scan is authorized by tests.
