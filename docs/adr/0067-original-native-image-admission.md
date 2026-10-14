# ADR 0067: Original native image admission

## Status

Accepted for the internal original native image consumer. Refs #140, #142 and
#138. The native artifact execution profile remains metadata-only.

## Context

ADR 0058 preserves independently executed native Trivy VERSION and SCAN streams,
requests, terminal outcomes, selected material and custody receipts. The older
`images.ApplyVerifiedTrivyImages` consumer deliberately expects a three-role
legacy report with executionless VERSION health evidence. Rewriting the executed
VERSION as a health probe would destroy original acquisition facts.

The native pair needs a separate evidence consumer that can compose original
custody into the existing canonical image, package and Finding model. Historical
replay must remain possible after the owning workspace moves or the selected
binary, archive and database files become unavailable.

## Decision

Add the internal `native_image_admission` module with a distinct six-role source
family. Reopen every original immutable manifest and blob through the canonical
owning evidence store. Apply bounded role/media budgets to both caller references
and actual store-owned references before allocation. Require original canonical
schema-one receipts, exact factory argv, resource and environment profiles,
independent invocation-bound authorization records and original event histories.

Verify the full VERSION receipt digest recorded by SCAN, separate original
scratch and authorization identities, chronological collection windows and exact
owner, read consent, target, scope, policy and selected-material association.
Observed VERSION remains separate from the original unknown-version invocation.
Successful custody requires successful original terminal facts and unchanged
selected bytes/physical identities. Replay preserves failed or refused SCAN
facts without parsing incomplete stdout as successful inventory.

Model admission requires the original typed producer captures to match the
retained receipt, request and executor outcome. The consumer performs no process
launch, file discovery, current authorization issuance, model save or evidence
write. Historical interpretation does not require current access to old selected
material. The original records attribute collection; they are not publisher
signatures, current permission or proof against an actor able to replace every
workspace record coherently.

Reuse the pure `images.TrivyCandidates` interpretation and existing `ApplyBatch`
and verified Finding ingestion. This keeps provider-independent native image and
installed-package identities, exact package/vulnerability correlation, existing
triage and model schema one. The caller owns the separate canonical CAS save and
workspace-reference persistence. No fabricated legacy health record or artifact
grant is introduced.

## Verification

Owned executable integration tests execute the actual production capture,
evidence, admission, CAS save, reopening and relocated replay path. Their wire
producer is explicitly simulated and performs no genuine image decoding.
Negative tests retain original partial/nonzero bytes while refusing model
admission, and cover manifest substitution, receipt provenance, event histories,
bounded roles, chronology, material and request substitutions.

The existing opt-in pinned genuine Trivy lane also exercises canonical native
admission and model reopening for the independently selected vulnerable/fixed
package oracle. It retains original raw evidence plus model and admission
artifacts. Genuine acceptance requires that isolated CI lane; absent local native
material is an explicit skip.

## Consequences

Legacy health-based native ingestion, synthetic image family isolation and all
existing evidence/model schemas remain unchanged. Native execution enrollment,
the native CLI/job workflow and general scanner completeness remain separate
work. This consumer adds evidence-backed canonical interpretation without
expanding native execution policy.
