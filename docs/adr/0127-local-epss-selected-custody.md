# ADR 0127: Local EPSS selected custody and original-source replay

## Status

Accepted Experimental SDK boundary extending the pure decoder in ADR 0126.
The same product iteration adds a separate `intel epss import|inspect` consumer
over this boundary. No HTTPS receiver, enrichment, matching or official-source
authentication is added.
#43 and #47 remain open.

## Decision

Use existing `LocalWorkspaceStore`, `LocalEvidenceStore`, `EvidenceProvenance`
and schema-one `EvidenceRecord` owners. New local request/source DTOs require
explicit immutable CVE selection, caller source facts, model/day, primary
license attribution and one to four canonical additional terms URLs. There is
no filename discovery or remote locator admission; payload bytes are explicit.

Publish original bounded gzip, a separate attributed envelope and an exact
terminal receipt with identical original acquisition provenance. The source
acquisition clock is importer-observed; the score clock remains original CSV
metadata. The envelope family `epss-acquired-selection:` binds source terms,
original raw manifest identity and nested unchanged decoder schema-two/profile-one
content. Its own schema-one/profile-one marker is not legacy Intel schema one.
The explicit score clock must not follow original acquisition completion.

| Artifact             | Separate evidence role     | Limit   |
| -------------------- | -------------------------- | ------- |
| Complete gzip        | epss-gzip-source           | 4 MiB   |
| Incomplete prefix    | epss-gzip-partial          | 4 MiB   |
| Attributed selection | epss-selected-snapshot     | 128 KiB |
| Terminal receipt     | epss-selection-acquisition | 32 KiB  |

The caller may reduce the compressed limit but cannot raise decoder budgets.
Legacy parser/snapshot/receipt serialization, remote admission, source limits,
model state and dispatch remain unchanged. No `SnapshotRequest` with remote
payload omission is constructed.

## Failure and acknowledgement contract

Raw, selection and receipt stages have independent `not-attempted`, `confirmed`
or `unknown` acknowledgements. Mark a stage unknown before `Put`, and confirmed
only after its exact manifest is returned. On storage failure, stop and return
`storage-failed`, keep previously confirmed handles and no usable success envelope.
Immutable orphan artifacts may remain; rollback is never inferred.

The serialized receipt excludes its own publication acknowledgement, avoiding a
circular claim. A receipt write may commit and lose acknowledgement: the caller
still receives unknown/failure, while later exact-root reopening can establish
the physically committed successful custody. Failed raw/selection publication
cannot manufacture that receipt or a complete accepted acquisition.

Digest and decode failures retain original complete bytes and an honest failure
receipt when storage succeeds. Over-limit input retains only the bounded prefix
under the partial role with body completeness false. None yields selected content.

## Replay boundary

Require exact selected-envelope and successful receipt manifest IDs. Check owner,
role/media/importer, identical provenance and role-specific byte budgets before
content interpretation. Strict bounded JSON rejects duplicate fields/nonfinite
constants and reconstruction enforces exact field sets and canonical types.
The owning store's `Get` also verifies blob content through virtual `Read`.
Use a narrowly configured profile subclass whose `Read` checks the caller's
expected role, media type and byte ceiling before delegating. Do not select a
ceiling from an untrusted manifest role or wait until after `Get` to bound reads.

Validate receipt limits, source/digest selection, raw metadata and the complete
expected envelope/receipt before original raw `Get` or content read. Then require
the exact original acquisition manifest, hash-verified bytes, and repeat the
unchanged gzip decoder with original requested IDs/model/day. Compare its complete
result, including unknown partition and decode facts, before returning. Inspection
writes nothing. Rehashed but inconsistent selected records cannot replace source
assertions; full replacement of caller-selected root identities is a different
selection, not authentication of the original publisher.

## Attribution and remaining acceptance

Terms URLs are caller-declared source facts, not verified licensing or invented
SPDX grants. FIRST attribution guidance and public-service terms can be preserved
as separate links, independently of code or repository licensing. Synthetic
fixtures retain synthetic origin and explicit fixture-only attribution.

Deterministic store-bound tests cover custody, unknowns, relocation, loss/corruption,
tampering, invalid provenance, partial source and publication-before/after-commit
failures. A local SDK import of an already downloaded pinned archive is local
original-source proof, never isolated HTTPS acceptance. The separate CLI consumer
is implemented and its portable example is verified through an installed wheel.
Official source terms review and exact isolated SDK receiver acceptance remain
future work.
