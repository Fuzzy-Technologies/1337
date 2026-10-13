# Governed local artifacts

`fuzzy1337.artifact_inputs` and `fuzzy1337.artifact_policy` are Experimental
contract-version-1 foundations for explicitly selected local inputs. They reuse
the existing workspace, `LocalScopeStore`, recorded consent, `ImpactPolicy`,
`LocalExecutor`, jobs and evidence. No artifact scope or authoritative grant store
is added. See [ADR 0044](adr/0044-governed-local-artifact-authorization.md).

Select each file with `ArtifactSelection(name, absolute_path)` and record explicit
read authority in `ArtifactReadConsent(actor_ref, record_ref)` before calling
`ArtifactStage.Create`. Construction reads no files. Capture copies only those
selected bytes, never recursively discovers sources, and does not grant scanning.
The stage contains role-separated input, scanner and material manifests plus a
fresh separate scratch partition. Names, selected counts, streaming reads and
aggregate bytes are bounded. Observed links/reparse points, hardlinks, special
files, portable collisions, missing or extra material are rejected.

Register and allow `stage.input.manifest.Target()` in the existing scope store,
with explicitly granted current consent. Its `manifest-sha256:` digest binds the
profile, input role and sorted file names/lengths/hashes. It is distinct from an
archive's content SHA, OCI manifest, configuration or layer digest. Source paths
are absent from content identity; relocation preserves manifests but requires a
new physical stage and fresh grant. Original input changes after capture do not
change captured bytes. The selected executable itself is pinned and rehashed
before launch and result acceptance.

| Boundary               | Initial delivered behavior                                      |
| ---------------------- | --------------------------------------------------------------- |
| Native profile catalog | Metadata only; no native plan, grant or launch can be issued     |
| Synthetic profile      | Current trusted CPython and closed reviewed producer SHA only    |
| Source selection       | `image.tar`, exactly `Dockerfile`, or finite rendered YAML files |
| Fixed command          | `-I -S`, explicit pinned policy, memory cache and fixed flags     |
| Policy                 | Explicit provider/capability permission and current scope consent |
| Request binding        | Exact argv, cwd, environment, output/time/cleanup limits         |
| Launch                 | Fresh persisted scope/policy/owner/material validation twice     |
| Acceptance             | Fresh original grant/authority/material check, including expiry |
| Raw result             | Actual exit/timeout/cancellation/output-limit facts preserved    |

`PrepareArtifact(stage, workspace_root)` generates the only accepted request.
It rejects caller commands, flags, capability declarations and environment
overlays. Native Trivy IDs cannot be enabled by attested version or compatibility
text. Synthetic preparation accepts only the running trusted CPython canonical
executable and a source-owned producer hash allowlist. The bundled Internal
`artifact_fixture_worker` is a finite lifecycle oracle; it is not a detector and
does not issue a clean finding verdict. Reviewed richer fixture identities require
separate source and policy-schema changes. The initial fixed policy is bounded
strict UTF-8 JSON: duplicate/nonfinite values and version/type aliases fail before
grant issuance and in the worker itself. Real compatible scanner/material acceptance remains
work in #140, #142 and #158; no tool or database is downloaded here.

Build `ArtifactPolicyContext(current_scope, current_policy, owner_ref)` and call
`ArtifactPolicyEngine.Authorize(prepared, stage, context, at=aware_time)`.
The engine independently reopens the workspace and same scope document. Scope
attester and executing owner are separate operator metadata, not authenticated
principals; a consumer can add its own caller/consent-actor binding. Complete
scope/policy content and revision, consent, owner, all manifests, physical lease
and every process-affecting request field enter the grant. A same-revision change
does not bypass freshness. SAFE requires an explicit capability permission.

`GovernedArtifactExecutor.Execute(prepared, stage, grant, context_provider)`
requires a synchronous fresh typed context provider and returns immutable
`ArtifactExecutionOutcome`. Its `raw_result` is the unchanged accepted executor
result. Its separate `acceptance` receipt binds the exact original run, stage,
grant, process state, stream hashes and event identity. Post-run revocation,
expiry, material mutation or lookup failure records refusal without discarding
raw stdout/stderr or relabeling actual exit facts. Cooperative cancellation
returns a raw cancelled result. Caller coroutine cancellation preserves the
executor's existing raise-after-cleanup contract.

Consumers attach raw stdout/stderr to the existing evidence store with original
execution/grant provenance before interpreting a refusal or updating the model.
Call `ValidateAcceptance` with fresh authority immediately before normalization;
an earlier successful receipt is not permanent authority. A failed process is
never accepted as a successful scan. A per-job wrapper can return `raw_result` to
the existing `LocalExecutionJob`, retaining its immutable outcome for that job's
result handler. There is no mutable shared last-result property.

`outcome.Metadata()` records original grant, receipt, manifests and bounded raw
fact metadata for existing evidence storage. `VerifyArtifactReplay(metadata,
stdout, stderr)` verifies original bindings and returns the historical receipt
read-only. Obtain metadata and streams through the existing evidence-integrity
checks first. Replay issues no grant, reads no current scope, reauthorizes no
launch and never relabels old bytes with today's owner or consent.

The operator must exclude hostile writers from selected executable and physical
staging paths. Portable read-only copies, observed identities and before/after
hashes cannot detect a concurrent change-and-restore attack, attest interpreter
libraries/publisher identity or establish OS immutability/isolation. Scratch starts
empty, has a single-run marker and separate owned cwd/home/temp/cache paths;
post-run verification bounds observed safe output files. This is not an OS
disk-write, CPU, memory or network quota. Scratch is never reused as approved
input. Network policy explicitly rejects ARTIFACT targets, including when valid
IP destinations are supplied; artifact grants cannot authorize network policy.
