# Governed local artifacts

`fuzzy1337.artifact_inputs` and `fuzzy1337.artifact_policy` are Experimental
foundations for explicitly selected local inputs. Selected-byte manifests remain
contract/schema version 1; new execution metadata is schema 2. They reuse
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

Each selected path is bound to its opened regular file by nonzero file identity,
device, size and modification time. Complete path observations remain stable
within the path API; complete handle observations remain stable within `fstat`.
On Windows only, cross-API change time is compared separately because CPython
can expose creation time through path `stat` and change time through `fstat`.
Different device/inode IDs or unavailable stable identity refuse capture rather
than normalize metadata. A second read-only handle witnesses the guarded path
without replacing its original identity anchor. Both handles close on refusal.

Register and allow `stage.input.manifest.Target()` in the existing scope store,
with explicitly granted current consent. Its `manifest-sha256:` digest binds the
profile, input role and sorted file names/lengths/hashes. It is distinct from an
archive's content SHA, OCI manifest, configuration or layer digest. Source paths
are absent from content identity; relocation preserves manifests but requires a
new physical stage and fresh grant. Original input changes after capture do not
change captured bytes. The selected executable itself is pinned and rehashed
before launch and result acceptance.

| Boundary               | Initial delivered behavior                                        |
| ---------------------- | ----------------------------------------------------------------- |
| Native profile catalog | Metadata only; no native plan, grant or launch can be issued      |
| Synthetic profile      | Current trusted CPython and closed reviewed producer SHA only     |
| Source selection       | `image.tar`, exactly `Dockerfile`, or finite rendered YAML files  |
| Fixed command          | `-I -S`, explicit pinned policy, memory cache and fixed flags     |
| Policy                 | Explicit provider/capability permission and current scope consent |
| Request binding        | Exact argv, cwd, environment, output/time/cleanup limits          |
| Launch                 | Fresh persisted scope/policy/owner/material validation twice      |
| Acceptance             | Fresh original grant/authority/material check, including expiry   |
| Raw result             | Actual exit/timeout/cancellation/output-limit facts preserved     |

`PrepareArtifact(stage, workspace_root)` generates the only accepted request.
It rejects caller commands, flags, capability declarations and environment
overlays. Native Trivy IDs cannot be enabled by attested version or compatibility
text. Synthetic preparation accepts only the running trusted CPython canonical
executable and a source-owned producer hash allowlist. The bundled Internal
`artifact_fixture_worker` is a finite lifecycle oracle; it is not a detector and
does not issue a clean finding verdict. The independently reviewed richer image
worker now has its own closed family/policy/operation dispatcher; merely sharing
the lifecycle profile does not select its policy or argv. Configuration wire
registration remains separate. The initial fixed policy is bounded
strict UTF-8 JSON: duplicate/nonfinite values and version/type aliases fail before
grant issuance and in the worker itself. Real compatible scanner/material acceptance remains
work in #140, #142 and #158; no tool or database is downloaded here.

The closed lifecycle worker emits exact LF-delimited stdout/stderr bytes on every
platform. The executor retains those original bytes; it applies no newline
normalization. Readiness consumers accumulate bounded stream prefixes because
executor events are chunks rather than line records.

Build `ArtifactPolicyContext(current_scope, current_policy, owner_ref)` and call
`ArtifactPolicyEngine.Authorize(prepared, stage, context, at=aware_time)`.
The engine independently reopens the workspace and same scope document. Scope
attester and executing owner are separate operator metadata, not authenticated
principals; a consumer can add its own caller/consent-actor binding. Complete
scope/policy content and revision, consent, owner, all manifests, physical lease
and every process-affecting request field enter the grant. A same-revision change
does not bypass freshness. SAFE requires an explicit capability permission.
Live validation recomputes the exact exclusive expiry from original issuance and
the fully bound policy and consent. Issuance itself must be within recorded
consent; rebuilding an envelope cannot change that canonical lifetime.
After full hashing and scratch setup, the final launch hook re-reads complete
authority and the clock without a new expensive hash cycle. Any owner, scope,
policy or expiry change in either window denies before process start. Prepared
environment values are frozen once and the actual request must equal the rebuilt
canonical request.

`GovernedArtifactExecutor.Execute(prepared, stage, grant, context_provider)`
requires a synchronous fresh typed context provider and returns immutable
`ArtifactExecutionOutcome`. Its `raw_result` is the unchanged accepted executor
result. Its separate `acceptance` receipt binds the exact original run, stage,
grant, process state, stream hashes and event identity.
The accepted receipt also binds the actual single-run marker's physical identity
and fixed bounded contents containing the original run and authorization IDs.
Its checked time is within the original grant and no later than a
fresh acceptance decision. Missing/changed/relinked markers cannot relabel a run.
Copying raw output into another policy-valid grant window cannot relabel the
physical launch's original authorization.
Post-run revocation, expiry, material mutation or lookup failure records refusal without discarding
raw stdout/stderr or relabeling actual exit facts.
The internal receipt decision also re-reads context and time after full after-run
hashing and marker verification; changes during that work refuse the receipt.
Cooperative cancellation returns a raw cancelled result. Caller coroutine cancellation preserves the
executor's existing raise-after-cleanup contract.

Consumers attach raw stdout/stderr to the existing evidence store with original
execution/grant provenance before interpreting a refusal or updating the model.
Call `ValidateAcceptance` with fresh authority immediately before normalization;
an earlier successful receipt is not permanent authority. A failed process is
never accepted as a successful scan. A per-job wrapper can return `raw_result` to
the existing `LocalExecutionJob`, retaining its immutable outcome for that job's
result handler. There is no mutable shared last-result property.

The richer image family adds explicit `ArtifactOperation.VERSION` and `SCAN`.
VERSION has a fixed three-second deadline and 16 KiB per-stream ceilings; richer
SCAN defaults to 30 seconds, admits integer deadlines from 1 through 60 seconds
and captures at most 4 MiB stdout/1 MiB stderr. Lifecycle SCAN retains its existing
120-second default and exact argv ordering. Every operation has a separate fresh
stage/root/scratch/lease/grant/run/marker/receipt; no native profile is enabled.

After collecting and freshly accepting an actual richer VERSION, construct
`ArtifactVersionProof(outcome, prepared, stage)`. Its construction checks original
successful raw/receipt/request/stage facts and strict observed version JSON, but
does not create current authority. Pass it to richer SCAN preparation as
`PrepareArtifact(scan_stage, workspace_root, version_proof=proof)`. Missing or
failed VERSION cannot grant SCAN; VERSION and lifecycle SCAN require no proof.
The request and schema-2 plan contain explicit `operation`, `producer_family`,
`version_run_id`, `version_grant_id` and `version_prerequisite_sha256`; the last
three are null only for VERSION and lifecycle SCAN. The original prerequisite
digest commits original VERSION metadata and complete prepared/stage payloads.
SCAN planning/issuance/launch freshly verify it, so another valid same-content
VERSION cannot replace the originally bound proof.

The facade's `ValidateAcceptanceFresh` reads canonical current context and time
after full original-run validation. `ValidatePairAcceptanceFresh(version_tuple,
scan_tuple, context_provider)` requires each tuple to be the actual original
outcome/request/stage, checks the bound VERSION prerequisite and cross-stage
content/executable/workspace/owner agreement, validates both originals, then
refreshes both at a final shared authority/time barrier. A VERSION expiry during
SCAN hashing refuses acceptance. Post-run VERSION expiry preserves successful
SCAN process facts and both raw results while recording a separate refusal.
Consumer capture-window chronology, evidence persistence and atomic model save
remain separate responsibilities in [the operation contract](SYNTHETIC_IMAGE_OPERATIONS_DESIGN.md).

`outcome.Metadata()` records original grant, receipt, manifests and bounded raw
fact metadata for existing evidence storage. `VerifyArtifactReplay(metadata,
stdout, stderr)` verifies original bindings and returns the historical receipt
read-only. Schema 1 retains its original exact field shape, intent and envelope
hashing and denotes only legacy lifecycle SCAN. It cannot be upgraded into a new
operation, family, VERSION proof or live grant. Schema 2 requires all operation
and prerequisite fields, including explicit nulls. Unknown schemas or extra and
missing fields reject. Obtain metadata and streams through the existing evidence-integrity
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
