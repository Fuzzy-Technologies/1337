# ADR 0109: Native configuration SDK prerequisites

## Status

Prerequisite-only design accepted by the integration coordinator after independent
review on 2026-10-28. Refs Task #158. Implementation and actual execution evidence
remain required. This decision grants no native provider execution, product SDK,
CLI, model import or CI enrollment.

## Context

[ADR 0105](0105-pinned-native-configuration-compatibility.md) established a
separate native Trivy compatibility harness. Its five specimen identities prove
selected native checks, not a general product input allowlist. Synthetic
configuration and native image handles cannot authorize configuration execution.

The next product direction is an evidence-first native configuration SDK: an
original governed VERSION/config pair, exact selected source, durable provider
report and historical replay. Authority, custody and workflow decisions remain
separate subsequent slices. First establish a fixed recipe and bounded observed
material without weakening existing artifact contracts.

## Decision

### Pure selection and fixed recipe

Add internal native-configuration selection and recipe contracts. Admit one
explicitly selected UTF-8 source of at most 4096 bytes: logical `Dockerfile`, or
one portable flat Kubernetes `.yaml`/`.yml` name. Preserve reserved control-name
and path guards. Do not restrict source content to the five compatibility
specimens or introduce caller-defined executable registrations.

Selection constructors validate syntax without reading files. Actual reads
require explicit artifact-read consent and the executing owner. The initial
candidate is the already tested Linux x86_64 Trivy 0.75.0 executable pin from
ADR 0105. A pin identifies candidate bytes; it is neither publisher
authentication nor permission to execute.

Promote the fixed VERSION/config argument grammar into production without
importing test helpers. VERSION has no previously observed provider version.
The SCAN recipe remains descriptive until a separately accepted original VERSION
prerequisite and configuration authority exist. Caller flags, environment
overlays, renderers, external checks and image database material are excluded.

### Owned snapshot creation and verification

Implement a fixed installed create/verify child and its parent observer in
separate internal modules. Both require supported Linux x86_64 ownership before
reading selected material. The child cannot launch Trivy.

Compose the existing `ArtifactSnapshot.Capture` operation with explicit streaming
admission limits: INPUT 4096 bytes, SCANNER 256 MiB and empty MATERIAL zero bytes.
Construct the typed stage from these observed snapshots. Do not call
`ArtifactStage.Create`, `ArtifactStage.Verify` or `ArtifactSnapshot.Verify` with
their broader global budgets. Do not change shared artifact APIs for this slice.

Existing bounded reads use 64 KiB chunks. A growing file may therefore cause one
bounded over-limit read buffer, followed by refusal before that buffer is
admitted, hashed or copied. The per-role limits describe admitted bytes, not a
promise that the operating system reads exactly 4096 source bytes.

Verify exact copied source and scanner bytes and the selected original
executable with explicit bounded `ReadArtifactFile` calls, preserving existing
before/open/after physical guards. Bind manifest, selected executable identity,
staged executable copy and exact candidate pin. Decode UTF-8 only from those same
bounded verifier bytes after manifest agreement. Do not reopen the original
source after snapshot capture or perform a separate uncapped read.

Use closed-world staged partitions and existing physical-path guards. Observed
integrity is not an operating-system sandbox against a hostile concurrent writer.
Unknown files and changed original executable/staged material refuse proof.

### Proof, control and lifecycle

Only the original observer instance may issue an opaque material proof after
actual successful child termination, bounded response validation and confirmed
owned cleanup. Bind the exact selection, owner, workspace identity, operation,
nonce, stage, manifests and physical facts. Construction, copying or reopening a
receipt cannot issue a proof. Material proof grants no provider authority.

Use exclusive private control files, fixed create/verify actions, bounded
canonical JSON and the installed isolated entry point. Do not inherit arbitrary
host environment or caller commands. Reuse the existing nonauthority observation
budget ledger; do not import image material, proof, claim or capture contracts.

Each helper consumes one inclusive 12-second observation slot: up to three
seconds READY, six seconds worker and three seconds cleanup. Charge control and
result handling to that same slot. The future workflow's single 45-second ledger
reserves three observations and nine seconds finalization; helpers cannot create
fresh replacement budgets or consume that reserve implicitly.

Cancellation must settle the owned helper and monitor. Timeout, overflow,
nonzero exit, changed controls, missing proof or unknown cleanup cannot produce a
successful proof. Retain private state when cleanup is uncertain; recursive
cleanup requires confirmed terminal ownership. No executor, grant, evidence,
model, job or workspace-reference behavior is added by this prerequisite.

## Implementation and acceptance

Commit the pure selection/factory with focused grammar and contract checks first.
Implement the owned observer/worker as a second coherent slice with direct
mutation, bounds, cancellation, timeout, cleanup and proof-identity checks.
Independent source review must verify actual streaming limits and copied-byte
associations. Installed helper execution is distinct from genuine Trivy product
acceptance; neither substitutes for the other. New production modules retain the
per-module statement/branch coverage contract at final integration.

Any future native report acceptance must establish actual selected-file
processing and embedded-check provenance. An executable pin, successful exit or
empty output alone proves no clean configuration or completed scan. Product
authority, seven-role custody/replay, SDK, CLI and additional genuine cases require
their own reviewed implementation decisions.
