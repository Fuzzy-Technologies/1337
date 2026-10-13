# ADR 0058: Original native image VERSION/SCAN capture

## Status

Accepted bounded production prerequisite — 2026-10-13. Tasks #140/#142.
Genuine compatibility evidence requires a passing exact-head Trivy acceptance
workflow; locally skipped native tests establish no native PASS.

## Decision

Add `TrivyAdapter.PrepareVersionInvocation` as a fixed SAFE, archive-associated,
three-second JSON VERSION factory without a borrowed provider version. Keep the
existing descriptor, capability, scan factory, health interface and normalizer.
VERSION and SCAN are original independently executed operations through the
accepted bounded `LocalExecutor`, using separate caller-issued typed exact
invocation authorizations. No collector, receipt parser or file checksum issues
permission. Native `ArtifactProfile.IMAGE` remains metadata-only.

`CaptureNativeTrivyOperation` takes explicit physical selections, read consent,
canonical existing evidence storage, owner/workspace identities and exact caller
invocation/authorization. It creates fresh owned cwd/home/config/temp and a clean
explicit environment for each operation. VERSION captures at most 16 KiB per
stream; SCAN captures at most 4 MiB stdout and 1 MiB stderr. Original stdout,
stderr and a canonical custody receipt are retained separately for each operation
with actual invocation digest, execution/termination/events and observed start/end
times. VERSION's original invocation remains unknown-version; its successfully
observed provider version is a distinct fact, never a retroactive rewrite.

Selected archive, executable, offline database and metadata receive independent
bounded SHA-256 and device/inode/size/mtime/ctime observations before launch and
after cleanup. The final executor launch callback repeats these observations and
optionally rereads upstream authority; the optional callback is also invoked
post-run. Genuine VERSION must report the supported native envelope and schema-2
DB metadata matching the explicitly selected metadata bytes and aware update time.
Missing database material is an explicit absence, never invented from output.

SCAN requires the original accepted VERSION, reopens all three canonical original
records and their exact receipt/stream bytes, and requires matching selected
material, owner/workspace, target, scope and policy. Its independently issued
SCAN authorization must have a different decision identifier. SCAN custody
references the exact original VERSION receipt digest without turning that digest
into factory authority. Failed, truncated, timed out, cancelled, material-changed
or authority-unverified VERSION cannot launch an associated SCAN. Original failed
execution and post-run interpretation refusal remain distinct retained facts.

## Compatibility and limits

The legacy `ApplyVerifiedTrivyImages` contract remains unchanged: its original
version record has no execution/invocation provenance. New executed VERSION
records intentionally cannot enter that import path; callers must not remove
facts or invent health provenance. This slice writes no durable model state and
provides no native product artifact registration, scope grant, CLI scan or paired
SDK acceptance. The synthetic governed workflow remains separate.

Trusted selected files and independently enforced isolation are caller
prerequisites. Physical/hash observations identify selected material, not publisher
authentication, hostile-writer resistance or a process sandbox. Network, CPU and
memory confinement are not provided by this collector. The genuine CI lane retains
its external no-egress namespace and official fixed binary/database provisioning.
No native binary/database is vendored or published to PyPI.

Direct task cancellation propagates after executor cleanup; cooperative
cancellation retains its original outcome and raw records. Storage failures retain
the existing canonical store's possible orphan-blob behavior. No atomic two-phase
model commit, complete scan assertion or database freshness claim is introduced.
Tasks #140/#142 remain open for subsequent product authorization and integration.

See [the genuine acceptance guide](../TRIVY_ACCEPTANCE.md) for fixed materials,
isolation and retained original evidence.
