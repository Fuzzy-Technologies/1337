# ADR 0114: Governed local Docker image-reference export

## Status

Accepted bounded direction by the integration coordinator on 2026-10-29, Task
#140. This decision authorizes implementation and its independently reviewed
acceptance; source alone does not establish genuine Docker or Trivy execution.

## Decision

Complete the local-reference profile as two explicit phases:

1. Plan and approve a bounded local Docker image-reference export. Resolve the
   exact supplied local reference, export only its immutable config ID, verify
   the Docker-save config bytes, and recheck the original reference.
2. Register and approve the resulting archive target independently, then use the
   existing native archive scan. Export permission never grants Trivy execution
   and the application never silently adds the generated archive to scope.

The local export is not a vulnerability scan. Its result includes original
evidence references, the archive byte identity, canonical archive target and
selected image config ID. The documented product recipe must prove export,
explicit archive scope registration, native scan, saved Findings and reopen.
The native scan integration must compare the expected config identity before
model Save; an after-save mismatch is not successful acceptance.

## Selected boundary

The initial runtime is Linux with the accepted owned descendant executor. The
operator supplies a trusted absolute Docker executable and explicit absolute
local Unix socket; the default canonical spelling is `/run/docker.sock`.
An explicitly selected owned test daemon is supported under the same contract.
No Docker context, ambient endpoint, inherited configuration, credential store,
proxy, plugin, registry transport or implicit default tag is selected.

Inputs are a complete `sha256:` image ID or an exact local repository/tag.
Names are looked up only by the local image-inspect command. No pull, load,
build, container creation/start, registry lookup or image mutation is allowed.
The fixed Docker argv names its endpoint, private empty config and immutable
export ID explicitly. A reference changing between observations refuses the
export even when saving by the earlier ID produced valid bytes.

A closed schema-one reference manifest binds the exact reference, Docker path
and Unix endpoint. Its canonical JSON digest supplies the existing ARTIFACT
`manifest-sha256:` scope target; it is not an archive, image config, registry
manifest or `ArtifactManifest` for the generated tar. Existing artifact profiles
and their serialized values remain unchanged.

The canonical `ArtifactPolicyEngine` owns additive local-export plan/grant/claim
delegates. The capability is `image.local-reference-export`, provider
`native.docker-local`, SAFE read-only impact with explicit local Docker read
privilege. Current registered scope, actor/read consent, operator permission,
exclusive expiry and exact workflow opt-in precede command grants. A separate
one-use grant binds each exact invocation, request/environment/resources,
selected executable/socket facts and original resolution. Original opaque
issuer identity plus durable exclusive claims prevent grant reconstruction and
reuse. No native-image or configuration grant can authorize Docker reads.

## Bounds and evidence

Use the existing executor with explicit Linux descendant ownership, fixed private
HOME/config/cwd and no inherited endpoint controls. Inspect output is at most
one MiB; archive stdout at most 64 MiB; stderr at most 64 KiB. Inspect has a
10-second deadline and export 30 seconds, with separate bounded owned cleanup.
Do not use Docker's output-file option: it would bypass the stdout byte limit.

Retain original stdout/stderr, exact invocation, execution/cleanup outcome,
authority attribution and inspect/export associations. Export overflow, timeout,
cancellation, nonzero exit, unknown cleanup, changed authority/material or
reference reassignment fails without invoking Trivy. Partial original captures
remain explicitly incomplete and never become an accepted archive.

Read the bounded Docker-save tar without extracting paths or executing image
contents. Require one manifest entry and one ordinary bounded config member;
its SHA-256 must equal the inspected config ID. Keep archive byte hashes, config
IDs, distribution manifests and layer DiffIDs distinct. Publish the complete
archive without overwrite beneath the selected owning workspace only after
all acceptance checks. Preserve preexisting workspace/model/evidence facts and
report actual acknowledgement uncertainty if any persistence step fails.

## Acceptance

Focused deterministic tests cover reference grammar, fixed argv, exact authority,
claim reuse, revocation/expiry, reassignment, malformed/oversize tar, missing
images, limits, cancellation, original custody and no-clobber behavior. An
ordinary opt-in pytest lane loads only repository-owned inert metadata images
into its explicitly owned local daemon, invokes the installed product export,
then separately approves and runs the existing pinned native Trivy scan.
It preserves original receipts, independent config/package/advisory identities,
saved/reopened model and refused missing-scope/reference cases. Enabled missing
prerequisites fail. No Internet target, remote registry or arbitrary image runs.

Shared policy delegates, CLI, API/locale inventories, changelog and CI enrollment
remain integration-owner changes. This task does not add another image scanner,
general Docker administration, runtime discovery or release publication logic.
