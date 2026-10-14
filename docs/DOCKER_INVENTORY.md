# Owned Docker inspect inventory

The experimental `fuzzy1337.docker_inventory` module imports one explicitly
supplied offline Docker container inspect JSON list. It advances runtime inventory
and relationship tasks #149/#150. It does not collect daemon state, connect to a
socket, invoke Docker, discover hosts or execute breakout checks.

Acquire the original caller-owned input through `LocalEvidenceStore.Put` with role
`docker-inspect`, media type `application/json`, source ID
`inventory.docker-inspect` and source version
`owned-docker-container-inspect-v1`. The evidence owner controls acquisition and
which authorized bytes are retained. Environment, labels, commands, health log
output and arbitrary provider fields never enter normalized metadata. The profile
does not discover or export credential values. Review or redact sensitive input
before acquisition; any such input is the supplied document, not an assertion that
it contains unmodified daemon output.

Create or select an existing canonical literal HOST object through the normal model
owner. Supply its exact reference as both `host_reference` and model provenance's
`target_reference`. `ApplyVerifiedDockerInspect` verifies the workspace, immutable
manifest, original blob, exact scope/source/provider version/finished time and raw
reference. Offline source and model provenance must have no invocation/execution
claim. Attribution grants no execution authority.

The importer returns an in-memory `(ModelState, ModelDelta)`. Save it explicitly
through `LocalModelStore.Save(..., expected_revision=...)`; the importer writes no
storage. One fully validated input becomes one canonical revision. Exact source
replay is a no-op, including after moving the whole owning workspace. Fresh
acquisition evidence retains observation history and preserves operator finding
triage.

## Selected facts and identities

| Input                              | Normalized interpretation                                           |
| ---------------------------------- | ------------------------------------------------------------------- |
| Full `Id`                          | Host-scoped ASSET subtype `container`                               |
| `Image` config SHA-256 digest      | Existing `image-config:sha256:...` key through `ImageIdentity`      |
| Configured user                    | `root`, `numeric-nonroot`, `named` or unknown; username is omitted  |
| Privileged/rootfs/capability flags | Explicit configured values; effective access remains unverified     |
| Namespace modes                    | Fixed categories; cross-container selector text is omitted          |
| State/health                       | Selected reported status flags; health log output is omitted        |
| Network ID and assigned addresses  | Host-scoped network ASSET and reported literal membership facts     |
| Ports and host bindings            | Container-scoped SERVICE declarations; no observed listening claim  |
| Bind/volume/tmpfs mounts           | Host-scoped lexical mount associations; source paths are never read |

Image config and manifest identity domains remain distinct. Mutable tags do not
identify an image, and a config digest never invents a manifest digest. Existing
image-scan object metadata and its original provenance survive correlation. Every
imported selected fact and relationship retains the exact source evidence
reference; original bytes remain separate in the evidence store.

Missing/null selected fields remain `None`, including capability collections,
namespace flags, reported health/state, collection counts and port bindings. An
empty explicit collection remains distinct from unknown. No absent field means a
safe runtime. Named users remain unresolved rather than becoming a confirmed
non-root effective user.

The profile admits Linux-style POSIX bind paths, known capabilities, complete
lowercase container/network IDs, literal unzoned IPv4/IPv6 addresses and selected
TCP/UDP/SCTP declarations. Unsupported selected fields fail closed. Unselected
fields are ignored after bounded JSON validation rather than copied into model
attributes or exception messages.

## Configured conditions and graph consumers

Direct OPEN findings describe privileged configuration, configured root user,
selected host namespace settings, added powerful capabilities and configured
management-socket or sensitive host bind mounts. Their evidence confidence refers
to the direct selected configuration fact. Severity is advisory; these findings do
not prove usable daemon access, effective Linux privileges, vulnerability,
exploitability, reachable service or successful breakout. Import never changes
operator triage, executes remediation or issues a policy grant.

Image→container, container→network/service/resource and host→container associations
reuse existing model relation kinds. A caller may explicitly select RELATED_TO
associations for `ReadReachabilityClaims` / `ProjectReachability`. With no separate
admissible attestation, selected transitions and candidate paths stay UNKNOWN with
the `unassessed` reason. A shared network or configured port does not become a
confirmed communication path.

## Bounds and verification

Defaults and fixed inclusive maximums are 1 MiB original bytes, 32 containers,
16 networks, 32 port declarations and 32 mounts per container. Port declarations
allow at most 16 explicit bindings; capability arrays allow at most 64 names.
JSON additionally caps depth at 24, nodes at 20,000 and each key/string at 4096 UTF-8
bytes. Callers may lower `DockerInventoryLimits`; exceeding a bound rejects the
whole input. Typed subclass overrides or mutated frozen quota/provenance values
cannot relax the boundary.

The handwritten owned fixture/oracle checks exact inventory, six configured
positive conditions and three explicit negative conditions. Integration tests
exercise actual evidence acquisition, importer, canonical save/reopen, portable
replay, existing image correlation, preserved triage, no-live-access tripwires and
existing reachability consumption. Malformed/truncated JSON, duplicate keys and
identities, finite-number/depth/node/byte limits, forged attribution, missing or
corrupt manifests/blobs, foreign workspaces and invalid selected fields have direct
failure coverage.

Live daemon inventory, daemon/socket exposure discovery, complete runtime-version
support, network observation and physical runtime security acceptance remain open.
See [ADR 0070](adr/0070-owned-docker-inspect-inventory.md).
