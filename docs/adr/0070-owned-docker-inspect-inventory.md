# ADR 0070: Owned Docker inspect inventory

Status: Accepted for the experimental offline input profile

## Context

Tasks #149 and #150 need attributable runtime facts and image/container/network/
service/host/resource associations. Docker container inspect includes sensitive
environment, command and label values. It describes a supplied runtime snapshot;
it does not prove network reachability, effective privileges or exploitability.

## Decision

Import an explicit, immutable `docker-inspect` JSON evidence record from the
current workspace. The acquisition source is `inventory.docker-inspect`, with
source version `owned-docker-container-inspect-v1`. The caller supplies an existing
literal HOST reference. Collection attribution must match that host, workspace,
scope, source, optional provider version, observation time and exact evidence
reference. Offline imports cannot invent invocation or execution provenance.

Admit a nonempty bounded list of container inspect records. Require full container
IDs and config image digests; reuse `ImageIdentity(..., "config")` and never infer
manifest digests from tags. Container, network, service and mount identities are
host-scoped. Reuse canonical Security Objects, findings, observations and storage.
Apply a fully validated batch in memory; the caller owns model persistence.

Whitelist selected config/state fields, network IDs and literal assigned addresses,
port declarations/bindings and mount associations. Ignore arbitrary labels,
environment, commands, health output and other unselected fields. Normalize user
configuration to categories without retaining the supplied username. Preserve
missing/null facts as unknown. Direct findings describe configured privileged mode,
root user, selected host namespace settings, added powerful capabilities and
management/sensitive bind mounts. They remain OPEN advisory detections, not
confirmed physical access or breakout results.

Associations use existing relation kinds with explicit configuration semantics.
RELATED_TO edges can be explicitly selected by the existing reachability consumer;
without separately supplied admissible assessments they remain UNKNOWN. The
importer issues no reachability claims, policy grant, daemon request or remediation.

## Consequences

The profile can correlate with previously imported image config identities and
survives owner workspace relocation. Exact replay is a no-op; existing finding
triage survives refreshed evidence. Malformed selected fields, duplicate JSON
keys, truncated/failed sources, forged provenance, missing manifests, foreign
workspaces and resource excess fail before any model mutation.

This advances both tasks without completing daemon discovery, socket exposure
discovery, arbitrary runtime/API versions, live Docker collection or physical
security acceptance. It adds no dependency, CLI command or canonical schema.

Docker field semantics were checked against the primary
[Engine API v1.51 reference](https://docs.docker.com/reference/api/engine/version/v1.51/)
and [container inspect CLI reference](https://docs.docker.com/reference/cli/docker/inspect/).
The profile selects these fields rather than promising complete API conformance.
