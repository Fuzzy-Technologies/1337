# ADR 0011: Domain profiles for robotics and cyber-physical systems

## Status

Accepted — 2026-09-12

## Context

ADR 0010 centers 1337 on one durable Security Object Model enriched by native
discovery, tools, integrations, evidence, and workflow lenses.

That model must not become implicitly limited to conventional Web, host, cloud, or
container targets. Robotics and other cyber-physical systems combine software supply
chains, embedded/runtime components, identities, networks, middleware, sensors,
controllers, actuators, update channels, and physical effects.

Those systems need security analysis across the same concerns already present in
1337:

- attack surface and reachable paths;
- evidence and incident reconstruction;
- source, dependencies, firmware, images, and deployment/update trust;
- authorized validation, telemetry, controls, and retest.

Treating robotics as a separate product or database would duplicate the same identity,
evidence, relation, provenance, storage, query, and policy semantics.

## Decision

### 1. Robotics/CPS is a domain profile, not a workflow lens

Robotics and cyber-physical systems extend the target/domain vocabulary of 1337.

They do not add a fifth first-class workflow lens.

The same initial lenses apply:

```text
Pentest
DFIR
DevSecOps
Purple Team
```

A robotics target may therefore be examined through any of those lenses without
changing the underlying workspace state.

### 2. Domain profiles extend the same Security Object Model

A domain profile may introduce typed domain objects and relations when the generic
model is not expressive enough.

Candidate robotics/CPS object families include:

```text
Robot           Fleet             ComputeUnit
Controller      Firmware          Bootloader
UpdateArtifact  RobotNode         Topic
Service         Action            MiddlewareDomain
SecurityEnclave Sensor            Actuator
SafetyController
FieldBus        NetworkInterface  TeleoperationChannel
OTAChannel      ModelArtifact     CalibrationArtifact
```

The exact schema is deferred to implementation work.

Domain objects must reuse canonical 1337 boundaries for identity, provenance,
Observation, Evidence, Finding, Relation, storage, querying, scope, and policy.

A robotics-specific truth store is not permitted.

### 3. Cyber-to-physical paths are first-class graph use cases

1337 should be able to represent evidence-backed paths that cross software,
identity, network, middleware, control, and physical boundaries.

An illustrative path is:

```text
Repository
→ Dependency / Package
→ CI / Build
→ Firmware / Container / Update Artifact
→ Robot Compute Unit
→ Robot Middleware Node
→ Topic / Service / Control Channel
→ Controller
→ Actuator
→ Physical Effect
```

A physical effect is not itself proof of exploitability. Each meaningful relation
must preserve its evidence, provenance, confidence/state, and authorization context.

### 4. Robotics tooling remains modular and optional

Potential capability providers include:

- ROS 2 / DDS discovery and security-state inspection;
- firmware, image, package, and SBOM analysis;
- software-supply-chain and OTA/update-chain inspection;
- robot/fleet network discovery;
- certificate, identity, and permission inspection;
- vendor SDK or fleet-management integrations;
- imported telemetry and forensic artifacts.

Provider-specific data must be normalized into shared Security Objects,
observations, evidence, findings, and relations.

No robotics middleware, vendor SDK, or heavy scanner becomes a mandatory Core
dependency.

### 5. Physical validation is safe-by-default and bounded

Real-world actuator control must never be a default validation mechanism.

Development, CI, and public demonstrations should use repository-owned synthetic or
simulated systems with bounded, reversible effects.

Any future operation against a physical system must remain:

- explicitly authorized;
- inside Scope/Policy;
- bounded by impact controls;
- observable and attributable;
- fail-safe by design.

### 6. Milestone boundary

This decision does not expand M1.

M2 only preserves the extension path: the Security Object Model and typed relation
mechanism must not be hard-coded around Web, Host, or cloud-only object families.

The first robotics/CPS domain implementation belongs to later discovery and
attack-path work, currently tracked in M4 under Feature #174.

## Consequences

- the core SOM must remain extensible without parallel domain databases;
- robotics/CPS can reuse existing evidence, graph, lens, storage, and policy
  mechanisms;
- software-supply-chain state can be connected to runtime/control state in one
  workspace;
- future robot-security providers remain optional modules;
- M4 may include a synthetic ROS 2/CPS lab proving a software-to-physical path
  without real hardware;
- other future domains such as OT/ICS, automotive, drones, or specialized embedded
  systems may use the same domain-profile mechanism when justified.

## Relationship to previous ADRs

- ADR 0005 remains the Scope and model-agnostic knowledge-layer direction.
- ADR 0008 remains the durable execution/state/evidence Core boundary.
- ADR 0009 remains the shared-state workflow-lens model.
- ADR 0010 remains the live Security Object Model and modular-tooling architecture.

This ADR extends those decisions with an explicit domain-profile mechanism and the
first named cyber-physical target domain.

## Architectural invariant

> **One Security Object Model. Multiple lenses. Multiple domains. No competing truth.**

