# ADR 0009: Operator profiles and orthogonal execution dimensions

## Status

Accepted — 2026-09-11

## Context

1337 is intended to serve several security workflows without becoming several
different products.

The same Core should support, among others:

- penetration testing and hands-on security assessment;
- DevSecOps / AppSec checks embedded into CI/CD;
- SOC / exposure-management workflows with recurring scans, change detection,
  validation, and retesting after remediation;
- DFIR, incident response, internal investigations, and evidence-led cybercrime
  investigation workflows;
- Red / Blue / Purple collaboration over one shared security state.

These users need different defaults, views, triggers, outputs, and preferred
capabilities. They must not receive different underlying security truth.

A single mode enum such as:

```text
mode = PENTEST | SOC | DEVSECOPS
```

would mix several independent concerns:

- operator intent and workflow;
- allowed execution impact;
- target families and scan surface;
- trigger/scheduling context;
- output/reporting preferences.

That coupling would create exceptions quickly. A DevSecOps job may need an ACTIVE
API check in staging. A penetration tester may be constrained to SAFE actions. A SOC
workflow may scan only an external perimeter today and Kubernetes tomorrow.

## Decision

1337 will model operator/workflow profiles as **presets over one shared Core**, while
keeping execution impact and target selection as orthogonal dimensions.

The canonical model is:

```text
                 one durable 1337 security state
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
        workflow profile  impact profile  target profile
              │               │               │
              └───────────────┼───────────────┘
                              ▼
                    governed execution plan
```

Profiles configure defaults and presentation. They do not create separate security
databases or alternate domain models.

## Dimension 1: workflow profile

A workflow profile expresses **what the operator is trying to accomplish**.

Initial profile families are expected to include:

```text
pentest
devsecops
soc
dfir
purple
```

Additional Red/Blue/AppSec-specific lenses may exist where useful, but they should
remain presets/views over the same workspace, evidence, findings, and graph.

A workflow profile may provide defaults for:

- preferred capabilities and commands;
- UI/TUI/Web lens and information density;
- default target families;
- default impact ceiling;
- trigger style;
- scheduling/retest behavior;
- output/report formats;
- prioritization and next-action suggestions.

A workflow profile **must not** silently expand authorized scope, grant new
privileges, or raise execution impact beyond explicit policy.

### DevSecOps / AppSec profile

Typical defaults:

```text
trigger:
  pull request / push / pipeline / build

targets:
  source
  dependencies
  container image / SBOM
  Dockerfile / IaC
  API / OpenAPI
  Kubernetes manifests
  optional approved runtime

impact:
  PASSIVE / SAFE by default

outputs:
  SARIF
  JUnit
  JSON
  CI annotations
  deterministic exit codes
  reachable-risk gate
```

Primary question:

> Should this build or deployment pass the security gate, and what reachable risk
> would it introduce?

This profile aligns with CI/CD security UX and target profiles tracked in #70, #75,
#138, #143, #148, #158, and #159.

### SOC / exposure profile

Typical defaults:

```text
trigger:
  scheduled / recurring / change-driven

targets:
  external attack surface
  services and APIs
  container runtime
  Kubernetes
  identities and controls

impact:
  PASSIVE / SAFE by default

outputs:
  new exposure
  security-state diff
  attack-path diff
  stale evidence
  remediation priority
  retest result
```

Primary questions:

> What changed since the previous observation?

> Which new attack path became reachable?

> Did the remediation actually remove the path?

Recurring observation, evidence freshness, change detection, and retesting are
workflow concerns; the resulting objects and graph remain ordinary 1337 state.

### DFIR / investigations profile

The DFIR profile is for incident response, digital forensics, internal
investigations, CERT/CSIRT work, forensic consulting, and evidence-led cybercrime
investigations.

Typical defaults:

```text
trigger:
  incident / case intake / manual acquisition / evidence import

targets:
  logs and telemetry
  hosts and forensic artifacts
  identities
  network evidence
  cloud resources
  containers and Kubernetes
  external files / case evidence

impact:
  PASSIVE / read-only by default

focus:
  evidence acquisition and preservation
  integrity and provenance
  chain of custody
  timestamp and timezone normalization
  IOC / entity correlation
  incident timeline
  observed attack paths
  investigator-visible audit history

outputs:
  case / investigation record
  evidence manifest
  integrity hashes
  acquisition and custody history
  normalized timeline
  observed attack graph
  exportable evidence bundle and report
```

Primary questions:

> What actually happened, in what order, and what evidence supports each step?

> Can another investigator reproduce how this conclusion was reached from the
> preserved evidence?

The DFIR profile extends the same evidence-first architecture used by assessment and
SOC workflows. It does not create a separate forensic truth store.

For M8, the evidence model should be able to represent concepts such as:

```text
Case / Investigation
        ↓
Evidence Item / Artifact
        ↓
Acquisition
        ↓
Custody Event(s)
        ↓
Observation
        ↓
Timeline Event
        ↓
Observed Attack Path
        ↓
Report / Evidence Bundle
```

At minimum, preserved evidence should be able to carry:

- stable evidence identifier;
- original source and acquisition method;
- acquisition timestamp and timezone;
- collector / examiner identity;
- cryptographic integrity hash where applicable;
- original artifact reference and derived/normalized representations;
- custody / transfer history;
- parser/tool/version provenance;
- confidence and interpretation boundary;
- links to related security objects, timeline events, and observed attack paths.

**Evidence and interpretation must remain distinct.** Analyst notes, model output,
correlation, and hypotheses may be useful, but they must not silently replace source
evidence or its provenance.

### Jurisdiction and legal-use boundary

Courts, law-enforcement procedures, evidentiary rules, and formal chain-of-custody
requirements vary by jurisdiction.

1337 must therefore avoid hard-coding one country's procedural law into the Core and
must not claim that a stored artifact is automatically admissible in court.

Instead, the platform should preserve broadly reusable factual primitives — source,
time, collector, integrity, lineage, custody history, tool provenance, and audit
events — so organizations, forensic experts, investigators, and future
jurisdiction-specific integrations can apply the required local procedure.

This creates a path for 1337 Trace to be useful not only to SOC teams, but also to:

- incident-response teams;
- forensic consultants and laboratories;
- CERT / CSIRT teams;
- internal corporate investigations;
- cybercrime investigators;
- law-enforcement or judicial-forensic workflows where organizations choose to
  adopt 1337 and map its evidence records to their local process.

The architectural goal is **forensically defensible provenance and reproducibility**,
not a universal legal-admissibility guarantee.

### Pentest profile

Typical defaults:

```text
trigger:
  interactive operator session

targets:
  any explicitly authorized target family

impact:
  SAFE / STANDARD initially
  ACTIVE / INTRUSIVE only when explicitly authorized

focus:
  reconnaissance
  browser and API discovery
  pivots
  identities and credentials
  attack paths
  evidence drill-down
  authorized validation
```

Primary questions:

> What can I reach next?

> Which path is confirmed, inferred, or blocked?

> What bounded validation can prove or reject this edge?

The pentest profile should preserve direct access to familiar security tools while
still producing structured evidence and durable graph state.

### Purple profile

The Purple profile emphasizes comparison and state transition:

```text
before validation
        ↓
authorized action
        ↓
new evidence
        ↓
reachability / graph recomputation
        ↓
control or remediation change
        ↓
retest
        ↓
after state
```

It uses the same findings and evidence as Red and Blue views rather than maintaining
a separate exercise state.

## Dimension 2: impact profile

Impact answers **how aggressive execution is allowed to be**.

The canonical impact levels are those tracked in #32:

```text
PASSIVE
SAFE
STANDARD
ACTIVE
INTRUSIVE
```

Impact is independent of workflow.

Examples:

```text
workflow=devsecops + impact=SAFE
workflow=devsecops + impact=ACTIVE      # approved staging test

workflow=pentest   + impact=SAFE        # restricted assessment
workflow=pentest   + impact=ACTIVE      # explicit authorization

workflow=soc       + impact=PASSIVE     # observation only
workflow=soc       + impact=SAFE        # scheduled low-impact verification
```

A workflow profile may recommend an impact default or ceiling, but policy remains
authoritative.

## Dimension 3: target / scan profile

Target profile answers **what class of security surface is being evaluated**.

Target families may include:

```text
web
api
source
dependencies
supply-chain
container-image
container-runtime
kubernetes-manifest
kubernetes-runtime
external-surface
full-scope
```

Target profiles are composable rather than mutually exclusive.

Examples:

```text
workflow=devsecops
impact=SAFE
targets=image,api,kubernetes-manifest

workflow=soc
impact=PASSIVE
targets=external-surface,api,kubernetes-runtime

workflow=pentest
impact=ACTIVE
targets=web,api,container-runtime
```

The target dimension maps to capabilities and scanners; it does not fork the domain
model.

## Trigger and scheduling context

Trigger style is intentionally not a fourth security-state model.

It is execution context attached to a workflow/job:

```text
interactive
manual
CI event
scheduled
recurring
change-driven
API-triggered
```

A scheduled SOC scan and a CI-triggered DevSecOps scan may invoke the same
capability against different scopes and policies.

Scheduling must therefore reuse normal Jobs, Scope, Policy, Evidence, and audit
contracts rather than creating a separate scheduler-specific result model.

## Shared-state invariant

Operator lenses and profiles must never create competing truth.

Conceptually:

```text
                     SAME SECURITY STATE

        ┌─────────────┬─────────────┬─────────────┐
        ▼             ▼             ▼             ▼
     Pentest          SOC          DFIR        DevSecOps
      lens            lens          lens          lens

  pivots / paths   exposure/diff  timeline /    build/deploy
  validation       controls/retest evidence      gates/artifacts
```

The user interface may prioritize different objects, but:

- an Asset remains the same Asset;
- Evidence retains the same provenance;
- a Finding remains the same Finding;
- a ReachabilityEdge retains the same state;
- an AttackPath is not duplicated per persona;
- remediation and validation update the shared graph.

## Configuration model

The eventual configuration surface should support explicit composition rather than
hidden mode behavior.

Illustrative configuration:

```yaml
profile: devsecops
impact: SAFE
targets:
  - container-image
  - api
  - kubernetes-manifest

trigger:
  type: ci

outputs:
  - sarif
  - junit
  - json
```

and:

```yaml
profile: soc
impact: PASSIVE
targets:
  - external-surface
  - api
  - kubernetes-runtime

trigger:
  type: scheduled
  schedule: "0 3 * * *"

retest_after_remediation: true
```

and:

```yaml
profile: dfir
impact: PASSIVE
targets:
  - logs
  - hosts
  - identities
  - container-runtime

trigger:
  type: incident

evidence:
  preserve_originals: true
  hash: true
  record_custody_events: true

outputs:
  - timeline
  - evidence-bundle
  - observed-attack-paths
```

The exact file/CLI syntax is not decided by this ADR. The architectural requirement
is that these concerns remain separately representable and composable.

## CLI and UI consequence

A future CLI may expose profiles directly, for example:

```text
1337 --profile pentest
1337 --profile devsecops
1337 --profile soc
1337 --profile dfir
1337 --profile purple
```

This syntax is illustrative, not a current CLI contract.

The selected profile may:

- choose a default workspace lens;
- surface relevant commands first;
- preselect common target profiles;
- suggest an impact ceiling;
- choose report/output defaults.

The operator must still be able to inspect the resolved execution plan before
high-impact actions.

## AI-agent consequence

AI agents consume the same resolved profile, impact, scope, targets, capabilities,
and security state as human operators.

An agent must not infer a more permissive execution mode from persona labels such
as "pentest" or "red".

For AI execution:

```text
workflow profile
        +
impact profile
        +
target profile
        +
identity / scope / policy
        ↓
resolved capabilities
        ↓
governed execution
        ↓
evidence / state update
```

This keeps model choice orthogonal to authorization and execution safety.

## Roadmap relationship

This ADR unifies several existing roadmap directions without changing their
milestone ownership:

- #32 — impact profiles and policy enforcement;
- #70 / #75 / #159 — DevSecOps and CI/CD workflows;
- #79 / #81 — Red / Blue / Purple / DevSecOps lenses;
- #138 — image and supply-chain scanning;
- #143 — API security scanning;
- #148 — container and Kubernetes runtime security;
- #153 — synthetic user journeys and traffic generation;
- #160 / #161 — bounded runtime privilege validation;
- #83 / #85 — DFIR evidence ingestion and canonical artifact parsing;
- #84 / #86 — incident timelines, observed attack paths, and investigation reports.

The SOC/exposure workflow is architecturally defined here even where recurring
scheduling/change-detection implementation is still future roadmap work.

The DFIR/investigation profile is anchored in M8 / 1337 Trace. M8 should extend the
shared evidence model with investigation/case, integrity, acquisition, custody, and
timeline semantics without forking the Core into a separate forensic database.

## Alternatives considered

### One hard mode enum

Rejected. It couples operator intent, target selection, impact, and outputs and
cannot express common combinations cleanly.

### Separate products or databases per persona

Rejected. It would duplicate evidence and findings, fragment attack-path reasoning,
and make Red/Blue/DevSecOps results disagree about the same environment.

### UI-only personas

Rejected as insufficient. The view is persona-specific, but workflow defaults,
triggers, outputs, and capability selection also need an explicit machine-readable
profile.

### Let the AI model choose the mode dynamically

Rejected. Operator intent may inform model reasoning, but scope, impact, target
selection, and execution policy must remain explicit and auditable platform state.

## Relationship to previous ADRs

This ADR extends ADR 0005 and ADR 0008.

- ADR 0005 established shared scope and AI-neutral security knowledge.
- ADR 0008 established one durable execution/state/evidence platform for human,
  automation, CI/CD, and AI clients.
- ADR 0009 defines how different operator workflows compose over that same platform
  without forking the Core or authorization model.

## Architectural invariant

> **Profiles change the workflow and view, not the underlying security truth**

Any future persona, scanner mode, CI preset, or SOC workflow should be representable
as composition over shared state, explicit impact, explicit targets, scope, policy,
and capabilities.
