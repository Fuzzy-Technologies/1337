# ADR 0037: Bounded SAFE Quick Scan through product commands

- Status: Accepted
- Related work: #38, #39, #40, #267

## Decision

Expose a foreground `1337 scan quick` workflow over the existing owned job,
governed native HTTP discovery, evidence, scope, workspace and model boundaries.
The command accepts explicit literal-IP HTTP(S) endpoints, a workspace-local
scope, the recorded owning operator and finite request/rate/total bounds. Creating
a workspace, registering a target or discovering a service grants no authority.

Workspace and scope commands record explicit URL/IP allow and exclusion rules.
Consent is unknown unless the operator supplies an explicit grant flag, authority,
consent-record reference and validity interval. A Quick Scan additionally requires
`--approve-safe-http`, permitting only the native SAFE HTTP endpoint capability.
No CLI path issues implicit STANDARD or higher-impact confirmation. Native
discovery reopens current scope and revalidates policy immediately before every
exact governed process launch; the coordinator does not implement another probe.
This product workflow additionally binds its declared owner to the current consent
actor through the native provider's explicit fresh-context restriction hook, both
before every new grant and at final launch. The generic SDK does not equate every
job owner with its scope's consent attester automatically.

Starting the owned job immediately publishes queued status. Versioned ordered
job events stream while discovery proceeds. The command measures the time to the
first persisted model delta and reports the producer's declared first-update
budget alongside the bounded total runtime. Failed, cancelled or partial runs
retain their actual terminal state and all already published evidence/model data.

The workflow wrapper persists workspace job, scope, object and evidence references
before the job seals its terminal state. Reopen reads the existing authoritative
model and independently verifies retained evidence, without contacting targets.
Repeated runs retain one logical object identity while adding actual provenance.
JSON summary and optional JSON-line event output reuse the owned job contracts.
Prior retained acquisitions are verified before new work and again before saving
terminal metadata, so a new run cannot claim durable success with broken old evidence.

## Boundaries

The initial workflow performs endpoint discovery only. It does not enumerate
networks, resolve DNS names, follow redirects, collect response bodies or cookies,
execute vulnerability checks or claim optional third-party enrichment. The
interactive shell can invoke the same foreground commands and display live
updates; a full concurrent split-pane TUI remains separate work.

Local authority and consent references are operator-recorded metadata, not an
identity provider. The CLI does not load credentials or secret tokens. Request
inputs remain data and cannot widen approved scope. Job/event state remains
in-process; durable model and raw evidence are independently reopenable.

## Validation

Owned-localhost E2E exercises workspace creation, explicit consent, real governed
native discovery, live model/evidence events, persisted references, clean reopen
and repeat-run identity. Denied, expired, excluded, missing capability approval,
provider error, timeout and cancellation paths must preserve truthful machine
statuses and avoid unauthorized target contact. Deterministic unit and contract
tests cover input bounds, serialization and storage failures.
