# ADR 0024: Bounded optional Nmap adapter without scan authority

## Status

Accepted — 2026-10-05

## Context

Task #35 under Tool Adapter SDK feature #29 needs the first concrete network-tool
producer for the provider-neutral adapter, executor, and evidence contracts.
Scope management, impact policy, Security Object Model persistence, and arbitrary
tool option passthrough remain separate work. Installing a scanner or observing
its health must not implicitly grant permission to scan.

## Decision

Introduce the Experimental `fuzzy1337.adapters.nmap.NmapAdapter`, using the
unchanged existing SDK envelopes. Nmap remains an optional operator-installed
executable under its own terms; 1337 neither bundles it nor modifies dependencies
or product licensing. Base SDK imports do not load the concrete adapter.

`CheckHealth` has one narrow local-process exception: run only `--version`, with
fixed elapsed/capture budgets and truthful unavailable/degraded states. No target
is supplied and no scan authorization is constructed. The selected executable
is trusted operator configuration, not caller-controlled request parameters.

Preparation is pure. Initial capabilities are `network.tcp-connect` and
`network.service-discovery`, both with explicitly approved `STANDARD` impact.
One literal address, an explicit bounded unique TCP port set, and a positive
bounded timeout are required. Deterministic shell-free argv disables DNS and
host discovery, forces unprivileged TCP connect, and sends XML to stdout. Service
discovery opts into light version probes. Raw flags, DNS/CIDR/range expansion,
credentials, NSE, UDP, OS detection, and public scan CLI are absent.

Only an existing governed executor supplied with exact caller-issued
`ExecutionAuthorization` can run the prepared target invocation. Callers store
stdout/stderr through the immutable Evidence Store with actual collection and
execution provenance before normalization. The adapter reads one explicit stdout
reference and verifies its digest/length; it neither discovers files nor stores
evidence itself.

Parsing is bounded UTF-8 XML. Nmap's inert doctype may be removed; active DTDs,
entities, external declarations, and unbounded structures fail closed. XML host
and TCP port facts must match the exact finite request. Successful execution
requires a successful XML completion marker; invalid successful reports fail
explicitly. Partial unsuccessful stdout emits only an incomplete diagnostic,
while preserving raw evidence and terminal execution truth.

Normalized host/port/service observations and enrichment proposals remain
provider metadata. References are opaque and deterministic, and a future model
consumer explicitly maps them to model identities. No target scan directly
mutates model state. Open ports are observations, not vulnerability findings;
grouped omitted ports do not imply fabricated individual observations.

## Consequences

- Existing adapter/executor/evidence contracts have a concrete optional consumer
  without a schema change or tool installation at Workbench startup.
- Scope and policy remain upstream authorities; this adapter does not complete
  their roadmap tasks or advertise a generally authorized scanning command.
- Unit tests directly cover argument/profile guards, parser limits, evidence
  integrity, and failed/timed-out/cancelled execution preservation.
- An owned synthetic executable proves the complete real executor/evidence/parser
  pipeline with explicitly synthetic provenance, separately from genuine Nmap.
- An optional two-port loopback oracle verifies genuine installed Nmap. Tool
  absence is an explicit skip, never a claim of real scanner evidence.
- The finite XML profile is narrower than Nmap's full extensible DTD. Additional
  protocols, target kinds, intrusive options, or orchestration require their own
  approved contracts and tests.
