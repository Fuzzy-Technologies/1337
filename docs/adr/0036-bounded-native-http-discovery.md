# ADR 0036: Bounded native HTTP discovery

Status: Accepted for implementation; API and records are Experimental version 1.

## Decision

Task #267 supplies the first native SAFE discovery provider for Quick Scan #38.
The provider accepts a finite tuple of explicitly approved literal-IP HTTP(S)
URL targets. Each target requires current granted scope consent, exact URL
registration/membership and approved literal-IP destination membership. A trusted
first-party worker runs through the existing policy and governed local executor;
scope is reread at the executor's final launch boundary. No separate model,
evidence, authorization or job store is introduced.
Broadcast, scoped IPv6 and IPv4-mapped IPv6 aliases are unsupported, preserving
literal destination semantics without weakening existing exclusion rules.

The initial probe sends one GET to the exact supplied endpoint. It performs no
DNS resolution, follows no redirects, sends no credentials or cookies, and
rejects query-bearing URLs to avoid retaining token parameters. It
does not retain response headers, bodies, cookies or server-generated error text.
HTTPS uses ordinary certificate verification against the supplied literal IP;
certificate verification cannot be disabled by a target or request parameter.
A valid bounded HTTP response status proves an observed host, TCP port, HTTP(S)
service and exact endpoint. A redirect or HTTP error status is an observation,
not an instruction to fetch another endpoint or a vulnerability.

The worker emits only strict schema-v1 JSON containing the approved URL, observed
literal peer IP, port, scheme and integer status. Failure records contain a fixed
error code only. Before storing bytes, the parent rejects extra fields, mismatched
destinations, unsupported versions, duplicate JSON keys and oversized output.
Verified evidence precedes canonical model persistence; each saved incremental
delta then enters the existing job event stream. Failed probes do not create
successful service facts. Earlier verified updates survive later failure.

## Experimental producer API

`NativeDiscoveryProvider(workspace_root, targets, scope_id, policy, *, limits,
clock)` implements `JobProvider.Run(context)`. The consumer owns workspace,
approved scope and initial model creation. `DiscoveryLimits` caps endpoints,
per-probe timeout, interval and total runtime. Defaults are eight endpoints,
three seconds per request, 0.2 seconds between requests and thirty seconds total.
Hard maxima are sixteen endpoints, ten seconds per request and sixty seconds
total. Execution is sequential; no implicit target expansion occurs.

`Descriptor` identifies `native.http`, version `1`, capability
`http.endpoint-discovery`, maximum impact `SAFE`, with no privileged requirement.
Preparation and health inspection do not issue authorization. The nominal first
observed-update budget is the request timeout plus one second of worker startup,
bounded by total timeout; operating-system scheduling is not a real-time promise.
The actual elapsed measurement belongs to the consuming Quick Scan result.

Host identities use canonical literal IPs. TCP port and service keys reuse the
model's established `host:<address>/tcp/<port>` binding convention; endpoint keys
use canonical exact URLs. Repeated acquisition adds attributable observation
history without duplicating logical objects or relations. Replaying the same
result/provenance is a no-op.

## Failure and limits

Authority denial, worker failure, malformed output, output overflow, timeout,
cancellation and storage failure remain distinct job outcomes. Worker cleanup is
owned by the governed executor, including cancellation. The provider stops after
a failed endpoint; it never reports a completed scan over a truncated target list.
Runtime, input/output, HTTP header and event budgets are finite. The executor is
an owned subprocess boundary, not an OS network or memory sandbox.

DNS discovery, arbitrary ports, crawling, redirect replay, sessions, authenticated
requests, response-body analysis and vulnerability checks are separate tasks.
PASSIVE input registration is not presented as observed network discovery.

## Acceptance evidence

Deterministic unit/contract tests exercise unsafe inputs and record validation.
Owned localhost HTTP fixtures exercise actual worker execution, granted and
denied policy, incremental evidence/model events, reopen/repeat identity,
redirect containment, failure, cancellation and timeout. No Internet target or
browser is needed. The repository's locked full gate and per-module branch
coverage contract apply to all added production modules.
