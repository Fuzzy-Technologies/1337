# ADR 0021: Pinned optional external target pack

## Status

Accepted — 2026-10-04

## Context

Task #95 adds realistic black-box regression targets beside the deterministic
first-party micro-targets. Upstream vulnerable applications need immutable
provenance and fixture-owned isolation; a mutable image tag or public demo
cannot provide reproducible test evidence. Their challenge lists are not a
complete positive/negative scanner oracle.

## Decision

The initial executable pack contains OWASP Juice Shop 20.2.0. Its official
`bkimminich/juice-shop:v20.2.0` image is pinned by the multi-platform OCI index
digest as well as its readable release tag. The pack manifest records the
upstream source revision, official release and registry URLs, supported platform
manifest digests, and bounded resource/lifecycle budgets.

Keep external targets in a separate Compose definition and a unique project
owned by one pytest fixture. An explicit `FUZZY1337_EXTERNAL_TARGETS=juice-shop`
opt-in permits the fixture to pull and start that image. Ordinary repository
checks do not download or start external applications. An enabled pack fails
when Docker is unavailable; its required CI smoke must actually execute.

The container has one internal network, no published host ports, no host mounts,
no added capabilities, and no privilege escalation.
Its writable container layer supports upstream SQLite initialization and is
removed on teardown. CPU, memory, PID count, pull, startup, health requests,
diagnostic collection, and cleanup have explicit limits. HTTP requests run through
bounded `docker compose exec -T` using the image's Node executable and a first-party
`node:http` script. Its fixed destination is container loopback `127.0.0.1:3000`;
it does not resolve an input URL, follow redirects, or honor proxies.

Real Docker CI showed that an internal-only container became healthy with the
pinned image but had no published port. [Docker Engine v28.3.3 skips port mappings
for internal networks](https://github.com/moby/moby/blob/v28.3.3/daemon/network.go#L940-L944),
and [Compose documents their lack of a host interface and default gateway](https://docs.docker.com/compose/how-tos/networking/#internal-networks).
The fixture therefore probes inside the container rather than adding a network
that would permit outbound access. The original observed Compose fixture remains
historical evidence; the no-port fixture is explicitly derived from that output.

The Node child owns an absolute deadline at 75% of the parent request budget,
destroys its request and response on expiry, and returns exit 124 with bounded
received headers/body preserved as JSON. The parent records that as a timed-out
HTTP observation without rewriting the raw command outcome. Response body text
uses explicit UTF-8 decoding. Request duration includes Docker exec launch
latency, and the parent subprocess deadline and container teardown bound failures.

Before yielding the target, verify the application version endpoint, configured
image digest, running image configuration ID, OS/architecture, repository digest,
and selected platform manifest from the pinned registry index. Preserve raw
commands, HTTP responses, timeout/failure states, duration, and provenance under
ignored `functional-evidence/external-juice-shop/`. Cleanup runs after startup
failures and test failures; unsuccessful cleanup is an error, not a successful
smoke result.

Regression reports reuse ADR 0018 with an incomplete oracle. They record the
actual contract-probe observations and generated capability matrix while
withholding TP/FP/FN/TN and accuracy. This smoke proves the pinned target and
report pipeline, not production scanner effectiveness.

## Candidate evaluation

| Candidate        | Decision in this pack | Reason                                                          |
| ---------------- | --------------------- | --------------------------------------------------------------- |
| OWASP Juice Shop | Execute               | One official image; bounded version and HTTP regression probes  |
| OWASP WebGoat    | Evaluated, deferred   | Java teaching lessons need separate authenticated scenarios     |
| OWASP crAPI      | Evaluated, deferred   | Multiple services and data stores need a full isolated topology |
| OWASP Benchmark  | Separate evaluation   | Finite expected-results CSV can support a dedicated oracle      |

WebGoat and crAPI remain valid future packs; this decision does not import their
mutable default Compose definitions or claim their scenarios have executed.
BenchmarkJava publishes `expectedresults-1.2.csv` with testcase, category,
real-vulnerability, and CWE fields. A future accuracy pack must pin both source
and expected results, validate their mapping to scanner output and applicability,
and preserve its GPL-2.0 licensing boundary. Its release name alone is
insufficient because upstream recommends the current repository head.

## Primary provenance

- [Juice Shop official release](https://github.com/juice-shop/juice-shop/releases/tag/v20.2.0)
- [Juice Shop official Docker manifest](https://hub.docker.com/layers/bkimminich/juice-shop/v20.2.0/images/sha256-7f7539921b046863f2fc48b84061f957e50b3aa4652ae0a62014a2fc25654d0b)
- [WebGoat upstream Docker instructions](https://github.com/WebGoat/WebGoat#1-run-using-docker)
- [crAPI upstream topology](https://github.com/OWASP/crAPI/blob/main/deploy/docker/docker-compose.yml)
- [BenchmarkJava upstream project](https://github.com/OWASP-Benchmark/BenchmarkJava)

## Consequences

The pack adds test infrastructure and an explicitly enabled Docker CI smoke.
It adds no product command, scanner, runtime dependency, or default external
target access. New applications require their own immutable provenance,
resource budgets, health contracts, and actual lifecycle evidence before they
join the executable inventory.
