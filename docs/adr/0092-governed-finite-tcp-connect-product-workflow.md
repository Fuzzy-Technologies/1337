# ADR 0092: Governed finite TCP-connect product workflow

## Status

Accepted — 2026-10-23

## Context

The optional Nmap adapter accepted under Task #35 prepares finite commands and
normalizes original evidence, but does not own scan authority, jobs, canonical
model persistence, or a product command. Task #40 requires the complete governed
model-centered path, including durable evidence and reopening the workspace.
This decision advances that acceptance without reopening the completed adapter
task or completing the broader MVP.

## Decision

Introduce an Experimental `fuzzy1337.portscan` SDK with `PlanPortScan` and
`RunPortScan`, and the product command `1337 scan ports`. Both use only the
existing `native.nmap` / `network.tcp-connect` capability. The provider remains
an optional operator-installed, explicitly selected trusted absolute executable.
Construction does not install or discover scanners at Workbench startup. A
bounded local `--version` observation grants no target execution authority.

Select exactly one canonical literal IP, 1–1024 explicit unique TCP ports, and
the adapter's bounded integer host/executor timeout. The owning job adds a fixed
five-second cleanup/custody/persistence margin, following the existing Nuclei
workflow; the approved invocation and process timeout remain unchanged. No
default port set, automatic target registration, DNS/CIDR expansion, credentials,
service probes, NSE, UDP, OS
detection, arbitrary flags, or raw passthrough is introduced. Existing adapter
validation and fixed unprivileged TCP-connect argv remain authoritative.

Planning reads current workspace/model/evidence, scope, recorded consent actor,
and an explicit typed policy. It presents the complete exact invocation and
STANDARD confirmation intent. Execution requires the matching confirmation and
current explicit capability permission; neither installation nor planning adds
permissions. The actual invocation address is derived from the same canonical
IP used as the policy target and sole actual destination. Current scope is
IP-based; the explicit port set is bound by the exact invocation and approval,
not represented as a new port-granular scope rule.

Compose the existing `PolicyEngine`, `GovernedLocalExecutor`, `LocalExecutionJob`,
`ScanJob`, `LocalEvidenceStore`, and model/workspace stores. Recompute the exact
selected invocation and reread owner, consent, scope, and policy immediately
before launch and before canonical model Save, with the same unexpired launch
grant. Check cancellation before persistence and use one model CAS transition.
No separate authorization, execution, evidence, or object store is introduced.

Retain original stdout/stderr, invocation digest, observed provider version,
terminal process facts, collection times, and job/workspace references before
success. Failed, timed-out, cancelled, oversized, malformed, or persistence-denied
runs preserve available original evidence and truthful terminal failure; they do
not become successful canonical enrichment. Omitted/grouped ports are not expanded
into invented individual results. XML completion alone is not proof that every
requested port was assessed.

Map the adapter's opaque host subject to the existing canonical Host address.
Map each reported TCP port to `host:<address>/tcp/<number>` and each reported
Service to that same port natural key, matching native discovery. Apply the
existing typed enrichment envelopes and provenance through the model owner.
Repeated scans preserve logical object identities and unrelated data. Service
metadata is admitted only when reported; an open port is never a Finding.

## Acceptance

- Focused deterministic SDK/CLI tests exercise planning, exact confirmation,
  current authority at launch and Save, canonical mapping, original custody,
  failure truth, repeated identities, and offline/relocated reopen.
- Existing executor/parser tests remain owners of their contracts; new tests
  cover this composition rather than duplicating executor lifecycle suites.
- Genuine product acceptance uses only two pytest-owned sockets on
  `127.0.0.1`: listening/open and bound without listening/closed. Require the
  listening port to be explicitly open and the other never falsely open; retain
  explicit closed or faithful grouped/unassessed output as actually reported.
  Original evidence, tool provenance, the machine-readable oracle, zero
  Findings, and reopen after target shutdown must be retained. Synthetic output
  is labeled.
- A dedicated genuine-provider CI lane must fail on missing/incompatible Nmap,
  not turn an optional skip into acceptance. Pin the official Nmap 7.992 source
  archive and its published SHA256
  `0c12660eddbf7eabeff6996cb0c044a4eadf2bb0c6fbcb340d6cf72b1caee402`.
  Build/install into a runner-owned prefix, verify the actual version, and keep
  archive hash/build/version provenance alongside functional evidence. Nmap
  remains separate optional software under its own distribution terms.
- Per-commit checks stay small, deterministic, and process-parallel where
  independent; full shared integration CI runs at the final review checkpoint.

Official provider references checked on 2026-10-23:

- [Official download and distribution terms](https://nmap.org/download.html)
- [Pinned source archive](https://nmap.org/dist/nmap-7.992.tar.bz2)
- [Official archive hashes](https://nmap.org/dist/sigs/nmap-7.992.tar.bz2.digest.txt)
- [Integrity verification](https://nmap.org/book/install.html#inst-integrity)
- [Source installation and an unprivileged prefix](https://nmap.org/book/inst-source.html)

## Consequences

This supplies one finite governed network-discovery product route. It does not
implement raw expert CLI passthrough, extend the selected adapter profiles,
complete Task #40, authorize remote development tests, bundle Nmap, or authorize
a release or publication. Future service discovery or additional profiles need
their own explicit product contract and acceptance.
