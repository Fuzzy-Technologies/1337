# ADR 0110: Governed native configuration workflow

## Status

Bounded direction accepted by the integration coordinator on 2026-10-29.
Refs Task #158. Actual product acceptance and independent review remain required.

## Decision

Extend the prerequisite-only [ADR 0109](0109-native-configuration-sdk-prerequisites.md)
with a separately tagged native configuration workflow. Accept exactly one selected
UTF-8 Dockerfile or already-rendered flat Kubernetes manifest, using the existing
4096-byte source and pinned Trivy 0.75.0 executable contracts. No Helm, Kustomize,
template, YAML rendering, directory discovery, custom checks or external material
is supplied. General selected sources are admitted; the five compatibility
specimens are acceptance targets, not a production allowlist.

The canonical artifact policy engine owns separate native-configuration grants.
Current same-store scope, registered manifest target, independently recorded
consent, explicit executing owner, SAFE capability permission and explicit workflow
approval are necessary. Original observer-issued material proof is necessary but
never sufficient authority. A copied grant, reconstructed receipt, image grant,
synthetic grant or historical replay cannot launch configuration execution.

Execute an original fixed VERSION and then a prerequisite-bound original config
SCAN. Each operation consumes a persistent exclusive operation and observation
claim, binds exactly one request and private fresh scratch, and revalidates current
authority immediately before launch and before acceptance. VERSION starts with an
unknown provider version. SCAN requires the original accepted VERSION object from
the same issuing engine, owner, selected stage and pair. Fresh material observations
occur before VERSION, after VERSION and after SCAN, using the one 45-second
observation ledger and its nine-second finalization reserve. Provider deadlines
are additional explicit job allowances; they cannot replenish observation time.

Use the existing low-level local executor with Linux descendant ownership,
bounded streams and fixed environment. Retain original stdout, stderr and receipt
for both operations, plus exact staged source: seven immutable evidence roles.
SCAN stdout is the original provider report. A process failure, cancellation,
timeout, output overflow, changed material, refused authority or unknown cleanup
cannot become success. Retain available original evidence before interpretation;
uncertain custody or publication is reported separately and prevents model save.

Accept only schema-two native JSON with exactly the selected file, declared
configuration type and positive processed check rows. Require original positive
embedded-library and embedded-check loader diagnostics, and refuse disk/reader
check overrides. Preserve every original native row. Normalize failed native checks
to typed Findings with native IDs, severity, remediation and source coordinates
where supplied. Do not invent missing locations or assume synthetic checks,
finding totals, whole-scanner accuracy or a clean configuration.

Historical replay verifies the seven original owning acquisitions, source digest,
fixed factory, request, authority receipt, stream digests, VERSION association,
chronology and provenance after workspace relocation. Replay is read-only and
does not consult current selected paths, issue grants or write a model. Fresh
application additionally requires original live engine/capture association and
current authority. Save the canonical model before emitting its delta, persist
workspace evidence references, then optionally export the saved JSON/SARIF through
the existing report owner. Publication outcome remains separate from scan truth.

## Product interface and evidence

Add explicit SDK planning and scanning functions and CLI `scan config --profile
native --kind dockerfile|kubernetes`. Existing synthetic behavior remains separate.
The caller selects the executable, source, logical name, read consent and owner;
the caller independently registers the exact previewed artifact target and scope.

Focused unit/contract tests exercise authority and custody failure boundaries.
Ordinary installed functional pytest cases execute the real pinned provider in the
existing owned no-egress lane against the five unchanged specimens and independent
native oracle, then verify canonical saved Findings, original evidence, replay and
report export. Required CI absence fails; optional unavailable local prerequisites
are explicitly unexecuted. Mocks never establish native product acceptance.
