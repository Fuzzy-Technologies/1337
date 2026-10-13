# Offline configuration profile design

[ADR 0046](adr/0046-closed-offline-configuration-profiles.md) records the agreed
#158 consumer requirements. This checkpoint supplies design and independent data
fixtures only. No adapter, source parser, runtime producer, profile registration,
consumer API or model import is implemented or claimed.

## Foundation ownership and input closure

The future consumer depends only on the accepted Task #278 / ADR 0044 artifact
producer. Private producer history is not a dependency. The owner supplies explicit
read consent, input/scanner/material snapshots, ARTIFACT scope, exact factory
request, current authority and separate execution/acceptance facts. A local file
never becomes a loopback or other invented network destination.

Dockerfile profiles admit exactly one logical `Dockerfile`. The two physical
fixture locations represent separate selections with that same logical name.
Kubernetes profiles admit a finite explicitly selected `.yaml`/`.yml` set. A
manifest commits profile/role and sorted logical relative names, lengths and
content hashes. No directory recursion or co-located control file is implicit.

Reserved controls are excluded case-insensitively, including `trivy.yaml`,
`trivy.yml`, `trivy-secret.yaml`, `trivy-secret.yml`, `.trivyignore`,
`.trivyignore.yaml`, `.trivyignore.yml`, `Chart.yaml`, `Chart.yml`, `values.yaml`,
`values.yml`, `kustomization.yaml`, `kustomization.yml` and `Kustomization`.
Rego/WASM/Terraform files, settings directories, module/plugin inputs and renderer
overrides are outside the profile. Future detection acceptance must establish that
every selected file was processed as the declared Dockerfile/Kubernetes type;
extension matching or an empty findings list is insufficient.

Owned cwd, home, temp and XDG paths are separate fresh scratch, with controlled
PATH/PATHEXT/locale/platform environment and no ambient `TRIVY_*`, `PYTHONPATH`,
proxy, registry, plugin, Rego or ignore overlays. The exact policy factory owns
these settings. Input/scanner/material partitions are immutable selected snapshots.
Scratch bounds are observed checks, not an OS write quota.

## Native profile remains unavailable

The reserved native IDs are `trivy.dockerfile-offline.v1` and
`trivy.kubernetes-offline.v1`; their provider is `native.trivy`. They cannot receive
a grant or launch from an operator-attested version string. Supplied compatible
binary/material validation must first verify actual argv support, selected-file
detection, empty override behavior, cache/check selection and controlled environment.

The pinned official config CLI supports empty config/ignore overrides, memory
cache, a single selected misconfiguration scanner, JSON output and bounded timeout,
with check/version updates and telemetry disabled. It does not document the image
profile's database, offline-scan, generic scanners, package-list or no-progress
flags. `--file-patterns` adds recognizers and does not disable default detection.
`--config-check` loads custom Rego rather than proving exclusive bundle selection.

The initial native design declares embedded checks: pinned executable, empty
immutable material manifest, fresh separate scratch/cache and memory backend.
Cached checks can fall back to binary-embedded checks, so no external-bundle usage
or observed native check selection is asserted by this design. Offline argv is
not a network sandbox. No Helm/Kustomize/Terraform rendering, image/registry/daemon
operations, downloads, implicit updates or arbitrary flags are accepted.

## Explicit synthetic boundary

The synthetic IDs are `synthetic.dockerfile-offline.v1` and
`synthetic.kubernetes-offline.v1`, provider `synthetic.trivy`. The fixed factory
uses trusted current CPython with `-I -S`, staged `scanner/producer.py`, and exactly
`--fixture-policy material/policy.json` before the fixed profile argv. Interpreter,
reviewed producer and finite policy material are pinned. There is no caller-driven
producer/check/hash registration or arbitrary code/environment selection.

The foundation owns its minimal lifecycle producer and allowlist. Its finite
success/failure/output/wait/mutate modes prove lifecycle contracts only. It does
not emit configuration findings. The fixtures below specify an independent future
configuration consumer oracle; they do not register another producer or establish
that the lifecycle producer detects the fixture conditions. Source implementation,
policy data wire and reviewed producer identity await a separate root assignment.

## Proposed configuration record

A consumer-owned future wire should contain the following strict bounded fields.
These are design requirements, not an accepted producer API or JSON schema:

Proposed consumer ceilings are 64 selected files, 1 MiB per source file, 16 MiB
total input, 1 MiB JSON stdout, 16 KiB version evidence, 32 JSON levels, 65536 nodes
and 4096 entries per consumed array. Identity/selector text is limited to 2048
characters and normalized attributes retain the existing 64 KiB model ceiling.
These tighter configuration limits need agreement with the accepted factory before
implementation; they do not change the foundation's global capture contract.

| Field group    | Required interpretation                                                   |
| -------------- | ------------------------------------------------------------------------- |
| Version/source | One owned wire version, fixed profile, explicit synthetic/native family   |
| Context        | Input/scanner/material manifest digests and reviewed worker identity      |
| File outcomes  | Exactly one unique relative path/content SHA/type/outcome per input       |
| Rule findings  | Finite check ID, known severity, explicit failing outcome                 |
| Location       | Valid source line pair, document index where applicable, bounded selector |
| Completion     | No missing, duplicate, unknown, failed, unsupported or unprocessed file   |

Raw wire self-claims never replace the canonical receipt. Validate exact input/
scanner/material/request/run linkage, raw evidence-store manifests and bytes,
terminal execution and fresh authority before proposing a newly collected update.
Only an accepted successful run can yield successful normalization. Unknown
severity/rule/status, invalid UTF-8, duplicate JSON keys, non-finite values,
excessive bytes/nodes/depth/items and inconsistent coordinates reject atomically.

Raw output, original source bytes, snippets, rendered causes, messages, URLs,
descriptions, environment values and arbitrary provider extensions remain evidence.
Normalized state admits only the agreed identity/check/location and attributed
outcome facts. Errors and chained tracebacks must not echo private source values.

## Existing model and replay

A configuration ASSET natural key binds the canonical artifact manifest SHA and
logical finite path. File content SHA, whole-manifest SHA and any OCI digest remain
distinct roles. Rule identity and canonical line/document/resource coordinates
form the existing Finding check/location identity. Exact replay deduplicates while
preserving the owner's existing triage; absent findings do not resolve old ones.

Synthetic configuration assets/findings require a closed distinct namespace before
their future importer is implemented. Explicit synthetic provenance alone cannot
prevent same-key `ModelState.Apply` attribute overlays. Collision tests must retain
entire native objects/finding dispositions byte-for-byte, not only their count or
provenance. Every relation, observation and finding subject must stay in its
source family. No native upgrade or cross-family link is inferred from hints.

Dockerfile image references and Kubernetes apiVersion/kind/name/image strings are
source hints only. They create no live runtime/image entity or association. Later
RELATED_TO relations require actual attributed association evidence. No parallel
model, finding, consent, grant or evidence store is introduced.

Historical replay verifies saved original bytes/provenance/receipt facts read-only;
it neither revalidates an old receipt as a current grant nor launches a process.
Relocation preserves logical manifest identity; a new launch requires fresh stage
and authority. Raw post-run results survive revoked/expired authority or mutated
material even when normalization is refused.

## Independent fixtures and failure oracle

`tests/contract/fixtures/configuration_profiles/oracle.v1.json` is hand-authored
expected data. Future producers must not load it or derive expected results from
consumer implementation. Source fixtures are inert Dockerfile/YAML text. They
cover root-user versus explicit non-root Dockerfile lines, privileged versus
non-privileged containers, and a failing second YAML document. A synthetic private
comment marker must remain raw-only. No image is built or fetched and no workload
is applied or contacted.

The oracle specifies exact logical paths, synthetic rule IDs and source line/
document/selector coordinates. It deliberately contains no private staging API,
unpublished SDK hashes, provider attestation or native accuracy claim. Future
fixture policy is independent of expected output and uses only an agreed finite
reviewed wire; it cannot select arbitrary rules or invocation options.

| Failure or mutation                 | Expected invariant                                          |
| ----------------------------------- | ----------------------------------------------------------- |
| Missing/excluded/revoked consent    | No launch and no model update                               |
| Changed scope/policy/owner/request  | No launch under stale binding                               |
| Input/worker/policy mutation        | Launch or acceptance denied by the affected boundary        |
| Unknown file/implicit control input | No selected-set expansion or clean verdict                  |
| Failure/timeout/cancel/output limit | Actual executor truth and bounded raw streams preserved     |
| Valid-looking partial JSON          | No successful normalization or partial model write          |
| Missing/duplicate/unprocessed file  | No clean verdict                                            |
| Wrong rule/severity/location/hash   | Atomic sanitized rejection                                  |
| Revocation/expiry after execution   | Raw result retained, new normalized state refused           |
| Replay/relocation                   | Saved facts stable; no current authority or launch invented |
| Colliding synthetic/native identity | Existing native ASSET/Finding objects wholly unchanged      |

Actual config producer source, accepted API, provider semantic validation,
renderers, full Dockerfile/Kubernetes grammar, genuine native scans and later
runtime/image correlation remain open. Task #158 is incomplete.
