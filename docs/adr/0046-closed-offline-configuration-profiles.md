# ADR 0046: Closed offline configuration profiles

## Status

Proposed — 2026-10-13. Task #158; related work #138, #142 and #278.
This design/data checkpoint implements no adapter, producer registration or
configuration finding ingestion. The accepted ADR 0044 producer is a prerequisite
for any later source implementation.

## Context

Dockerfiles and already-rendered Kubernetes definitions are selected local
inputs. Their image names, resource names and URLs grant no network or runtime
authority. A directory scan must not silently consume ignore files, tool settings,
custom Rego, Helm charts, Terraform modules or other ambient material.

Trivy 0.75 `config` has a different CLI envelope from `image`. Misconfiguration
checks can be loaded from an external cache or fall back to embedded binary
checks. An empty configuration argument, executable hash or version string alone
does not prove the actual check selection, filesystem behavior or absence of
network access.

## Decision

Consume the single ADR 0044 artifact owner rather than adding scope, consent,
policy, executor or evidence stores. Its agreed metadata identifiers are:

| Profile                           | Selected logical input               | Capability                            |
| --------------------------------- | ------------------------------------ | ------------------------------------- |
| `trivy.dockerfile-offline.v1`     | Exactly `Dockerfile`                 | `config.dockerfile-misconfigurations` |
| `trivy.kubernetes-offline.v1`     | Finite explicit `.yaml`/`.yml` files | `config.kubernetes-misconfigurations` |
| `synthetic.dockerfile-offline.v1` | Exactly `Dockerfile`                 | `config.dockerfile-misconfigurations` |
| `synthetic.kubernetes-offline.v1` | Finite explicit `.yaml`/`.yml` files | `config.kubernetes-misconfigurations` |

Native identifiers remain metadata-only. No native consumer capability, grant or
launch is exposed until supplied compatible binary/material validation proves the
exact closed profile and cache behavior. Operator attestation and version strings
are insufficient. No installation, download or genuine Trivy scan is part of
this checkpoint.

The foundation binds separate immutable input, scanner and material manifests,
explicit selected-read consent and a fresh physical stage lease. Each manifest
uses its own role/profile domain, finite portable relative names, byte lengths
and SHA256. The input target is `manifest-sha256:<64 lowercase hex>` in the existing
scope store. Absolute source paths, an OCI image digest and a file content digest
never substitute for this manifest identity.

Execution requires the current owner, scope/consent and policy content/revisions,
fixed capability, exact invocation, controlled cwd/home/environment, privileges
and bounded resources. Source/material checks occur at launch and acceptance.
Raw result and acceptance remain separate: refusal after a run retains stdout,
stderr and actual terminal outcome. A fresh accepted receipt is required before
newly collected state is proposed. Historical replay remains read-only and cannot
revive a grant or launch a process.

Native configuration design selects exactly the Dockerfile or Kubernetes scanner,
JSON stdout, finding exit code zero, memory cache and disabled check/version/
telemetry updates. Empty config/ignore overrides and a fresh owned cwd/home/temp
are required together with the closed input set. Image-only database/offline/
scanner flags are not copied. The initial declared native check mode uses embedded
checks with an empty immutable material manifest and separate fresh scratch/cache;
actual selection is still unverified without native acceptance evidence.

Source profiles exclude implicit settings, ignore, Rego, WASM, Helm, Kustomize,
Terraform and module/control inputs. File-pattern flags add detection and are
never used to prove an exclusive selected set. No rendering, package/image scan,
container build, remote reference resolution, registry or daemon access occurs.

The agreed synthetic factory prefix is `(trusted current CPython, '-I', '-S',
staged 'scanner/producer.py', '--fixture-policy', 'material/policy.json')`, followed
by fixed profile argv. The foundation owns the reviewed producer allowlist and
its finite lifecycle policy. Callers cannot register producer hashes, arbitrary
scripts, checks, flags or environment overlays. The foundation lifecycle oracle
does not produce configuration detections; future configuration producer source
and registration require a separate reviewed assignment.

## Model and wire boundary

`docs/OFFLINE_CONFIGURATION_DESIGN.md` defines the proposed consumer wire and
independent data oracle. A future consumer uses existing ASSET configuration
subjects derived from manifest SHA plus finite relative path, and existing Finding
subject/check/location identity with exact rule/line/document/resource coordinates.
It preserves triage and raw evidence and creates no live workload or image entity
from source hints. Synthetic projections additionally require a closed synthetic
natural-key/check namespace before implementation; fixture evidence cannot update
native assets or findings. No new model schema is proposed here.

## Consequences

- The first deliverable is design and hand-authored source/expected fixtures only.
  They are not output from Trivy, a Kubernetes API, a build or a running workload.
- Unsupported, missing or unprocessed files cannot become a clean scan verdict.
  Failure, timeout, cancellation and capture limits preserve actual execution truth.
- Native cache/material compatibility, detection accuracy, full grammar support,
  configuration producer source, consumer API and real scanning remain open.
- Parent #158 remains open. The artifact foundation does not promise OS CPU,
  memory, network or write-quota isolation or publisher authentication.

## References

- [Configuration design and independent oracle](../OFFLINE_CONFIGURATION_DESIGN.md)
- ADR 0044: Governed local artifact snapshots and offline authorization, Task #278
- [Trivy 0.75 config CLI](https://trivy.dev/docs/v0.75/guide/references/configuration/cli/trivy_config/)
- [Trivy 0.75 file detection](https://trivy.dev/docs/v0.75/guide/configuration/skipping/)
- [Trivy 0.75 built-in checks](https://trivy.dev/docs/v0.75/guide/scanner/misconfiguration/check/builtin/)
