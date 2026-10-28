# ADR 0105: Pinned native configuration compatibility

## Status

Compatibility-only direction authorized by the integration coordinator on
2026-10-28. Refs Task #158. This decision enrolls no native product profile and
does not complete the task. Exact source review and genuine isolated execution
remain required for the compatibility harness.

## Context

[ADR 0046](0046-closed-offline-configuration-profiles.md) reserves native
Dockerfile and Kubernetes profiles without granting execution authority.
[ADR 0059](0059-governed-synthetic-configuration-sdk.md) and
[ADR 0068](0068-configuration-evidence-workflow.md) establish the separate
synthetic configuration workflow. Its five inert source specimens and
handwritten synthetic oracle remain unchanged.

The remaining immediate Task #158 criterion is supplied compatible native
scanner/check-material acceptance on owned fixtures. The image adapter, image
grants and image receipts cannot establish configuration compatibility. A version
string, executable digest or empty finding list does not prove that selected
configuration files were processed or identify the checks actually loaded.

## Decision

Create a test-only native compatibility harness before designing a native
configuration product consumer. Use the existing independently checksum-pinned
official Trivy 0.75.0 executable and the five unchanged owned Dockerfile and
Kubernetes specimens. Each case supplies one exact source file under its declared
logical name. No caller-selected directory or unknown source enters this harness.

The exact release source is Apache-2.0 licensed. Its `go.mod` selects
`github.com/aquasecurity/trivy-checks` at
`v1.12.2-0.20260908095928-2d1b9bec7d6f`; that exact checks revision is MIT licensed.
The independent compatibility oracle records original specimen byte identities,
native check identities/statuses and source-derived locations, together with
pinned upstream source references and loader provenance. Neither the harness nor
a future product consumer generates expected native answers from scanner output.

### Original process and selected material

Run only in the existing separate Linux no-egress namespace as its ordinary
nonroot owner. Preserve the actual namespace identity, loopback-only interface
inventory, absent IPv4 routes and absent external IPv6 routes. Optional local
absence is explicitly unexecuted compatibility. Required CI mode fails when the
binary, provisioning receipt or isolation prerequisites are absent or inconsistent.

Every case owns a wholly fresh empty cache, cwd, HOME, XDG configuration/cache
and temporary directories, separate from the selected input. Stage only that
case's exact source bytes. Record before/after inventories and hashes. The image
vulnerability database is neither selected configuration material nor a config
prerequisite. The configuration material manifest is empty: this profile proves
the binary's embedded checks, without an external downloaded checks bundle.

Observe the actual original VERSION process, then use a fixed configuration-only
argv: the exact selected executable, empty configuration and ignore overrides,
memory cache, exactly one `dockerfile` or `kubernetes` misconfiguration scanner,
JSON output, included nonfailure results, finding exit code zero, finite timeout,
and disabled check/version updates and telemetry. The harness supplies no image
database/offline/package flags, custom checks/data/schema, modules, renderers,
credentials or inherited provider/proxy environment.

The existing low-level executor may own bounded original streams, finite process
deadlines and Linux descendant cleanup under an explicit test-only caller
decision. That decision is not a native configuration product grant. No image
grant, product authorization engine or new executor is introduced. Preserve exact
argv, cwd, controlled environment, original exit/termination/cleanup facts and
all available original streams before checking their interpretation. Timeout,
output overflow, process failure and unconfirmed cleanup remain failures with
truthful partial evidence.

### Check and processing proof

The pinned executable and source loader references, wholly fresh empty check
cache, controlled environment and actual no-egress execution establish the
candidate embedded-check selection together. Retain original debug evidence of
embedded checks and libraries loading. Refuse a disk/reader policy filesystem or
other check override; a version/hash alone cannot satisfy this proof.
The pinned scanner internally supplies virtual default data, including
`system/k8s-version.json`, and logs `Overriding filesystem for data` for that
ordinary path. This message alone is not an external-data override. Fixed argv,
the empty material selection and fresh environment exclude caller data/schema
paths; policy-disk/reader/check-filesystem overrides remain refused.

Each selected path must appear as a successfully processed result of the declared
configuration type. Included nonfailure results must provide positive evidence
for the selected safe rule. Missing, duplicate, unknown, malformed or unprocessed
file outcomes fail even when no failure is reported. Native root-user and
privileged-container rule IDs, statuses and locations come from an independent
native oracle, including the original second Kubernetes document where the
upstream format supplies the required source location. Synthetic rule names,
severity assumptions, selectors and expected finding totals are not reused.

Retain unrelated native results and raw source text as original evidence. The
harness reports selected compatibility assertions only, with
`scan_completeness="not-assessed"`. A fixed selected advisory/check is not a clean
configuration or whole-scanner accuracy result.

## Source and CI ownership

The initial implementation owns only this ADR, dedicated native configuration
compatibility tests/helpers and the independent native oracle. Existing source
fixtures, their synthetic oracle and synthetic production behavior remain
unchanged. Shared pinned Trivy CI enrollment and its new evidence path require
the coordinator's accepted-base integration, with no concurrent workflow writer.

An explicit draft-only `[native-configuration-compatibility-checkpoint]` runs
only the five new cases, provisioning the pinned binary without an image database.
Ready/push acceptance retains all nine existing native/image/CI cases and adds the
five configuration cases. The existing image draft checkpoint retains its original
selection. Actual JUnit must contain all five config cases without skipped,
failed or errored outcomes, and every case must retain original successful
compatibility evidence. Failed runs preserve the same bounded artifact directory.

Focused tests cover the new harness's input, provenance, processing and failure
boundaries. Genuine provider execution occurs only against the closed owned
specimens in the pinned no-egress lane. Missing required prerequisites fail;
mocked process output is explicitly separate and never establishes native
compatibility. Final exact-source review and real shared evidence precede any
subsequent product consumer design.

## Deferred product boundaries

This slice creates no configuration factory, capability registration, grant,
capture/replay schema, native model/Finding importer, CLI profile or CI predicate.
It makes no authority, filesystem sandbox, hostile-writer immutability, arbitrary
configuration grammar, Helm/Kustomize rendering, runtime/image correlation or
publisher-authentication claim. Task #158 remains open until its actual acceptance
criteria and any later approved consumer design are complete.

## Primary references

- [Trivy 0.75.0 license](https://github.com/aquasecurity/trivy/blob/v0.75.0/LICENSE)
- [Pinned checks module](https://github.com/aquasecurity/trivy/blob/v0.75.0/go.mod)
- [Exact checks license](https://github.com/aquasecurity/trivy-checks/blob/2d1b9bec7d6f/LICENSE)
- [Trivy 0.75 configuration CLI](https://trivy.dev/docs/v0.75/guide/references/configuration/cli/trivy_config/)
- [Trivy 0.75 embedded-check fallback](https://trivy.dev/docs/v0.75/guide/scanner/misconfiguration/check/builtin/)
