# Genuine pinned Trivy adapter acceptance

The `Genuine Trivy acceptance` workflow validates the existing optional
`TrivyAdapter -> CaptureNativeTrivyOperation -> LocalExecutor -> LocalEvidenceStore`
and detached `NormalizeReport`
boundary. It uses a genuine upstream binary and official offline vulnerability
database with repository-owned inert image archives. Native artifact profiles
remain metadata-only; this acceptance lane does not expose native product scan
execution or write fixture findings into durable model state.

## Independent material and advisory pins

`tests/fixtures/trivy/native_oracle.json` records the following independent pins:

- Trivy release: `v0.75.0`, Linux amd64 archive, SHA-256
  `c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f`.
- Official database OCI manifest:
  `ghcr.io/aquasecurity/trivy-db@sha256:4efa1d9d38f992c2472847b04b802f390924514574fad189f7d89e4c7e93ab00`,
  created 2026-06-22. It is deliberately historical reproducible test material.
- Maintainer advisory `GHSA-j8r2-6x86-q33q` / `CVE-2023-32681`: Requests 2.30.0
  is affected; 2.31.0 is fixed for this specific advisory.
- Each 20-KiB Docker-save input archive has its own independently recorded byte
  hash. The builder uses regular USTAR members, a proper image config and one
  layer DiffID. That DiffID and the archive hash retain their distinct meanings.

The owned layer contains only Python package `METADATA` and empty `RECORD` files.
No Requests implementation is installed, executed or exploited. Trivy must decode
the actual archive and detect the declared package/version itself. The real
database supplies actual advisory results. Tests preserve every other Finding
proposal; absence of the selected advisory is never a general clean-scan claim.

CI downloads the checksum-pinned binary release, extracts only the bounded regular
`trivy` member and runs its exact database-only provisioning command with the
immutable OCI reference. Upstream Trivy's OCI transfer verifies content digests.
CI records separate hashes of the extracted executable, `trivy.db` and
`metadata.json`. These selected-file receipts are not publisher authentication.
Trivy and trivy-db tooling use Apache-2.0; their external binary/database material
remains ephemeral CI input rather than vendored or redistributed product content.

## Actual isolated scan boundary

After provisioning, CI creates a fresh Linux network namespace with `unshare
--net`, then drops to the runner's original uid/gid before starting pytest.
The namespace must differ from the host provisioning namespace, contain only
loopback and have no external IPv4/IPv6 route. Native version and scan processes
inherit it. Assertions inspect local namespace/interface/route state and never
probe an Internet endpoint. Provisioning access is outside this scan boundary.

The actual adapter invocation retains all existing offline flags, fixed archive
input, explicit cache/config selections, 60-second deadline and 4-MiB/1-MiB
stdout/stderr bounds. Scan home/config/temp locations belong to the owned test.
Before and after each accepted scan, selected database bytes match their original
provisioning receipt and remain unchanged. Actual version-observed DB schema and
timestamps also match the copied selected metadata, which is retained explicitly
in the run document. No arbitrary `TRIVY_*` setting, ambient
credential, registry input, daemon or network update is supplied.

Native acceptance is opt-in locally and in ordinary matrix tests. Supply all four
explicit non-secret selections **inside an isolated Linux network namespace**:
`FUZZY1337_TRIVY_BINARY`, `FUZZY1337_TRIVY_CACHE`,
`FUZZY1337_TRIVY_PROVISIONING` and `FUZZY1337_TRIVY_HOST_NETNS`. The last value is
the recorded host namespace identity from before isolation; the provisioning
receipt follows the workflow's exact schema and pins. Partial setup fails.
With no selections, native tests skip and establish no native PASS.

```bash
uv run --locked --extra dev pytest tests/integration/test_trivy_native.py -o addopts='' -q
```

That invocation cannot provision material or create its own isolation. The
canonical workflow supplies both before executing it. Its retained artifacts are
under `functional-evidence/trivy-native/`: each original immutable evidence store,
exact invocation/terminal run document, material and network context, and unchanged
normalized SDK proposals for successful cases. A missing-DB case retains actual
provider failure rather than an empty successful scan.

Positive cases now execute original VERSION through the same bounded low-level
executor as the independent SCAN. VERSION retains its own 3-second deadline,
16-KiB stdout/stderr budgets, actual exit/termination/events, original invocation
with unknown provider version, selected material facts and collection timestamps.
SCAN has a separate caller-issued exact invocation authorization and references
that immutable accepted VERSION receipt digest. Fresh owned cwd/home/config/temp
and an explicit clean environment apply to each operation. All six original raw
roles remain in canonical custody; VERSION stdout/stderr/execution is never
reconstructed from health state or rewritten into SCAN provenance.

Association requires unchanged selected archive, binary, database and metadata
byte/physical facts, owner/workspace, target, scope and policy. A failed, timed out,
cancelled, truncated, altered or unverified VERSION cannot launch an associated
SCAN. Post-run refusal preserves actual process success/failure rather than
rewriting it. A second missing-DB case retains original executed VERSION and
proves SCAN association refusal. The earlier native missing-DB SCAN compatibility
case keeps its unchanged health-based path and must still genuinely fail.

These are low-level caller-authorized acquisitions and descriptive custody,
without product artifact grants. Receipt bytes, checksums and supplied
`ExecutionAuthorization` values cannot issue SDK native image permission. The
legacy `ApplyVerifiedTrivyImages` import retains its original health-only version
shape and intentionally refuses execution-bearing VERSION provenance; no field
is stripped to force these captures through it. Detached adapter normalization
in this lane writes no model state. Native product paired acceptance remains
future work. Database metadata is provider-observed; byte receipts establish
neither feed completeness nor freshness. `scan_completeness` stays `not-assessed`.

A trusted selected workspace/executable and independently enforced isolation are
caller prerequisites. The collector checks observed physical identities and
bounded bytes around launch; it does not sandbox an untrusted binary or attest
against a hostile concurrent writer. Direct task cancellation propagates after
owned executor cleanup; cooperative cancellation retains original raw custody.
Filesystem publication failure follows the unchanged evidence-store orphan-blob
contract and does not create accepted model state.

## Primary sources

- [Pinned Trivy release and checksums](https://github.com/aquasecurity/trivy/releases/tag/v0.75.0)
- [Pinned database package manifest](https://github.com/aquasecurity/trivy-db/pkgs/container/trivy-db/965220078)
- [Official DB provisioning and schema-2 artifact format](https://github.com/aquasecurity/trivy-db)
- [Trivy 0.75 image CLI](https://trivy.dev/docs/v0.75/guide/references/configuration/cli/trivy_image/)
- [Pinned native Python packaging analyzer](https://github.com/aquasecurity/trivy/blob/v0.75.0/pkg/fanal/analyzer/language/python/packaging/packaging.go)
- [Maintainer's selected advisory](https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q)
- [Trivy license](https://github.com/aquasecurity/trivy/blob/v0.75.0/LICENSE)
- [trivy-db tooling license](https://github.com/aquasecurity/trivy-db/blob/main/LICENSE)

[ADR 0057](adr/0057-pinned-native-trivy-acceptance.md) defines the initial acceptance
prerequisite; [ADR 0058](adr/0058-original-native-image-capture.md) defines original
independent VERSION/SCAN custody. Supplied native product authorization and the remaining #140/#142
criteria remain separate work. No PyPI operation is performed.
