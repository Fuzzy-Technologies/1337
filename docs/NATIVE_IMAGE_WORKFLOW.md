# Governed native image workflow

The development candidate adds `PlanNativeImageScan`, `ScanNativeImage` and explicit
`1337 scan image --profile native`. The existing synthetic workflow keeps its
selection and summary contracts. The optional native provider is operator-supplied
Trivy; 1337 installs no engine, refreshes no database and discovers no input path.
ADR 0093 defines the accepted design. Native material observation and execution
require supported Linux descendant ownership; unsupported runtimes refuse before
starting the selected scanner.

## Explicit material and authority

Use an existing physical workspace. Select a canonical workspace-relative archive
and cache directory, an absolute trusted Trivy executable, an executing owner and
an explicit read-consent record. Archive/cache selections reject absolute paths,
traversal, links and ambiguous path spellings. The existing archive, executable,
database and metadata byte/physical bounds remain in force.

The SDK selection is `NativeTrivySelection` with
`ArtifactReadConsent(actor_ref, record_ref)`. The actor must match the executing
owner; the record reference stays a distinct operator-supplied reference. Neither
reference is an authenticated signature. Current recorded scope consent and the
complete current policy are separately checked.

An already selected policy must permit `native.trivy` /
`image.archive-vulnerabilities` at SAFE impact with empty `granted_privileges`.
The independent `--approve-safe-image` opt-in cannot manufacture that permission.
Policy content is reread, including same-revision changes. Grant expiry is
exclusive and bounded by policy lifetime and recorded scope consent.

## Preview, register and plan

With material already provisioned in `owned-workspace`, a preview starts only the
fixed bounded material reader:

```bash
1337 scan image owned-workspace --profile native --owner operator:demo \
  --archive image.tar --cache-directory trivy-cache \
  --executable /absolute/path/to/trivy --read-consent-reference read:demo --plan
```

The JSON phase is `material-preview`, with `execution_authorized: false` and the
canonical IMAGE/INPUT manifest's ARTIFACT target. Register that exact target using
the existing scope owner, with independently recorded current consent. Preview
does not create a scope or grant. It does not run Trivy.

Supply both existing scope and selected policy for a strictly scoped VERSION plan:

```bash
1337 scan image owned-workspace --profile native --owner operator:demo \
  --archive image.tar --cache-directory trivy-cache \
  --executable /absolute/path/to/trivy --read-consent-reference read:demo \
  --scope local-image --policy native-policy.json --plan
```

One missing authority argument is invalid. A denied scoped plan never becomes a
preview. The actual SCAN recipe remains deferred until a separately authorized
original VERSION succeeds. Planning has a separate twelve-second observation
budget and creates no execution claim.

## Run and retain results

Run the same explicit selections with current authority and workflow approval:

```bash
1337 scan image owned-workspace --profile native --owner operator:demo \
  --archive image.tar --cache-directory trivy-cache \
  --executable /absolute/path/to/trivy --read-consent-reference read:demo \
  --scope local-image --policy native-policy.json --approve-safe-image --events-json
```

`--timeout` selects the SCAN deadline from 1 through 3600 seconds, default 30.
VERSION retains three seconds. Three owned material observations share one
45-second observation/finalization ledger; provider READY/cleanup reserves yield
a provider bound of `scan_timeout + 60`, with a job backstop one second larger.
Ordinary filesystem operations retain their stated soft timing limits.

Distinct original VERSION/SCAN grants consume persistent grant, operation and
observation identities. A cancelled, refused or incomplete claimed attempt cannot
be resumed; a new attempt needs fresh material observation and authority. The
fixed offline provider argv and isolated environment remain governed. Available
original stdout/stderr/receipt acquisitions survive later refusal.

Successful canonical admission preserves image/package/Finding identities and
operator triage. Both original grants, latest selected material and cancellation
are rechecked immediately before model CAS. Model/workspace revisions stay frozen;
the two stores are not a cross-store transaction. If publication committed before
an acknowledgement or later step failed, the summary reports failure and the
reopened actual revision without rollback or blind retry. Verified evidence-only
retention after cancellation or revocation is not scan success.

Native summaries use source `native.trivy`, workflow `native-image` and completeness
`not-assessed`. Zero reported findings does not establish archive security.
`--events-json` reports actual job events; global `--json` returns a terminal
summary. Existing JSON/SARIF report options export the exact saved model and have
separate failure status. Exit meanings remain 0 success, 2 invalid input,
3 authority refusal, 4 provider/evidence/storage/export failure and 130 cancellation.

## Genuine acceptance

`tests/functional/test_native_image_product.py` uses the existing two inert
Docker-save archives, checksum-pinned Trivy 0.75.0 and provisioned database inside
the existing network namespace without external routes. It exercises real SDK and
installed isolated CLI, original six-role pairing, selected advisory correlation,
retained triage and relocated offline reopen after input deletion. The fixed case
omits only the selected CVE correlation; unrelated findings remain valid.

The required CI lane sets `FUZZY1337_RUN_NATIVE_IMAGE_PRODUCT_ACCEPTANCE=1` with all
four existing provisioning variables. Missing engine, material or isolation fails
that lane. Local optional skips and controlled unit protocols establish no genuine
acceptance. `functional-evidence/native-image-product/` retains actual evidence.
