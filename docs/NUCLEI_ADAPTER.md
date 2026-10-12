# Optional Nuclei adapter

`fuzzy1337.adapters.nuclei` is an Experimental optional producer for the existing
[ToolAdapter SDK](TOOL_ADAPTERS.md), governed executor and immutable evidence
store. It prepares finite familiar Nuclei CLI arguments and interprets verified
JSONL. It neither installs tools nor authorizes, launches, persists or orchestrates
target scans. See [ADR 0030](adr/0030-reviewed-optional-nuclei-adapter.md).

## Reviewed profile

The supported capability is `web.http-template-check` with `STANDARD` impact.
An operator configures `NucleiProfile` with 1–32 explicit `NucleiTemplate` records
and a regular config file containing exactly `{}\n`. Every template records:

- local absolute YAML file path, exact SHA-256 and byte length;
- provider template ID, source reference and pinned source revision;
- non-secret review reference and `reviewed_profile="single-get-exact-url"`.

The review must establish one HTTP GET against the exact input URL, with no
redirect, other destination/protocol, executable expression, payload expansion,
credential, local file access, global matcher or external callback. Normal YAML
is retained for direct Nuclei CLI use. The adapter verifies file identity and
size; it does not infer semantic safety from severity/tags/signatures or fabricate
a review. Use owned immutable files with an actual reviewed declaration.

An `AdapterRequest` must contain exactly `url`, `profile_sha256` (the profile's
`Digest`), `timeout_seconds` (1–300) and `rate_limit` (1–10 requests/second). The
URL is one literal unicast IP over HTTP(S), without credentials, query, fragment,
control characters, IPv4 limited broadcast, DNS resolution or comma/list
expansion. Its exact path and port are retained.
There is no arbitrary provider option passthrough. The profile hash binds all
selected source/revision/review data into existing invocation authorization.

Create `NucleiAdapter(evidence_store.Read, profile, executable, provider_version)`
using trusted operator-selected executable configuration. `CheckHealth()` runs
only bounded `-version -duc` and reports availability/version; it grants nothing.
Provide an actually observed Nuclei 3.x version before calling `PrepareInvocation`.
Preparation checks exact local artifact bytes without invoking a target process.

## Execution and evidence

Only the existing executor with explicit upstream `ExecutionAuthorization` may
run the prepared invocation. Scope registration, a profile digest and a health
result are not permissions. Keep artifacts immutable until execution finishes:
hash checking is not protection against hostile concurrent replacement or a
network sandbox.

Prepared flags explicitly select HTTP and local templates, override ambient
configuration, emit JSONL, omit raw request/response/template bodies, disable
updates/OAST/redirects/stdin/httpx, bound response size/rate/time, use concurrency
one and retries zero. Other protocols, workflows, template downloads, code,
headless browsers, fuzzing, cloud upload and unrestricted CLI passthrough require
another contract. The tool remains available independently through its familiar
CLI; doing so remains subject to operator scope/authorization.

Store actual stdout/stderr through `LocalEvidenceStore` with real version,
scope, invocation digest and terminal execution provenance before normalization.
`NormalizeReport` verifies the existing immutable stdout reference, then produces
`nuclei.run` metadata and `web.template-match` SDK findings. Exact URL/template
binding, selected hashes/source/review, severity/classification and deterministic
source finding identity are retained. Raw evidence stays in the enclosing report.
No provider-owned core model or persistence path is introduced.

Failed, timed-out and cancelled execution remain incomplete. Invalid successful
JSONL fails; malformed partial unsuccessful output becomes an explicit parse
diagnostic with no trusted findings. Zero matches mean no reported matches; they
do not prove template coverage or target safety. Replay needs captured evidence
and the immutable profile metadata, without requiring local template files.

## Verification

Tests use source-controlled synthetic YAML/JSONL and owned local version/JSONL
producers. The integration test executes the exact prepared argument array through
the existing executor, persists actual bytes through the evidence store, verifies
authorization denial, then normalizes the stored output. The fixture performs no
network activity and does not constitute a genuine installed Nuclei scan.

```bash
uv run --locked --extra dev pytest -q \
  tests/unit/test_nuclei_adapter.py \
  tests/contract/test_nuclei_contract.py \
  tests/integration/test_nuclei_evidence.py
```

Real provider compatibility is based on the upstream
[CLI flag reference](https://github.com/projectdiscovery/nuclei/blob/dev/README.md#command-line-flags)
and [template/output behavior](https://docs.projectdiscovery.io/opensource/nuclei/running).
No Internet target is part of the test suite.
