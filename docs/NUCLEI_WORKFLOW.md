# Explicit Nuclei Workbench workflow

The development candidate adds Experimental `1337 scan nuclei` and
`fuzzy1337.nucleiscan`. See [ADR 0055](adr/0055-explicit-standard-nuclei-workflow.md)
and the existing [reviewed adapter](NUCLEI_ADAPTER.md). The provider remains optional;
1337 installs no scanner and downloads no templates. The immutable v0.2.1 release
does not contain this workflow.

## Select material and authority

Select one exact literal-IP HTTP(S) URL, an absolute installed Nuclei 3.x executable,
an initialized workspace and an existing scope. Consent must be explicitly granted,
current and attributed to the same `--owner`. Both the exact URL and its actual IP
must independently be registered/allowed. Exclusions still win. Existing
[workspace/scope commands](QUICK_SCAN.md#run-an-owned-localhost-example) can record
an owned localhost endpoint; registration grants no capability or execution approval.

`--profile profile.json` matches `SerializeContract(NucleiProfile(...))` exactly:
`profile_id`, `templates`, `configuration_path`. Each of 1–32 selected templates
needs complete adapter path/hash/byte-length, source/revision and actual review
metadata. Its `single-get-exact-url` review establishes one GET at the exact URL,
without redirect, credentials, expansion, executable expressions, local file access,
other protocols or callbacks. The configuration contains exactly `{}\n`.
Hashes detect observed byte changes; they neither perform nor authenticate review.
Keep the binary and material operator-owned and immutable throughout execution.

`--policy policy.json` is the unchanged `SerializeContract(ImpactPolicy(...))`
representation. All fields are required; unknown/duplicate keys, floating-point or
nonfinite values, excessive structures and observed filesystem links are rejected.
A deliberately selected policy can permit the finite STANDARD provider capability:

```json
{
  "policy_id": "owned-nuclei",
  "revision": 0,
  "maximum_impact": "STANDARD",
  "permissions": [{
    "capability_id": "web.http-template-check",
    "adapter_id": "native.nuclei",
    "maximum_impact": "STANDARD",
    "granted_privileges": []
  }],
  "max_authorization_seconds": 300
}
```

That capability permission is not confirmation of a scan. Empty permissions or a
lower ceiling are denied. There is no implicit STANDARD permission or generic
approval flag. Current policy content is reread at planning, authorization, final
launch and canonical Save; same-revision edits still invalidate the exact plan.

## Plan, review and run

Use `uv run --locked 1337` from the accepted development checkout where needed.
Given actual reviewed profile/policy files and your existing owned localhost scope:

```bash
1337 scan nuclei owned-workspace --scope local --owner operator:demo \
  --target http://127.0.0.1:8000/ --profile profile.json --policy policy.json \
  --executable /absolute/path/to/nuclei --plan
```

Planning probes only the bounded local version command, verifies material and
checks current authority. It prints complete JSON with exact argv, observed version,
finite profile/review metadata, scope/policy digests and `intent_sha256`. It never
contacts the endpoint or grants execution authority. After approving that exact
shown operation, rerun its unchanged inputs with the digest and your actual
non-secret approval-record reference:

```bash
1337 scan nuclei owned-workspace --scope local --owner operator:demo \
  --target http://127.0.0.1:8000/ --profile profile.json --policy policy.json \
  --executable /absolute/path/to/nuclei \
  --confirm-plan EXACT_INTENT_SHA256 --confirmation-reference approval:actual-record \
  --events-json
1337 workspace open owned-workspace --json
```

This reference records operator attestation, not identity-provider login or
cryptographic proof of external consent. Changed target/profile/version/argv,
scope, owner or policy requires fresh planning and exact confirmation. Missing or
stale confirmation prevents target execution. The existing governed executor checks
fresh authority and selected bytes at final launch. After raw-evidence verification
and pure finding projection, the same launch grant is revalidated immediately
before model Save. Expired/revoked/changed authority or material leaves actual raw
acquisitions retained but prevents new canonical findings and terminal completion.

`--timeout` is an integer 1–300 seconds, default 30; the adapter caps individual
request timeout at 30. `--rate-limit` is 1–10 requests/second, default 2. Concurrency
is one, retries zero, target expansion and arbitrary provider flags unsupported.
The job allows five additional seconds for cleanup/persistence; storage and scheduling
are not hard real-time guarantees.

`--events-json` streams actual owned-job queued/running/liveness/acquisition,
persisted model and terminal events, then one summary. Global `--json` emits one
terminal summary. Raw streams stay in immutable evidence. `--plan` always emits
one complete JSON plan and rejects execution confirmation/event-stream flags.
Exit codes: 0 completed operation, 2 invalid inputs/configuration, 3 authority denial,
4 provider/evidence/normalization/storage failure, 130 owned cancellation.

## Durable canonical results

The existing job captures actual terminal stdout/stderr with exact invocation
digest, version, scope, acquisition and outcome before normalization. Failed,
timed-out, cancelled or overflowed execution cannot create trusted findings.
Malformed successful JSONL fails. Empty successful JSONL means no reported matches,
without claiming template coverage or target security.

Successful matches map explicitly through canonical `Finding` and verified ingestion
on the exact shared-model endpoint. Provider `info` becomes `informational`; confidence
remains unknown and detector disposition open. Recollection retains logical identity
and operator triage while appending real provenance. Source/hash/review metadata and
provider observations remain in the SOM. Composite pure projections commit through
one model-owner CAS transition. Save acknowledgement failure remains failure even
if atomic publication happened; the summary rereads the authoritative revision.

Old and new raw acquisitions are independently verified before terminal reference
persistence. Workspace scope/job/object/evidence references save before completed
state. Existing reopen/report consumers read this same durable state without tool
or endpoint contact. Job/event history stays in memory; model and raw acquisitions
are durable. Master and PyPI release/install acceptance remain separate work.

## Acceptance and upstream limits

Portable unit tests use an explicitly synthetic transport with real policy, jobs,
evidence, model and findings. POSIX integration tests also execute an actual owned
no-network JSONL producer. Neither constitutes installed-scanner acceptance.
The separate opt-in lane uses a genuine installed Nuclei 3.x binary against a
pytest-owned loopback marker/negative HTTP service. It verifies one GET at the exact
URL, positive/negative results, unchanged flags, native version/raw evidence,
canonical findings, reopen and report integrity. Ignored artifacts are retained
under `functional-evidence/nuclei-native/`; absent opt-in is a skip. The pinned Linux
acceptance lane uses upstream Nuclei v3.4.10.

```bash
FUZZY1337_NUCLEI_BINARY=/absolute/path/to/nuclei \
  uv run --locked --extra dev pytest -q tests/integration/test_nuclei_native.py
```

Native v3.4.10 outputs authority-only `host` plus explicit `url`, `scheme` and
decimal-string `port`. This form is accepted only when every component agrees
exactly with the approved URL. Existing full-URL-host fixtures remain supported;
contradictory URL/path/scheme/port/IP data fails.

The empty config overrides the main CLI configuration, not every upstream filesystem
access. Linked Uncover initialization can inspect/create default metadata and emit
a diagnostic even when discovery is disabled and the selected GET exits zero.
[Uncover v1.1.0's provider loader](https://github.com/projectdiscovery/uncover/blob/v1.1.0/sources/provider.go)
passes pathname bytes to its YAML decoder, causing the observed scalar-parse error;
[Nuclei v3.4.10's pinned dependency](https://github.com/projectdiscovery/nuclei/blob/v3.4.10/go.mod)
identifies this implementation. Acceptance preserves actual stderr and evaluates
the bounded selected operation's outcome/oracle without editing the binary or home
configuration. Disabled discovery/cloud/update/OAST/redirect options, byte checks
and limited inherited environment are not an OS network/filesystem sandbox or
atomic protection from hostile material replacement.
