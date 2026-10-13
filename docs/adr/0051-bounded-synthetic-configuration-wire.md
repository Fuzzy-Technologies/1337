# ADR 0051: Bounded synthetic configuration producer and result wire

## Status

Proposed — 2026-10-13. Task #158; related work #138 and #278.
Implementation requires acceptance of this decision. This independent fixture
producer is not an artifact SDK registration, native Trivy adapter, configuration
model importer or assembled governed workflow. The accepted artifact SDK remains
a prerequisite for any later governed launch and model acceptance.

## Context

[ADR 0046](0046-closed-offline-configuration-profiles.md) supplies five inert
Dockerfile/Kubernetes inputs and a hand-authored independent oracle. The shared
lifecycle producer does not interpret those fixtures. A bounded source-owned wire
producer can exercise concrete file/result and failure contracts while artifact
SDK integration and genuine scanner compatibility remain separate.

## Decision

Add one standalone standard-library-only synthetic producer under
`tests/fixtures/configuration_scan/producer.py`, with owned contract regressions.
It runs under selected current CPython with `-I -S`; it imports no sibling module,
reads no oracle, extracts/builds/applies nothing and performs no network access.
The source family is `owned-synthetic-configuration-wire-v1`, provider
`synthetic.trivy`, declared fixture version `0.75.0-synthetic`.

The producer admits only the exact five existing fixture byte sequences below.
It verifies the selected bytes against a closed source-owned catalog, then
interprets their finite USER/privileged lines and document separators. This is
an executable fixture wire, not detection of arbitrary Dockerfile/YAML grammar.
Unknown bytes, changed comments or unsupported selection reject rather than
becoming an empty successful result. No fixture or expected oracle is rewritten.

| Case ID                             | Profile suffix | Logical file | Bytes | Source SHA256                                                    |
| ----------------------------------- | -------------- | ------------ | ----- | ---------------------------------------------------------------- |
| dockerfile.root-user                | dockerfile     | Dockerfile   | 264   | 3f0114052cfa7d826abf315fededac339851d4c1991b5c2447bfdf01882323b7 |
| dockerfile.non-root-user            | dockerfile     | Dockerfile   | 271   | 1712d2480103b5881b6df078d5471d12a2c9e0d1d7f6cb96270aa7751943231c |
| kubernetes.privileged-container     | kubernetes     | unsafe.yaml  | 410   | 63b77e1703ab126b9f5283daa5091f750af8ddab3e3b8e24eed63ea36888dd1d |
| kubernetes.non-privileged-container | kubernetes     | safe.yaml    | 409   | 52e45b63f8aec99934dcfddd90d1f3b417111ccabe4514c262e3e8cf443f729f |
| kubernetes.second-document          | kubernetes     | multi.yaml   | 823   | 8cd7163a754dc1a0c29ce1e54fc29cb68a5a0a2b71c79d03a3c54d9caf363b1f |

Profiles are exactly `synthetic.dockerfile-offline.v1` and
`synthetic.kubernetes-offline.v1`. Each case selects one flat input file. The
second-document case means two YAML documents in that one selected file, not
implicit directory discovery. Rule IDs remain the independent oracle's
`synthetic.configuration.dockerfile-root-user` and
`synthetic.configuration.privileged-container`.

### Closed invocation and policy

The fixed prefix is `(selected_cpython, '-I', '-S', staged_producer,
'--fixture-policy', absolute_stage/material/policy.json)`. The exact config suffix
is the shared declared configuration ordering:

```text
("--cache-dir", stage/scratch/cache, "--config=", "config", "--misconfig-scanners",
 "dockerfile" OR "kubernetes", "--cache-backend", "memory", "--format", "json",
 "--disable-telemetry", "--skip-check-update", "--skip-version-check", "--ignorefile=",
 "--exit-code", "0", "--timeout", "<deadline>s", stage/input)
```

The deadline spelling represents an integer from 1 through 60 seconds. Fixed
path/scanner/profile/flag order must agree with the selected case. VERSION,
updates, custom checks, raw flags, environment-selected modes, shell commands,
image/registry/daemon access and alternate interpreter prefixes are unsupported.
The standalone wire does not itself impose an OS process deadline; the owning
test harness/future governed executor supplies timeout/capture/cleanup bounds.

Material policy is at most 1 KiB and exactly these five fields:

```json
{
  "schema_version": 1,
  "fixture_id": "owned-synthetic-configuration-wire-v1",
  "provider_version": "0.75.0-synthetic",
  "profile_id": "synthetic.dockerfile-offline.v1",
  "case_id": "dockerfile.root-user"
}
```

`schema_version` is an actual integer, excluding booleans; all other values are
exact closed strings. The case determines the profile and selected filename.
Policy cannot specify expected findings, rules, source paths, checks, code, flags,
resources or arbitrary scenario behavior. It uses a distinct config-family parser
and cannot pass as the image or lifecycle policy.

### Bounds and actual selected reads

Strict UTF-8 JSON policy rejects duplicate keys, non-finite values, floats,
unpaired surrogates, excessive integer text and extra/missing fields. Decode is
bounded by 1 KiB, depth 16 and 1024 nodes. Each source read is at most 4 KiB;
accepted source has at most 64 lines of at most 256 characters and at most two
documents. One input and one material file are selected; unexpected entries or
directories are rejected with bounded enumeration. No recursive discovery occurs.

Reads are confined to the declared stage input/material partitions. Observed
symlinks, reparse points, hard-linked/non-regular files, incorrect names, changed
file identity/length/content and path/profile mismatch reject. Cwd remains under
the declared scratch partition. The future SDK owns executable/stage authority
and its complete physical checks; no general command registration is introduced.
Pre/post checks assume exclusive owner control and do not prove OS immutability
against an adversarial concurrent writer.

### Exact offline result wire

Successful stdout is canonical finite UTF-8 JSON, at most 16 KiB, with exactly
`schema_version`, `provider_id`, `provider_version`, `fixture_id`, `profile_id`,
`case_id`, `scan_completeness`, `file_outcomes` and `findings`. Source/version/
family/case fields are the exact closed fixture values; completeness is always
`not-assessed`, including no-findings cases.

`file_outcomes` has exactly one item with `logical_path`, actual lowercase
`sha256`, actual integer `size_bytes`, `configuration_type`, `document_count` and
`outcome`. Type is `dockerfile` or `kubernetes`; outcome is `processed`, meaning
this exact admitted fixture was interpreted. Document count is null for Dockerfile
and exactly one or two for the selected YAML fixture.

`findings` has zero or one item with exactly `logical_path`, `check_id`, `severity`,
`outcome`, `start_line`, `end_line`, `document_index` and `resource_selector`.
Severity is `HIGH`, outcome `failed`, and line coordinates are exact positive
integers. Dockerfile USER root is line 7, document index null, selector
`instruction:USER`. Privileged Kubernetes is line 15/document 0 or line
31/document 1, selector `/spec/containers/0/securityContext/privileged`.
The source-owned interpreter determines those coordinates from the admitted
text; it does not load the expected oracle or emit a fixture-selected answer blob.

No source content, comment marker, snippet, message, URL, image/resource name,
absolute path, environment value, grant, receipt or invented manifest identity is
emitted. File hashes identify actual selected bytes, not an artifact manifest,
OCI image, running container or native scanner observation. Emit the complete
validated JSON atomically before returning exit zero. Rejected policy, argv,
selection, input or semantics returns exit 64, empty stdout and one fixed
sanitized stderr message; exceptions/tracebacks must not echo untrusted values.

### Future verification and namespace

This producer is not registered with the pending artifact SDK. Its frozen source
SHA and finite policy/wire require independent review and a later owner-controlled
family/profile dispatch before governed execution. The existing native and
lifecycle registrations remain unchanged. The future consumer must separately
verify canonical input/scanner/material manifests, selected executable/worker,
actual invocation/raw streams/terminal outcome, original run/grant/marker/receipt,
matching source/profile/version and fresh authority. Output self-claims cannot
replace that custody or invent a successful acquisition.

Proposed synthetic configuration ASSET keys are
`synthetic.trivy:owned-synthetic-configuration-wire-v1:configuration:<manifest_sha256>:<logical_path>`.
The whole canonical artifact manifest SHA and individual source-file SHA remain
distinct. Finding identity uses the fixed synthetic check plus canonical exact
line/document/selector coordinates. Every subject/relation/observation remains
inside the source family; full colliding native objects and triage must remain
unchanged. Source image/resource hints create no running object or association.
The existing model/Finding/store schemas are reused only by a later separately
reviewed consumer. Replay verifies saved facts read-only and never regrants or
relaunches; missing findings never resolve old triage implicitly.

## Required evidence and acceptance limits

Regressions run the real standalone producer with `-I -S` on all five admitted
fixtures and compare independently to the unchanged hand-authored oracle. They
also cover case/profile/path/flags/policy mismatches, malformed/deep/large JSON,
bool/float/non-finite/Unicode ambiguity, mutated/oversized sources, extra/control
files, links/non-regular inputs, atomic sanitized refusal and raw-only markers.
Every hostile parametrization has bounded descriptive test IDs for Windows.

The twelve existing future failure invariants involving grants, current authority,
durable model saves, replay and native collisions remain unexecuted in this
producer-only slice. The canonical source gate and owned portable regressions
must pass; independent review freezes exact worker bytes before any registration.
No arbitrary Dockerfile/YAML detection, actual native scan, SDK integration,
OS sandbox, publisher authentication, model ingestion or Task #158 closure is
claimed. No dependency, installation, download or PyPI work is added.
