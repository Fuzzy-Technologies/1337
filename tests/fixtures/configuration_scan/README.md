# Owned configuration wire fixtures

`producer.py` interprets the five exact accepted Dockerfile/Kubernetes fixtures
under `tests/contract/fixtures/configuration_profiles`. It verifies their reviewed
byte hashes before deriving USER/privileged outcomes and source coordinates.
Unknown or changed bytes are refused. The independently hand-authored
`oracle.v1.json` remains unchanged and is never read by the producer.

The worker is a standalone standard-library-only program, invoked as
`(selected_cpython, "-I", "-S", staged_producer, "--fixture-policy", absolute_policy)`
with the exact closed config flag ordering in
[ADR 0051](../../../docs/adr/0051-bounded-synthetic-configuration-wire.md).
It creates no container, build or workload and uses no registry, daemon, renderer
or network client. Tests execute only owned local synthetic stages.

The frozen producer source SHA256 is
`af34b374fa49ce3048d3a7821df5ad8370849240a786dabc7311e14322476eb6`.
Narrow `.gitattributes` entries keep that worker and all five admitted source
files in LF form under Windows checkout settings. Tests independently exercise
that checkout contract.

## Exact policy and result

Material policy has exactly `schema_version`, `fixture_id`, `provider_version`,
`profile_id` and `case_id`. The family is
`owned-synthetic-configuration-wire-v1`, provider `synthetic.trivy`, declared
fixture version `0.75.0-synthetic`. The closed case determines one file/profile;
policy cannot supply rules, expected findings, arbitrary filenames or code.
Policy is at most 1 KiB, depth 16 and 1024 nodes, with strict integer/UTF-8/unique
field semantics. Sources are at most 4 KiB, 64 lines and two documents.

Successful stdout is canonical schema-1 JSON with source/family/profile/case,
one actual file hash/length/type/processed outcome, and zero or one synthetic
Finding proposal. Findings match the independent oracle's exact check, severity,
line, document and selector. Dockerfile inputs have no YAML document coordinate.
`scan_completeness` always remains `not-assessed`, including zero findings.
Original source comments, private marker, image/resource hints, physical paths
and environment values are absent from output.

Both input and material selections contain exactly one declared flat file.
Unknown/control entries, extra directories, changed bytes, flags/profile/path
mismatch, malformed policy or an out-of-range deadline return exit 64, empty
stdout and one fixed sanitized stderr message. The input source is never executed.
The worker reads no oracle or sibling module and emits no grant or receipt.

## Physical reads and acceptance boundary

Bounded reads preserve nonzero path-to-handle device/inode/type/size/mtime
identity, regular type, single links and reparse guards. Full same-method
before/after identities retain ctime and other physical change facts. Only the
Windows path-versus-fstat ctime comparison is omitted because those APIs have
different creation/change-time semantics; POSIX retains that cross check.
Ancestor links are checked before any child metadata/read. Exclusive owner
control is a precondition; these observations do not establish OS immutability
against a hostile concurrent writer.

This source is not registered with the artifact SDK and implements no consumer
or model ingestion. Its exact source/policy/wire needs separate independent
review and later owner-controlled family/profile dispatch. Future normalization
must bind canonical manifests, actual invocation/execution/raw evidence and
original run/grant/marker/receipt, then freshly validate authority. Self-reported
file/source fields grant nothing and cannot become native scanner evidence.

The future synthetic configuration key prefix is
`synthetic.trivy:owned-synthetic-configuration-wire-v1:`, combined with canonical
INPUT manifest SHA and logical path. File SHA remains a separate byte role.
Existing `synthetic.configuration.*` checks and exact source coordinates belong
only to that family. No native asset/finding overlay or image/runtime association
is inferred. Actual replay/model collision/grant invariants await the consumer.

```bash
uv run --locked python -m pytest -q --no-cov tests/contract/test_configuration_scan_fixture.py
```

Owned regressions cover all five source cases, independent result/byte facts,
raw-only markers, closed policy/argv, hostile JSON, selected-set mutation,
path/handle mismatches, complete same-method mutation guards, reparse/hardlink
refusal and source-hash preservation under simulated CRLF checkout settings.
Real Windows filesystem proof remains normal exact-head CI.

These results establish the fixture interpreter/wire contract. They establish
no arbitrary Dockerfile/YAML detection, real Trivy compatibility or accuracy,
SDK registration, governed workflow, model acceptance or OS resource sandbox.
Task #158 remains open for those separate acceptance boundaries.
