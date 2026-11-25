# Declared business events

`fuzzy1337.business_events` is an Experimental offline library profile for
owner-defined unacceptable outcomes. It connects explicit critical Assets to an
accountable declaration and explains technical paths from selected attacker
positions to those Assets. An outcome declaration is a scenario, not evidence
that an incident happened, a loss estimate or an execution authorization.

## Original definition

Acquire original UTF-8 JSON through the existing evidence owner with role
`business-event-definition`, media type `application/json`, source version `1`,
and explicit workspace/scope/source/time attribution. Retain the returned original
manifest. The exact source object contains these fields:

| Field                       | Meaning                                                    |
| --------------------------- | ---------------------------------------------------------- |
| `profile_version`           | Exact integer `1`                                          |
| `workspace_id`              | Existing owning model workspace                            |
| `definition_key`            | Bounded ASCII declaration identifier                       |
| `definition_version`        | Explicit owner-selected version text                       |
| `owner_reference`           | Explicit attribution text; not an authenticated identity   |
| `title`                     | Nonempty single-line title                                 |
| `unacceptable_outcome`      | Explicit unacceptable outcome description                  |
| `declared_at`               | Offset-aware time no later than original acquisition start |
| `critical_asset_references` | One to 16 distinct existing ordinary Asset object refs     |

Original bytes are bounded to 64 KiB. Unknown/duplicate fields, non-finite JSON,
foreign references, malformed text, unsupported versions and execution-backed
acquisitions are refused. Critical membership cannot name a finding, reachability
control or another outcome declaration. Naming an Asset explicitly declares its
criticality for this scenario; it does not change the Asset's technical identity.

## Existing owners remain authoritative

`ReadBusinessEventDefinition` verifies the original manifest and bytes using the
evidence owner, reopens the model through `LocalModelStore`, and requires the exact
complete model version and declaration scope. The returned internal value cannot
be manufactured by simply constructing or replacing typed fields.

`ApplyBusinessEvent` returns the new immutable `ModelState` and delta. Save it with
the existing `LocalModelStore.Save(..., expected_revision=...)` operation, reopen,
then read the definition again against the new current model version. The profile
does not write storage itself. CAS conflicts remain the existing owner's errors.
Findings, dispositions, observation history and unrelated model state stay intact.

The canonical Asset has `asset_type="business-event-definition"` and represents
the declaration. Its dedicated key is bound to the exact definition and original
evidence manifest. Descriptive `RELATED_TO` links run from each critical Asset to
the declaration. They retain original evidence attribution and explicitly mean
declared critical-asset impact membership. Replaying the same original manifest
is idempotent. Changing a version, declaration or original acquisition produces a
separate identity; no prior accountable declaration is silently overwritten.

## Explain paths to the scenario

After persistence, obtain a fresh technical projection through the existing
`ReadReachabilityClaims` and `ProjectReachability` interfaces. Select technical
relations explicitly; exclude outcome membership links. Query
`AnalyzeBusinessEventPaths` with the fresh definition, the exact same current
model, this verified projection and an explicit tuple of attacker-position refs.

Each result retains the original `AnalyzeReachabilityPaths` explanation from one
selected attacker position to one critical Asset. The final membership relation
is returned separately. It is never traversed, assigned a technical state or
used to infer that the declared outcome occurred. The consumer refuses projections
containing any declaration endpoint, including another declaration's links.
Scope and complete model pins must match, and query time cannot predate original
definition acquisition. Owner definitions remain durable declarations; the
technical proof owner's existing freshness limits still govern hop attestations.

Hop labels (`UNKNOWN`, `POTENTIAL`, `LIKELY`, `CONFIRMED`, `BLOCKED`) retain their
existing supplied-attestation semantics. Original per-claim confidence estimates
and unusability reasons remain separate. No path/outcome probability is calculated.
Conflicting or stale proof remains conservative `UNKNOWN` evidence, never an
observed impact. A selected graph with no candidate route does not prove global
safety or complete discovery.

At most 16 distinct attacker positions and 64 attacker/critical-Asset pairs are
accepted. Existing search and independent cut-work bounds apply to each pair.
`enumeration_complete` and `cuts_complete` separately summarize whether all
individual bounded calculations finished; the individual reasons and selected
subgraph scope remain available. Structural cuts/removal samples describe the
selected technical graph and do not measure real mitigation effectiveness.

## Evidence

The focused suites exercise original source acquisition, definition verification,
Apply, CAS persistence, reopen and relocation through actual product interfaces.
Independent handwritten technical-route expectations cover all six reachability
phases, named blocking controls and stale/conflicting attestations. Failure tests
cover forged typed fields and manifests, corrupt/missing original bytes, foreign
scope/workspace, stale complete pins, changed persisted declaration/link fields,
descriptive-edge misuse, pair/resource bounds and writer conflicts. I/O tripwires
verify that application and analysis remain pure after their explicit owner reads.

```bash
uv run --locked --extra dev python -m pytest \
  tests/unit/test_business_events.py \
  tests/contract/test_business_events_contract.py \
  tests/integration/test_business_events_model.py -n 2 --no-cov
```

The original library profile adds no scanner, financial scoring or business-risk
ranking. Prioritization remains separate from this declaration model. The
operator interface below reopens already persisted declarations.

## Inspect a retained declaration through the product

An operator can reopen one already persisted owner scenario and its current saved
critical Assets without calculating paths or scores:

```bash
1337 business inspect /owned/retained-workspace \
  --definition sha256:ORIGINAL_DEFINITION_MANIFEST_DIGEST \
  --scope-reference scope:original-declaration \
  --expected-revision 7 \
  --expected-snapshot-sha256 CANONICAL_MODEL_SHA256 --json
```

Replace the example revision and both digest placeholders with your independent
selections. The original definition manifest comes from the existing evidence
owner. The full current model pin is the `model_revision` and `snapshot_sha256`
of an existing verified `report export` result, or the existing
`ReachabilityModelVersion.FromModel` SDK value. Revision alone is insufficient.
The same command is available in the interactive shell; context supplies no
implicit workspace, definition, scope or model pin.

Inspection reuses `ReadBusinessEventDefinition` and requires
`ApplyBusinessEvent` to be an exact no-op against the saved model. Missing or
altered declaration/membership records are refused; inspection never creates or
repairs them. The explicit scope is original attribution checked against the
original definition manifest, not current execution authorization.

The successful version-one terminal envelope has an `inspection` containing:

- The complete existing `model_version`, original `definition_evidence_id`,
  `definition_reference` and unchanged original `definition_record`.
- The canonical saved `declaration`, `critical_assets` and descriptive
  `memberships`, using the existing model record shapes and provenance.
- `checked_model_evidence_references`, counting unique references checked for
  those selected records, and `semantics: declared-unacceptable-outcome`.

Every selected declaration, Asset and membership evidence reference is checked
through the existing bounded report evidence consumer. Its limits remain 1,024
distinct blobs, 32 MiB per blob and 128 MiB in total. These checks establish
retained byte integrity, not source truth or authenticated ownership. Empty
evidence-reference collections remain visible in canonical provenance; no
supporting observation is invented. Unrelated saved records are not selected.

After supporting-byte checks, the original definition and current complete
model pin are read again. Freeze the operator-owned workspace during inspection;
the operation does not claim a lock against hostile concurrent writers. Moving
the complete workspace preserves its identities. No source, model or workspace
file is written, and repeated inspection adds no observation clock.

Without `--json`, the console shows the owner's title/outcome, supplied owner
reference and critical Asset keys. JSON exposes their full retained records and
declared text; select only material appropriate for the caller's terminal. The
scope is explicitly an owner-declared unacceptable outcome and critical-asset
membership. It establishes no observed incident, business loss or Action Priority.

Exit `0` confirms complete inspection; `2` is invalid configuration, `4` is
source/model/integrity or evidence-budget refusal, and `130` is interruption.
A failed outcome contains no `inspection`, partial Asset list or original source
text. The existing `core_mutation: none` and `evidence_commit: not-attempted`
terminal facts describe this read-only operation. Help requires no storage read.
