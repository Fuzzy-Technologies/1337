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

The profile adds no scanner, CLI, financial scoring or business-risk ranking. The
dependent prioritization task remains separate from this declaration/path model.
