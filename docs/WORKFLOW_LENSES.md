# Workflow lenses

`fuzzy1337.lenses` is an **Experimental** Python interface and versioned JSON
contract implementing [ADR 0029](adr/0029-read-only-workflow-lens-contract.md).
It provides four lightweight views of the same
[Security Object Model](SECURITY_MODEL.md). A lens is a query/presentation preset;
it does not change workspace state, target consent, impact, or execution authority.

## Initial views

| Lens        | Default object focus                                          | Presentation emphasis                         |
| ----------- | ------------------------------------------------------------- | --------------------------------------------- |
| `pentest`   | Targets, domains, hosts, ports, services, endpoints, software | Observed surface and reported state           |
| `dfir`      | Hosts, inventory assets, domains                              | Source attribution and observation order      |
| `devsecops` | Inventory assets, services, endpoints, software               | Inventory and reported versions               |
| `purple`    | All supported objects                                         | Shared observation history and source context |

These views use existing objects. They do not implement forensic ingestion,
incident reconstruction, build risk gates, detection validation, or attack paths.
An object keeps the same reference, attributes, and provenance in every view.

## Human and machine shell entry

Start `1337 shell`, then explicitly open an existing workspace containing a
model snapshot:

```text
model synthetic-workspace
view model
lens devsecops
view model --json
lens --json
lens dfir --json
```

`model` reads the portable store; it never creates or saves it. The path may
contain spaces and is taken literally. Missing, unsafe, or corrupt state is
reported and retains the previously loaded snapshot. `view model` requires a
loaded model, shows canonical object references and counts, and rerenders when
the lens changes. `view model --json` emits one versioned reference projection.
`lens --json` describes the currently selected lens; specifying a name selects
and describes it. These JSON commands emit a single JSON line without a human
prefix. Interactive shell prompts remain part of the interactive transport;
SDK clients can use the producer directly.

The loaded revision is a snapshot. Run `model <workspace-path>` again to observe
later persisted changes. Job subscriptions and live updates are not connected
by this feature. Shell lens selection stays in local presentation state and
does not save a workspace preference.

## SDK entry

```python
from pathlib import Path

from fuzzy1337.lenses import LensDescriptor, LensQuery, ResolveLens
from fuzzy1337.model import LocalModelStore, ObjectKind

state = LocalModelStore(Path("synthetic-workspace")).Open()
lens = ResolveLens("pentest")
descriptor = lens.ToDict()
assert LensDescriptor.FromDict(descriptor) == lens
view = lens.Project(state)
hosts = lens.Project(state, LensQuery(object_kinds=(ObjectKind.HOST,)))
assert hosts["workspace_id"] == view["workspace_id"]
assert hosts["revision"] == state.revision
```

The example reads an existing local workspace and performs no security testing.
`LENS_CATALOG` is an immutable ordered tuple of the four descriptors.
`ResolveLens` requires an exact canonical identifier and rejects unknown values.
`InteractiveShell.BindModel` accepts an actual `ModelState` for an explicit SDK
consumer without filesystem access.

## Descriptor contract

Schema version 1 is published at
[`contracts/workflow-lens.schema.json`](../contracts/workflow-lens.schema.json).
It validates either a descriptor or a reference view. Use
`LensDescriptor.FromDict` for runtime validation as well: it checks typed values,
required fields, unknown fields, versions, and identifier uniqueness. Duplicate
action IDs are invalid even if their descriptions differ.

- `preferred_object_kinds` and `preferred_relation_kinds` describe emphasis.
- `default_query` contains explicit kind filters, `attributes_match`,
  `key_contains`, `require_provenance`, and `include_observations`.
- `contextual_actions` contains identifiers, summaries, and applicable object
  kinds. They are suggestions, without callable handlers or permission grants.
- `preferred_capabilities` contains catalog preferences. A client must separately
  discover available providers and obtain ordinary governed execution approval.
- `overlays` names `evidence-references`, `source-provenance`, or
  `observation-history` from canonical records; no overlay is another truth store.
- `attribute_mappings` maps a display label to an existing attribute name. Missing
  attributes remain missing, and values are never rewritten or inferred.
- `presentation` provides `columns`, `group_by` (`kind`, `source`, or `none`), and
  `observation_order` (`reference` or `observed-at`) for future TUI/Web/API clients.

The compact shell renders kind/key/reference rows and relation/observation counts.
Control and directionality characters in observed keys are escaped for terminal
output, while canonical keys remain unchanged.
Rich clients may honor additional column, grouping, action, and overlay hints.
DFIR currently requires provenance explicitly, which canonical model records
already require; this does not claim evidence completeness or legal admissibility.

## Query and output semantics

An empty kind tuple selects all supported kinds. Nonempty kind filters use typed
`ObjectKind`/`RelationKind` values; unknown values fail. Key matching is a literal
Unicode case-insensitive substring, never regex or executable text.
Attribute matching requires key presence and exact canonical JSON equality.
In particular, `true` differs from `1`, and a missing attribute differs from
explicit `null`. Nested matches compare whole values rather than arbitrary paths.
Caller mappings/lists are detached and recursively frozen.

An explicit query replaces the descriptor's default query for that call only.
The result includes `schema_version`, `lens`, `workspace_id`, `revision`, the
resolved `query`, and `object_references`, `relation_references`, and
`observation_references`. Object/relation ordering follows canonical references.
An edge appears only when both endpoints are selected and its kind matches.
An observation appears only when its object/edge subject appears. DFIR/Purple
observations sort by normalized acquisition time, then reference; this is not
causal or detection analysis.

Resolve references against the exact workspace/revision that produced the view.
Keep the canonical objects and evidence store as the source of truth. A view is
detached presentation output and cannot be loaded through `ModelState.FromDict`.
Changing a returned JSON dictionary does not change a descriptor or the model.
Use the evidence API to verify referenced bytes; a view only retains references.

## Deterministic verification

```bash
uv run --locked --extra dev python -m pytest -o addopts='' \
  tests/unit/test_lenses.py tests/unit/test_shell.py \
  tests/contract/test_lenses_contract.py \
  tests/integration/test_lenses_integration.py
```

The integration suite stores actual synthetic evidence and shared model state,
opens it through the shell, compares machine views with SDK projections, checks
different terminal slices, and proves all workspace files remain unchanged.
Malformed descriptors, query flags, unsupported versions/kinds, extra authority
fields, and corrupt/missing stores have explicit failure tests. No external
target, browser, paid model, or provider process is used.
