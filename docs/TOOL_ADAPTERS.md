# ToolAdapter SDK

## Status

The `fuzzy1337.adapters` Python surface is **Experimental**. It is the first
provider-neutral contract for security-tool adapters and is versioned by
`ADAPTER_CONTRACT_VERSION`.

The architectural boundary is defined by
[ADR 0014](adr/0014-provider-neutral-tool-adapter-contract.md).

## Purpose

A ToolAdapter describes and normalizes a provider. It does not authorize,
execute, persist, or directly mutate security state.

The SDK keeps these concerns separate:

| Stage                | Contract                                                 | Owner later in the Workbench              |
| -------------------- | -------------------------------------------------------- | ----------------------------------------- |
| Provider declaration | `AdapterDescriptor`                                      | adapter registry and capability selection |
| Health observation   | `AdapterHealth`                                          | executor/runtime health policy            |
| Approved request     | `AdapterRequest`                                         | Scope and Policy                          |
| Prepared invocation  | `AdapterInvocation`                                      | governed Executor SDK                     |
| Execution facts      | `AdapterExecution` and `AdapterReport`                   | Executor SDK and future Evidence Core     |
| Normalized output    | `AdapterResult`, observations, findings, and enrichments | Security Object Model and Evidence        |

## Public import surface

```python
from fuzzy1337.adapters import (
    ADAPTER_CONTRACT_VERSION,
    AdapterDescriptor,
    AdapterRequest,
    AdapterResult,
    ToolAdapter,
)
```

`ToolAdapter` implementations provide three provider-facing operations:

1. `CheckHealth()` reports observed availability and provider version.
2. `PrepareInvocation()` converts an already-approved request into bounded,
   explicit invocation metadata.
3. `NormalizeReport()` converts executor facts and raw-evidence references into
   provider-neutral output envelopes.

The SDK never starts a process. The experimental Executor SDK owns process
lifecycle, timeouts, cancellation, and resource bounds. Scope/Policy remains the
upstream authority and the future Evidence Core owns durable audit evidence.

See [Executor SDK](EXECUTORS.md) and
[ADR 0015](adr/0015-governed-local-executor-boundary.md).

## Evidence and normalization

Raw provider content stays outside normalized output. `EvidenceReference` uses a
relative locator, SHA-256 digest, media type, size, and role; it does not embed
raw report bytes in a result object.

Adapters may place provider-specific fields in immutable JSON-like attributes on
observations, findings, and enrichments. Those attributes are adapter-bound
metadata, not new Security Object Model types.

Nested records use the SDK classes explicitly: `AdapterInvocation.request` requires
`AdapterRequest`; `AdapterReport` requires `AdapterInvocation`, `AdapterExecution`
and `EvidenceReference` members. `AdapterResult` requires an `AdapterReport` plus
the corresponding `NormalizedObservation`, `NormalizedFinding`, `ObjectEnrichment`
and `RelationEnrichment` members. These are exact concrete SDK types, including the
invocation/report/result envelopes themselves: subclasses can append mutable
dataclass fields and are refused with `ValueError`, even when frozen. DTO inheritance
is not a version-one wire extension point; retain provider-specific data in the
documented immutable attributes and implement providers through `ToolAdapter`.
Untyped mappings, duck records and null children also raise `ValueError` at construction.

Tuple, list and ordered iterator collections remain supported for evidence and
normalized output. Construction detaches those collections; each typed member's
JSON attributes are already frozen by its owner. Mutating the caller's original
collections cannot change an existing result's serialized meaning. A decoded JSON
object is an interchange representation, not an implicit SDK record constructor.
This adds no JSON loader or source-authenticity claim, and typed records still need
the existing evidence and canonical-owner checks before application.

## Security invariants

- A declared capability is not execution authorization.
- `ImpactLevel` is a provider declaration; Scope and Policy remain authoritative.
- Required privileges and credential references are opaque identifiers, never
  credential values.
- Invocation metadata uses an argument vector and a positive timeout. Adapters
  must not use shell interpolation.
- A non-zero, timed-out, or cancelled executor result cannot be represented as a
  successful execution.
- Execution duration is a non-negative finite integer or floating-point number.
  Booleans and nonnumeric values are rejected before serialization.
- Contract metadata is recursively immutable and serializes deterministically via
  `SerializeContract()`.

## Compatibility

The SDK is an Experimental public surface. It may evolve while concrete adapters
validate its shape, but any change is documented under the repository
compatibility policy. Downstream adapters should import only names exported from
`fuzzy1337.adapters` and declare the contract version they support.

Nested-type validation preserves valid Python calls, declaration order and the
version-one serialized field names/values. It corrects admission of malformed
Python envelopes without introducing a new wire version, REST endpoint, connector
or provider execution path.
