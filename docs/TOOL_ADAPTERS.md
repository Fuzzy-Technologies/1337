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

| Stage                 | Contract                                                    | Owner later in the Workbench               |
| --------------------- | ----------------------------------------------------------- | ------------------------------------------ |
| Provider declaration  | `AdapterDescriptor`                                         | adapter registry and capability selection  |
| Health observation    | `AdapterHealth`                                             | executor/runtime health policy             |
| Approved request      | `AdapterRequest`                                            | Scope and Policy                           |
| Prepared invocation   | `AdapterInvocation`                                         | governed Executor                          |
| Execution facts       | `AdapterExecution` and `AdapterReport`                      | Executor and Evidence                      |
| Normalized output     | `AdapterResult`, observations, findings, and enrichments    | Security Object Model and Evidence         |

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

1. `check_health()` reports observed availability and provider version.
2. `prepare_invocation()` converts an already-approved request into bounded,
   explicit invocation metadata.
3. `normalize_report()` converts executor facts and raw-evidence references into
   provider-neutral output envelopes.

The SDK never starts a process. A future Executor owns process lifecycle,
timeouts, cancellation, scope checks, and audit records.

## Evidence and normalization

Raw provider content stays outside normalized output. `EvidenceReference` uses a
relative locator, SHA-256 digest, media type, size, and role; it does not embed
raw report bytes in a result object.

Adapters may place provider-specific fields in immutable JSON-like attributes on
observations, findings, and enrichments. Those attributes are adapter-bound
metadata, not new Security Object Model types.

## Security invariants

- A declared capability is not execution authorization.
- `ImpactLevel` is a provider declaration; Scope and Policy remain authoritative.
- Required privileges and credential references are opaque identifiers, never
  credential values.
- Invocation metadata uses an argument vector and a positive timeout. Adapters
  must not use shell interpolation.
- A non-zero, timed-out, or cancelled executor result cannot be represented as a
  successful execution.
- Contract metadata is recursively immutable and serializes deterministically via
  `serialize_contract()`.

## Compatibility

The SDK is an Experimental public surface. It may evolve while concrete adapters
validate its shape, but any change is documented under the repository
compatibility policy. Downstream adapters should import only names exported from
`fuzzy1337.adapters` and declare the contract version they support.
