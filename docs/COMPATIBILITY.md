# Public Compatibility Contract

This document defines the public compatibility boundary for **1337 Security Workbench by Fuzzy Technologies**.

The goal is simple: extensions should be able to depend on explicit public contracts without depending on repository internals, implementation layout, or confidential code.

## Contract version

This policy is **Compatibility Contract v1**.

Repository releases use Semantic Versioning. Individual machine-readable contract families also carry their own schema version so a schema can evolve independently from the repository release number.

## Stability classes

| Stability class | Meaning                                                                 | Compatibility promise                                                                 |
| --------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| **Stable**      | Explicitly documented public contract intended for external consumers  | Breaking changes require the version transition defined below                         |
| **Experimental**| Publicly visible preview surface that is still being designed           | May change between releases; changes must be documented                              |
| **Internal**    | Implementation detail not declared as public                            | No compatibility promise; external consumers must not depend on it                   |

A surface is **not** Stable merely because it is importable, visible in source, reachable over HTTP, or present in a serialized file. Stability must be declared by public documentation or a versioned schema/SDK contract.

## Public contract boundaries

The following areas are the intended extension boundaries as they are introduced:

| Boundary                    | Public when                                                        | Not a public guarantee                                                     |
| --------------------------- | ------------------------------------------------------------------ | -------------------------------------------------------------------------- |
| Machine-readable contracts  | Versioned schema is published under `contracts/`                   | Unversioned internal JSON/YAML/state                                       |
| Python/API SDK              | Symbol is explicitly documented as public SDK surface              | Arbitrary internal modules, classes, helpers, or import paths               |
| Tool adapters               | Adapter interface/schema is published as a versioned contract      | Executor internals or third-party tool implementation details               |
| CLI                         | Command/option behavior is documented as a stable CLI contract     | Human-oriented formatting, spacing, colors, or incidental log text         |
| REST/OpenAPI                | Endpoint/schema is included in a versioned public API specification| Internal routes, debug endpoints, or undocumented fields                    |
| Evidence/finding formats    | A versioned schema is published                                    | Temporary runtime/cache/storage representation                             |
| Extension manifest          | Validates against `contracts/extension-manifest.schema.json`       | Extra undeclared fields or implementation-specific metadata                 |

The M0 repository does **not** freeze a Python import namespace before packaging is implemented. Future packaging work may choose the concrete import/package names, but once a symbol is declared Stable it must follow this compatibility policy.

## Version compatibility rules

### Repository releases

Before `1.0.0`:

- patch releases (`0.Y.Z` → `0.Y.Z+1`) must not intentionally break Stable contracts;
- a breaking change to a Stable contract requires at least the next minor release (`0.Y` → `0.Y+1`);
- Experimental surfaces may change in a patch or minor release, but the change must be documented;
- Internal surfaces may change at any time.

At and after `1.0.0`:

- breaking Stable-contract changes require a major version;
- backward-compatible additions may use a minor version;
- backward-compatible fixes use a patch version.

### Contract schemas

Each machine-readable contract family has an integer schema version starting at `1`.

- backward-compatible additions may retain the same schema version when old valid documents remain valid and semantics do not change incompatibly;
- incompatible field/meaning/removal changes require a new schema version;
- consumers must reject unsupported schema versions explicitly rather than guessing;
- schema-version negotiation/fallback must never silently weaken security or authorization semantics.

## Deprecation

Stable surfaces are deprecated before removal whenever practical.

For pre-1.0 development, a Stable contract should normally remain available for at least one subsequent minor release after deprecation before removal. Security fixes may require faster action; such exceptions must be documented with migration guidance.

Deprecated behavior must not be silently repurposed with different semantics.

## Extension manifest

`contracts/extension-manifest.schema.json` defines the first public machine-readable extension boundary.

The manifest declares:

- manifest schema version;
- extension identity and SemVer version;
- compatible 1337 core release range;
- required public contract schema versions;
- declared extension entry points;
- optional capability identifiers.

The manifest intentionally does **not** contain secrets, credentials, license material, executable source, or environment-specific absolute paths.

The concrete implementation locator syntax in `entry_points.*[].target` is intentionally not frozen by M0. Packaging/SDK work will define how locators are resolved while preserving the manifest structure or versioning it explicitly if an incompatible change is required.

## Entry-point families

Compatibility Contract v1 reserves these extension families:

- `tool_adapters` — security-tool/executor adapters;
- `commands` — additional command implementations;
- `reporters` — report/output providers;
- `integrations` — external-system connectors.

Adding a new optional family is backward-compatible when existing manifests and consumers remain valid. Changing the meaning of an existing family incompatibly requires a new manifest schema version.

## Capability identifiers

Capabilities are opaque, lowercase machine-readable identifiers such as:

```text
scanner.example
report.html
integration.example
```

A capability identifier advertises a declared ability; it is **not** authorization to execute that ability. Runtime scope, impact, authorization, and policy checks remain mandatory.

## Security boundary

Compatibility is never a reason to weaken security.

- Unknown or unsupported contract versions fail closed at security-sensitive boundaries.
- Extension metadata must not grant implicit authorization.
- Secrets must not be stored in public manifests.
- A compatible extension is still subject to scope, impact, executor, and evidence-integrity rules.
- Public contract stability does not guarantee that an unsafe action will remain enabled when security policy changes require restriction.

## Consumer rules

External consumers should:

1. depend only on explicitly Stable public contracts;
2. declare the supported core range and schema versions;
3. validate manifests/schemas before activation;
4. treat unknown required fields/versions according to the schema rather than ignoring them silently;
5. avoid importing or scraping repository internals;
6. run compatibility tests against every supported release line.

## Producer rules

Changes to a Stable contract require:

1. impact review against known consumers;
2. contract/schema tests when tooling exists;
3. compatibility classification: backward-compatible, deprecation, or breaking;
4. changelog/migration notes when externally visible;
5. a version/schema change when required by this policy.

## Contract index

Current versioned public contracts:

| Contract family       | Schema version | Location                                           | Status |
| --------------------- | -------------- | -------------------------------------------------- | ------ |
| Extension manifest    | `1`            | `contracts/extension-manifest.schema.json`         | Stable |

Examples are illustrative and live under `contracts/examples/`. An example does not create a new contract beyond the schema and this policy.
