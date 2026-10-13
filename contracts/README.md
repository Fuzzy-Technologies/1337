# Public Contracts

This directory contains machine-readable public compatibility contracts for 1337 Security Workbench.

Canonical policy: [`docs/COMPATIBILITY.md`](../docs/COMPATIBILITY.md).

## Current contracts

| Contract           | Schema version | File                             |
| ------------------ | -------------- | -------------------------------- |
| Extension manifest | `1`            | `extension-manifest.schema.json` |
| Local artifacts    | `1`            | `artifact-manifest.schema.json`  |

Artifact schema fields are bounded and exact; its SDK additionally enforces
sorted names, portable collision/device-name rules, role-separated aggregate
byte limits and physical selected-file integrity. This Experimental manifest is
not an OCI digest or an execution grant. Native profiles remain metadata-only.

Examples under `examples/` demonstrate valid documents but do not add fields or semantics beyond the corresponding schema and compatibility policy.

Rules:

- version schemas explicitly;
- reject unsupported versions instead of guessing;
- do not put secrets, credentials, license material, or machine-local absolute paths in public contract documents;
- treat only explicitly documented/versioned surfaces as Stable;
- keep generated/runtime state outside this directory unless it is an intentional test fixture for a public contract.
