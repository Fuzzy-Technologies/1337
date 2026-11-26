# ADR 0158: Owned offline MCP inventory

- Status: Accepted for offline inventory import
- Date: 2026-11-26
- Related work: #548, #549, #550, #551; ADR 0020, ADR 0023

## Decision

Define the Experimental version-one [MCP inventory](../MCP_INVENTORY.md)
as a bounded UTF-8 JSON profile and independent byte parser. A local file
import uses `ReadArtifactFile`, explicit `ArtifactReadConsent`, and a
caller-selected server key and existing scope. It performs no external I/O
or registered target mutation. The library owns import so later collection
and operator commands can consume the same model without a new owner.

Use the existing `ObjectKind.SERVICE` identity key `mcp:v1:<server-key>`
within the caller's workspace. The case-sensitive source names or redacted
locator fingerprints identify `ObjectKind.ASSET` descriptors under
`mcp:v1:<server-key>:<kind>:<key>`. Names are unique per descriptor
kind. A `CONTAINS` edge records the server's declaration of that descriptor.
The inventory uses existing generic attributes `mcp_inventory` and
`mcp_descriptor`. The core model format and existing enums stay unchanged.

An immutable `mcp-inventory-snapshot` observation commits the normalized
inventory digest, declared server fields, instructions fingerprint, and
per-section status and object IDs. Accepted imports preserve attributed
model history. A new acquisition updates the latest imported projection,
while exact prior acquisition replay preserves the current projection.
Earlier observations and data remain available through their evidence
reference. Consumers determine membership from a selected observation;
unobserved members of an incomplete section are unknown.

Use the existing evidence owner with the
`mcp-inventory-redacted` role and `mcp-inventory-local` source at
`offline-v1`. Canonical evidence JSON binds the selected server key,
actor/consent references, immutable normalized declarations, and their
digest. The original inventory bytes, filename and raw source digest do
not enter retained evidence. Prose, URI contents, schema literal values,
launch settings and arbitrary metadata do not become model instructions,
executable values, or credential fields.

Build the complete model transition and validate it with the existing
wire-admission path before publishing the redacted manifest and blob.
Then save the model transition with the selected revision using its
normal CAS. Evidence and model publication are independent. A race or
storage error after evidence publication can leave a valid redacted record;
no rollback is inferred. The manifest ID remains in the model provenance
run reference, discoverable through the existing model and evidence stores.
The standard report reader verifies model-linked blob integrity. The
workspace manifest index and report/CI outcome changes belong to the
operator workflow.

## Verification

Use the checked-in benign fixture as the source and test against real
file, scope, evidence and model owners. Exercise unchanged canonical
identity, replay and historical membership, malformed and oversized
inputs, source references, resource locator redaction, and verified
evidence replay. Tests add synthetic credentials only to temporary
source inputs. Tripwire process startup, socket creation and DNS lookup
during actual import. Saved metadata is never executed.
