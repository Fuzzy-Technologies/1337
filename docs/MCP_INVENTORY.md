# Offline MCP inventory

The Experimental version-one API admits an explicitly selected, caller-owned
Model Context Protocol (MCP) metadata snapshot into an existing Workbench
workspace. The source is UTF-8 JSON. The SDK uses the workspace model, scope,
and immutable evidence owners. It performs local file and storage operations
only.

## Input profile

The root requires an integer `schema_version` of `1` and a `server` object.
The server declares string `name` and `version`; it may declare
`protocolVersion` in `YYYY-MM-DD` form, `title`, and `description`.
The caller selects the server's stable Workbench key separately. An optional
root `instructions` string preserves a redacted change signal when present.

Each optional section uses `{"status": "...", "items": [...]}`. Status is the
producer's assertion about this declaration set. It is neither verified server
behavior nor proof of any permission to interact with a server.

| Status        | Items                    | Meaning                                              |
| ------------- | ------------------------ | ---------------------------------------------------- |
| `complete`    | Empty or populated       | The selected inventory reports a complete section.   |
| `incomplete`  | Empty or populated       | The source reports a partial enumeration.            |
| `unsupported` | Empty                    | The source reports that enumeration is unsupported.  |
| `unknown`     | Empty or section omitted | The source supplies no enumeration status or data.   |

Only an explicit complete section with zero items declares an empty inventory
for that section. A partial or unknown section leaves membership undecided.
Status words written as JSON strings are required for every supplied section.

| Section              | Item fields                                                                    | Identity                                         |
| -------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------ |
| `capabilities`       | `name`, optional `declaration` object                                           | Name                                             |
| `tools`              | `name`, required object-root `inputSchema`, optional `outputSchema` and `annotations` | Name                                             |
| `resources`          | `name`, `uri`, optional `mimeType` and non-negative integer `size`               | Fingerprint of the normalized locator            |
| `resource_templates` | `name`, `uriTemplate`, optional `mimeType` and non-negative integer `size`       | Fingerprint of the normalized template           |
| `prompts`            | `name`, optional `arguments` with `name`, `description` and boolean `required`   | Name                                             |

Tools, resources, templates, and prompts support optional string `title` and
`description`. Known capability flags are `listChanged` on tool, resource, and
prompt declarations and `subscribe` on resource declarations. The tool hints
are `readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint`. An
omitted flag or hint remains unknown, including when its annotations object is
missing. An explicit boolean is a source declaration. The normalization
preserves optional annotation titles as opaque fingerprints.

The profile permits `_meta` and `icons` on server or descriptor records, tool
`execution`, and resource/template `annotations` so producers can supply
descriptors already using those fields. Their contents are omitted. Unconsumed
capability fields and JSON Schema keywords set explicit omission flags. Other
unexpected envelope or descriptor fields cause a profile error. The closed
envelope admits declaration metadata only. A raw wire transcript,
launch configuration, credential store, resource content, or rendered prompt
is outside this profile.

Limits are 256 KiB each for source and redacted evidence, 12,000 JSON nodes
(counting keys), depth 20 from the root, 8 KiB per UTF-8 string, and 128
items per descriptor, argument, or schema array consumed by the profile.
Tool, prompt, argument, and capability names use up to 128 ASCII letters,
digits, periods, underscores, or hyphens. The model's existing 64 KiB per
attribute map and 8 MiB per snapshot limits apply. Duplicate JSON keys,
repeated declaration identities after normalization, malformed UTF-8, and
non-finite numbers are rejected. A malformed declaration fails before
publishing model or evidence state and includes a fixed component path.

## Retention and redaction

The profile retains structural schema metadata such as types, field names,
required lists, nested schemas, alternatives, and numeric or boolean
constraints. Schema `default`, `examples`, `const`, and `enum` values are
omitted, with a redaction marker for each keyword. Schema URI and pattern
text are opaque fingerprints. The result describes a declaration for review
and cannot serve as a JSON Schema validator or a request template.

Only fingerprints are retained for incoming prose, implementation names and
versions, resource names, media types, and resource locators. Fingerprints
are computed after removing recognizable inline credentials, HTTP auth
values, common credential-shaped tokens, and URI userinfo. Resource locators
additionally omit query strings, fragments, and URI-template query/fragment
expressions. Distinct source resource locators that collapse to the same
identity are refused, rather than merged or treated as absent. URI schemes
and structural names remain visible metadata, with recognized credential
spellings rejected or omitted. No reference, template, or prose is resolved,
rendered, or sent for interpretation.

The caller supplies non-secret logical keys and actor/consent references, and
must keep credentials out of identifiers, schema names, and structural fields.
The redactor recognizes specific credential spellings and does not identify
arbitrary secrets hidden inside otherwise legitimate metadata. Fingerprints
are deterministic change signals and do not encrypt low-entropy text. Rotations
solely in redacted fields cannot change the normalized snapshot.

## Import and verification

Use an existing workspace, scope, and model. The example uses the
[checked-in catalog fixture](../tests/contract/fixtures/mcp.inventory.v1.json)
and requires no service or credentials.

```python
from pathlib import Path

from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.mcp_inventory import ImportMcpInventory
from fuzzy1337.model import LocalModelStore

model = LocalModelStore(Path("catalog-workspace"))
result = ImportMcpInventory(
    model,
    Path("tests/contract/fixtures/mcp.inventory.v1.json"),
    serverKey="catalog",
    scopeId="catalog",
    consent=ArtifactReadConsent("actor:operator", "consent:owned-file"),
    observedAt="2026-11-26T12:30:00+00:00",
    expectedRevision=model.Open().revision,
)
```

The existing file reader validates each selected file as bounded, stable, and
singly linked. `ParseMcpInventory` is the equivalent byte-only normalization
entry point and performs no I/O. `ImportMcpInventory` returns the new or
unchanged model, delta, server reference, snapshot reference and redacted
evidence manifest reference. A distinct observation time or consent reference
records another acquisition. The same normalized inventory with the same
attribution is a no-op, including when declarations are reordered or replayed
after a newer acquisition. A changed acquisition preserves stable server and
descriptor identities. This lets consumers compare snapshot membership without
treating old retained objects as current or a partial omission as a removal.

To recover a historical snapshot, resolve its `mcp-inventory-snapshot`
observation in `LocalModelStore.Open()`. Call
`LocalEvidenceStore(workspace / "evidence").Get(observation.provenance.run_reference)`
to verify its manifest and bytes, then `Read(record.reference)` to retrieve the
exact redacted acquisition document. Its `inventory` is the historical
declaration, including its schema metadata, and its `snapshot_digest` matches
the immutable observation. The report reader verifies model-linked evidence
bytes through the existing reporting path. This import does not separately
update the workspace's manifest index.

See [ADR 0158](adr/0158-owned-offline-mcp-inventory.md) for identity, storage
sequencing, and compatibility details.
