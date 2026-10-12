# Offline attack reference contract

`fuzzy1337.intel_references` is an Experimental schema-v1 library for attributable
attack-pattern and behavior knowledge. It has no runtime dependencies or network
operations. Reference records can enrich a future finding interpretation while
the shared Security Object Model continues to own operational state.
The documented contract types and their methods are Experimental. Module-level
validation/JSON helpers remain Internal and do not establish extension guarantees.

## Identity, source, and review

| Value                | Meaning                                                             |
| -------------------- | ------------------------------------------------------------------- |
| `ReferenceNamespace` | Separate `capec`, `attack`, and `atlas` external identifier spaces  |
| `ReferenceIdentity`  | Namespace, case-preserved external ID, and external catalog version |
| `ReferenceKind`      | `attack-pattern` or `behavior` reference knowledge                  |
| `ReferenceSource`    | Explicit publisher, artifact, license, acquisition, importer facts  |
| `ReferenceRecord`    | Immutable identity/content with optional supplied review            |
| `ReferenceReview`    | Reviewer/time claim bound to exact record content hash              |
| `ReferenceCatalog`   | Deterministic offline records and strict versioned JSON transport   |

External catalog versions are mandatory caller-supplied release identifiers.
They are independent of the Core release and `schema_version`. External IDs are
opaque and preserve case; accepting one does not establish official membership.
No official dataset or mapping is bundled. Synthetic fixtures deliberately use
invented IDs and publisher/license labels referring only to repository fixtures.

`identity.Reference()` derives an `intel:<sha256>` ID from domain-separated
canonical identity JSON. `record.ContentDigest()` independently hashes identity,
kind, title, summary, and the complete source metadata. Editing a description or
source changes content while preserving identity. Namespace/version changes alter
identity. Neither hash contains an installation path.

Source metadata carries `origin`, `publisher`, `source_url`, `artifact_sha256`,
`license_name`, `license_url`, `acquired_at`, `importer_id`, and `importer_version`.
The source artifact hash is attributed metadata, not verification of bytes held by
this library. Callers must retain/verify authorized source artifacts and decide
redistribution rights separately. HTTPS locators cannot contain credentials,
queries, or fragments and are never fetched. No secret collection is performed.

Records begin with `review=None`. A caller may supply a `ReferenceReview` with a
reviewer, offset-aware review timestamp, and the exact content hash. Review dates
must follow acquisition, and editing content invalidates an existing attestation.
The contract validates the supplied claim; it cannot authenticate a reviewer or
establish human approval. Automation must never manufacture approval metadata.

## Consumer and serialization boundary

Resolve both identity and content when another subsystem pins an interpretation:

```python
from fuzzy1337.intel_references import ReferenceCatalog

# payload contains an explicitly supplied, authorized offline catalog.
catalog = ReferenceCatalog.Deserialize(payload)
record = catalog.Resolve(reference_id, content_sha256)
detached_bytes = catalog.Serialize()
```

`Resolve()` raises `KeyError` for a missing identity and `ValueError` for invalid
references or a mismatched pinned content revision. Omitting the content hash
performs identity-only lookup; consumers must explicitly choose that weaker pin.
No raw evidence is embedded. A finding-to-reference association requires its own
explicit rationale and evidence attribution. Membership is never evidence of a
vulnerability, observed behavior, exploitability, or a reachable infrastructure edge.

`Serialize()` emits deterministic UTF-8 JSON with `schema_version=1` and a `records`
array ordered by canonical reference ID. `Deserialize()` and `FromDict()` require
exact nested fields and recompute identity/content hashes. Duplicate identities,
duplicate JSON keys, unsupported/coerced versions, invalid text/time/hash values,
unknown fields, nonstandard constants, malformed encoding, and payloads exceeding
4 MiB fail explicitly. Direct runtime values pass the same typed/content validation.
The caller owns storage; parsing never changes workspace, model, or evidence state.

See [ADR 0033](adr/0033-offline-attributed-attack-references.md) for the decision.
