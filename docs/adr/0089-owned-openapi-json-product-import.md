# ADR 0089: Owned OpenAPI JSON product import

- Status: Accepted for implementation
- Date: 2026-10-23
- Related work: #144, #143, #58

## Context

The offline OpenAPI/Swagger SDK imports bounded structural operations, but the
product exposes only the original GraphQL input route. An owned-file product
route needs the same portable original custody, independently acknowledged
storage and current scope/revision controls without introducing transport.

## Decision

Add `api import openapi-json WORKSPACE`, selecting an explicitly owned physical
JSON file or an exact known original acquisition manifest. File reads require
separate actor/read-consent references. Scope, run and current model/workspace
revisions are explicit. An optional canonical `--base-url` is a resolution
context; absent and explicit values remain distinct custody choices.

Import every operation using the existing `ImportOpenApi` SDK. The first product
profile requires all resultant endpoint paths to be concrete and nonempty;
refuse path variables instead of dropping operations or inventing URL bindings.
Check every operation's exact derived URL using `CheckOpenApiTarget` and current
existing scope. Source metadata and endpoint membership grant no execution,
authentication or target-registration authority. JSON is explicit; YAML remains
an unchanged separate SDK profile.

Retain exact original JSON bytes under role `openapi-json`, source
`openapi-import`, version `1`, with a one-MiB physical-file/raw-reference limit.
Reuse the existing evidence owner, physical-file identity checks and independent
acquisition/model/workspace acknowledgement states. Retained replay requires
known original custody and the identical run, scope and base option. Each
affected endpoint owns a fixed source observation binding the acquisition,
original read consent, exact target, base option and complete operation-reference
collection. Reparse original bytes and verify the entire fact collection on replay.
Do not adopt an otherwise valid unknown manifest as original product custody.

Use existing complete `request_templates`/`openapi_operations` projections.
Occupied incompatible collections are refused; unrelated attributes and
provenance survive existing model merge semantics. Recheck current scope and
all owner bases immediately before model and workspace writes. A lost
acknowledgement remains unknown, including when the actual owner committed.

Both API routes preflight both original profiles before generic retained evidence
reads: exact roles, context, physical size, known source custody and digest/locator
aliases. Keep GraphQL defaults and existing callback boundaries compatible.
Share only helpers with actual consumers; no alternate evidence/model store or
general plugin/import framework is introduced.

## Acceptance

Use deterministic local JSON and actual product handlers/console/shell. Verify
all-operation projection and source pointers, independent original bytes,
explicit bases/read consent, source and scope refusals, occupied collections,
preserved operator data, coexistence with GraphQL, relocation/deleted-source
replay and truthful partial/unknown storage outcomes. No network, live model,
authentication, request execution or Finding is produced. Focused feature tests
run per commit; shared full integration CI runs only on final PR readiness.
