# ADR 0016: Composed Documentation Platform

## Status

Accepted design; implementation and publication require their own validated PRs.

## Context

1337 already has a Jekyll product site with English, Russian, and Chinese pages.
Those pages communicate product identity, vision, and maturity. Replacing them
with an API theme would discard a useful presentation boundary. Python source
needs a separate reference that can be checked against the packaged contracts
without importing security runtime modules or executing provider discovery.

The Fuzzy Technologies documentation blueprint in FuzzyRoutines provides portable
configuration, tooling, and provenance contracts. It is a design/tooling source,
not a runtime dependency or permission to copy another project's API text.

## Decision

Preserve the existing Jekyll product site and its public routes. Add an API
reference built with MkDocs, Material, and mkdocstrings/Griffe. Compose both build
outputs into one GitHub Pages artifact. The site base path remains `/1337`; the
API routes below are relative to that base path:

| Locale  | API route            | Content authority                        |
|---------|----------------------|------------------------------------------|
| `en`    | `/api/latest/en/`    | Canonical English source                 |
| `ru`    | `/api/latest/ru/`    | Approved translation or English fallback |
| `zh-cn` | `/api/latest/zh-cn/` | Approved translation or English fallback |

`latest` refers to documentation built from the accepted publication commit;
it must not claim that unreleased `develop` capabilities are already released.
Locale slugs in the API do not rename existing product-site URLs.
1337 selects `zh-cn` as its explicit project locale key, matching the existing
site route; this is a declared project input rather than a silent alias of
FuzzyRoutines' `zh-CN` key. Stable unit identities, canonical hash serialization,
approval model, and fallback semantics retain the blueprint contracts.

The source and build requirements are normative in
[Source Documentation Contract](../SOURCE_DOCUMENTATION.md):

- English is canonical; source digests expose translation drift and recorded
  human approvals distinguish approved translations from candidates.
- Missing translations use a visible English fallback. Stale or unapproved
  content cannot masquerade as an approved current translation.
- Static API discovery uses an explicit inventory and Griffe source parsing;
  runtime inspection, imports, provider loading, and scanner startup are forbidden.
- Strict documentation validation covers API inventory, local links/anchors,
  locale provenance, search, mathematical rendering, and generated-file cleanliness.
- A clean installed wheel must produce the same documented API inventory away
  from the checkout, with an import guard proving runtime modules were not loaded.
- Pages composition rejects output collisions and keeps package/source/evidence
  directories out of the public artifact.

Documentation tools are pinned build/development dependencies, isolated from the
installed product runtime. Adopt and adapt blueprint configuration and validators;
do not import FuzzyRoutines, copy its generated HTML, or mirror its domain content.

PR builds have read-only permissions and cannot deploy. Deployment is allowed
only from protected `master`, after applicable review and gates, using the Pages
environment and the exact composed artifact. Documentation workflow/dependency
changes follow normal development/release review; the documentation-only
publication exception cannot carry executable CI or dependency changes into
`master`. [Release workflow](../RELEASE_WORKFLOW.md) remains authoritative.

## Consequences

Positive:

- product presentation and API precision remain independently maintainable;
- documentation builds cannot accidentally start security capabilities;
- locale freshness and packaging completeness become measurable contracts;
- one artifact preserves a consistent site base path and publication boundary.

Costs:

- Jekyll and MkDocs require separate locked build environments and composition;
- localization requires review evidence and explicit fallback rather than guessed
  approval or silently stale text;
- discovery, output validation, and clean-wheel evidence need dedicated tooling.

## Non-goals

This ADR does not rename APIs, replace the product site, create a shared runtime
package, implement an automatic translation approval system, publish `develop`,
or claim that the new documentation gates have already been implemented.

## Invariant

> Documentation describes the accepted source without executing security runtime,
> hides neither translation drift nor fallback, and publishes one validated
> artifact only through the protected stable-branch review boundary.
