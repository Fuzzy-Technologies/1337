# Source Documentation Contract

This contract defines the documentation target adopted by
[ADR 0016](adr/0016-composed-documentation-platform.md). It complements
[DEVELOPMENT_PROTOCOL.md](../DEVELOPMENT_PROTOCOL.md) and
[Compatibility](COMPATIBILITY.md); it does not rename APIs or change their
stability classes. Requirements below are acceptance criteria for the dedicated
source-hardening, blueprint, Pages-composition, and clean-wheel work. The ADR
alone is not evidence that those gates or the API site already exist.

## Source ownership and headers

Repository-owned Python in `src/`, `tests/`, and tooling uses this SPDX header:

```python
# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Describe the module's responsibility and relevant boundary."""
```

Preserve legitimate earlier or third-party copyright/license notices. Extending
an ownership year range requires factual provenance; do not mechanically replace
historical authors or license terms. Vendored or generated files need explicit
inventory/exclusion provenance and retain their applicable notices. Synthetic
embedded Python fixtures are audited as source where they represent project code.

Put a shebang before the SPDX header only when a script is actually executed
directly by its documented invocation. Importable modules, tests, and package
entry-point modules do not gain a shebang merely because they contain `Main()`.
Retain an encoding declaration in its Python-valid position when required.
Comments precede the module docstring; the docstring remains the first statement.

## English docstrings and API contracts

Every production/test module, class, function, and method has a concise English
docstring. Use Google-style sections when relevant to the actual contract:

- summary: responsibility or observable behavior;
- `Args`: parameter meaning, units, bounds, defaults, and security restrictions;
- `Returns` or `Yields`: result meaning and any machine-readable status semantics;
- `Raises`: caller-visible failures, including denied authorization and validation;
- additional prose: side effects, resource ownership, cancellation/cleanup,
  determinism, stability, or compatibility constraints where material;
- `Examples`: bounded, reproducible examples with synthetic data when useful.

Do not add empty boilerplate sections or restate a signature without explaining
its contract. Keep annotations and documented defaults/exceptions consistent
with the implementation. A return value indicating failure is not success, and
an example must not bypass scope, authorization, or impact controls. Do not run
security examples as documentation-build side effects.

Source identifiers retain the existing house style: PascalCase callables/classes,
snake_case variables/parameters, UPPER_SNAKE_CASE constants, and framework-imposed
names. Keep intentional vertical spacing; `ruff format` is not the formatter
contract. Docstring/header hardening must preserve evaluation order, behavior,
import paths, schemas, commands, and externally imposed names.

## Audit and static API inventory

Audit `src/`, `tests/`, and repository tooling for ownership headers, missing
docstrings, incomplete contracts, comments, annotations, and house-style drift.
Separate a reproducible finding from a proposed fix. Record file/symbol, finding,
reason, and any justified exclusion; the inventory must not silently omit a new
module or undocumented symbol.

Maintain an explicit API-coverage inventory (the blueprint's `api-coverage.toml`
role). Public/stable versus internal/experimental status comes from the project's
declared compatibility contracts, not visibility alone. Static Griffe discovery
must compare source exports/aliases and configured pages against this inventory,
failing on missing, duplicate, unresolved, or unexplained entries. Explicit
exceptions need ownership and rationale; lowering coverage to make a build green
is not an acceptable resolution.

Use static Python source parsing without importing the package. Disable dynamic
inspection fallback in mkdocstrings/Griffe. Build tools must not load adapters,
discover providers, start executors/scanners, connect to targets, or evaluate
arbitrary source expressions. An unresolved dynamic symbol requires a declared
static contract or a failing gate, not runtime inspection.

## Localization and provenance

English source and API signatures are canonical. API locale identifiers are
`en`, `ru`, and `zh-cn`; the existing product-site locale routes remain unchanged.
Canonical machine interfaces and source docstrings stay English.

A locale manifest binds each page/segment to its canonical source path and
digest, translation content digest, locale, state, and review provenance where
approved. Source changes invalidate freshness even if translated text still
looks plausible. A recorded approval identifies the reviewer and the exact
reviewed revision/digests; tooling must never synthesize a reviewer or approval.
Approval decisions are human review work, not an LLM output or build action.

Preserve the blueprint's permanent ASCII unit IDs (`page:`, `symbol:`,
`concept:`) and canonical SHA-256 payload/serialization. Do not derive identity
from translated titles or recycle an ID for another concept. States remain
`missing`, `draft`, `review`, `approved`, `stale`, and `retired`; automation may
detect missing/stale state but never approve. Editorial review is mandatory,
with technical review for mathematical or executable contracts. Adapting the
validator must not change its hash or review semantics without a superseding ADR.

Untranslated content is visibly identified as an English fallback within the
locale site and language navigation. Stale/unapproved translation candidates
cannot be published as current approved content: publish the marked canonical
fallback or fail the declared locale gate. A deliberate fallback may build
successfully, but its manifest/report must expose that state. Never count it as
approved translated coverage. Keep canonical symbol names and identifiers intact.

## Deterministic documentation gates

Pin documentation dependencies and update the lock with configuration changes.
Do not regenerate dependency state during validation or publication. Run the
same non-mutating validation entry points locally and in CI. Once implemented,
the documentation gate must establish these properties:

| Boundary          | Required evidence                                                       |
| ----------------- | ----------------------------------------------------------------------- |
| API coverage      | Static inventory matches source and rendered documented symbols          |
| Strict build      | Missing references, unresolved symbols, and actionable warnings fail     |
| Links and anchors | Internal destinations and fragments resolve, including composed routes   |
| Locales           | Digests, review states, fallback labels, and language links are consistent |
| Search            | Expected pages/symbols appear in each locale's generated search index     |
| Mathematics       | Representative formulas render; source delimiter text is not leaked      |
| Generated output  | Fresh generation is reproducible and leaves tracked sources unchanged    |
| Packaging         | Clean installed wheel yields the same API inventory without imports      |
| Public artifact   | Only allowed site output is present; conflicting routes are rejected      |

Use `$...$` and `$$...$$` in Markdown mathematical source. Configure the renderer
and delimiter handling explicitly and verify rendered output rather than treating
a successful Markdown parser as proof of mathematical rendering. Checks may use
local render/browser fixtures; they must not depend on live third-party targets.

Build into ignored output directories. Generated HTML/search indexes, caches,
package artifacts, and reports remain untracked unless a reviewed contract
explicitly makes a generated fixture source-controlled. Compare tracked files
before and after validation; never overwrite a source file to mask drift.

Negative tests must prove rejected imports/dynamic inspection, missing inventory,
broken links/anchors, stale approvals, false fallback labels, and composition
collisions where those boundaries are implemented. A skipped or unavailable gate
is reported as such; it is never converted to PASS.

## Clean installed wheel proof

Build the wheel with locked tools and install it into a new environment outside
the checkout. Resolve source/API solely from the installed artifact rather than
editable paths or checkout `PYTHONPATH`. Statically discover documented modules
there, compare the canonical inventory, and build the reference. A runtime-import
tripwire must fail if documentation tooling imports any `fuzzy1337` module;
record the exact wheel, command, and outcome. Missing wheel files fail the gate.
Documentation tooling may have its own locked dependencies; those must not become
dependencies of the base product wheel.

## Pages composition and publication

Keep Jekyll product output at the site root. Compose API outputs beneath
`api/latest/en/`, `api/latest/ru/`, and `api/latest/zh-cn/`. Configure URLs with
the existing `/1337` base path; validate cross-site links against the final
artifact, not against either component alone. Reject output collisions and path
escapes rather than silently overwriting product pages.

One composed artifact contains the reviewed product site and API reference from
the same publication commit. It excludes raw source, tests, internal contracts,
credentials, evidence, and package artifacts. Validate artifact allowlists before
uploading it. Preserve existing product routes and add API navigation explicitly.

PR jobs build/validate with read-only permissions. Deployment requires protected
`master`, required review/checks, the Pages environment, and only the permissions
needed for Pages deployment. No PR or `develop` job deploys. A manual deployment
must enforce the same branch/artifact boundary. Never publish an unvalidated
component or copy a previously successful artifact over a failed current build.

Follow [Release workflow](RELEASE_WORKFLOW.md): workflow, tool/dependency, and
machine-readable contract changes use normal integration/release review.
The documentation/site-only publication exception does not include those changes.
No deployment is implied by adopting this contract.

## Blueprint provenance

The reusable design source is the
[Fuzzy Technologies documentation blueprint](https://github.com/Fuzzy-Technologies/FuzzyRoutines/tree/develop/docs/documentation-blueprint),
introduced through
[FuzzyRoutines PR #261](https://github.com/Fuzzy-Technologies/FuzzyRoutines/pull/261).
An implementation records the exact accepted upstream revision it adapts.
Transfer only required standalone configuration/templates/validators and adapt
package names, API inventory, locales, branding, and Pages base path. Do not copy
FuzzyRoutines prose or generated HTML and do not add it as a runtime dependency.
