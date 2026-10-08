# Documentation platform tooling

1337 adopts the portable Fuzzy Technologies documentation blueprint introduced
in FuzzyRoutines PR #261. The product site remains Jekyll; this directory owns
the separate static API reference. See ADR-0016 for the composition contract.
Documentation packages are development tooling and never runtime dependencies.

## Build and validate

From the repository root with Python 3.11 or later and `uv` installed:

```bash
python tools/locale_documentation.py validate
python tools/build_api_reference.py
```

The builder provisions a disposable environment outside the checkout from the
complete, SHA-256
hashed `docs/requirements-api.lock`, builds a wheel, installs it without runtime
dependencies, and launches an isolated Python process. Griffe inspection is
disabled. An import tripwire rejects every attempt to import `fuzzy1337`.
Installed wheel sources are the only configured Python-handler paths; every Python
source byte must match the reviewed checkout before rendering.

Outputs are `_build/api-reference/en/`, `_build/api-reference/ru/`, and
`_build/api-reference/zh-cn/`. `_build/docs/api-build.json` records deterministic
file digests, page counts, and runtime-import evidence. Search output, module
anchors, statically analyzed source blocks, local resources, cross-page anchors,
every inventoried public symbol anchor, and formula rendering resources are
mandatory output gates.

The reference opens in the dark palette by default, regardless of the operating
system's appearance. The header includes a light/dark toggle; the browser remembers
the reader's explicit choice. Its language selector links English, Russian and
Simplified Chinese routes and keeps the current page when switching languages.
Missing translations continue to show the explicit English fallback notice.

## Extend the reference

Add each source module to `api-coverage.toml` and its authored English page to
`content/en/api/`. Excluding a module requires a reason. Navigation derives from
the manifest in module-name order. The authored implementation owns canonical
symbol identity; package reexports are rendered without duplicating that identity.
No runtime import or dynamic discovery is permitted.

Inspect changed canonical units with:

```bash
python tools/locale_documentation.py inventory
```

Review English changes before updating the matching unit's `sourceHash` in
`docs/i18n/units.toml`. The inherited `fuzzy-doc-unit-v1` hash binds identity,
kind, signature, and source body. Path changes preserve stable page IDs.

Russian and Simplified Chinese translations begin as `missing`; generated pages
show a visible English fallback. The builder never creates translation approvals.
This initial renderer rejects any target state other than `missing`; reviewed
translation selection must be implemented before publishing draft or approved
resources. It cannot silently substitute English for an approved translation.
Approval requires the accountable editorial/technical or mathematical roles,
UTC review time, reviewer identity, and reviewed source hash defined by the
validator. Changed English invalidates approved translations as `stale`.

## Dependency and asset maintenance

Review version changes in `docs/requirements-api.txt`, then regenerate the full
transitive lock with `uv pip compile docs/requirements-api.txt -o
docs/requirements-api.lock --generate-hashes --universal`. Repeat strict builds and unit
tests before review. Product dependency metadata and `uv.lock` remain independent.

The vendored MathJax 3.2.2 SVG renderer is Apache-2.0 licensed; its upstream
license is adjacent to the bundle. It renders mathematical glyphs as SVG paths
without remote font or CDN dependencies. Preserve the license during upgrades.
