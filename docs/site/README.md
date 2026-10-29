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

The header logo and PNG favicon reuse the exact approved
`static/images/1337-logo.png` artwork, copied under the locale's own
`assets/images/` path. Material bounds the header image height and retains its
natural width/aspect ratio. The source is the existing illustrated landscape art;
no separate icon, wordmark, crop or redesign is claimed. Verify legibility at
narrow widths and both palettes in the final rendered artifact. All three locale
builds include the same bytes; the theme/language controls remain available.

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

## Versioned API publication and release transfer

[ADR 0116](../adr/0116-immutable-versioned-api-artifacts.md) defines the finite
first-0.3 publication. After package metadata is 0.3.0, explicitly request both
independent channels:

```bash
python tools/build_api_reference.py --release-version 0.3.0
```

Latest stays in `_build/api-reference/{locale}/`. Immutable output is
`_build/api-versions/0.3.0/{locale}/`, with version-specific canonical URLs,
language links, sitemap, search and relative assets. Source links select the
release tag. The builder rejects mismatched versions and uncommitted source
inputs. It seals the second reproducible render's original bytes in
`_build/docs/1337-0.3.0-api-docs.tar.gz`, with a separate
`1337-0.3.0-api-docs.manifest.json`; it does not create another render for delivery.

Compose the independently rendered current route explicitly:

```bash
python tools/compose_documentation.py \
  --product-site _build/product-site --api-root _build/api-reference \
  --version-root _build/api-versions/0.3.0 \
  --output _build/pages/site --revision FULL_SOURCE_COMMIT --base-path /1337
```

For a later publication, add a selected original archive using
`--retained-api-archive PATH --retained-api-sha256 VERIFIED_SHA256`. Both arguments
are required together. The composer validates the closed archive, complete
provenance/inventory and final links, preserving the original retained bytes.
A differing same-version tree is refused. Archive bounds are 128 MiB compressed,
512 MiB expanded tar and 20,000 regular files. Symlinks, hardlinks, traversal,
duplicate paths, extra versions and changed inventory are rejected before the
retained destination is published.

The standalone transfer verifier additionally binds a downloaded asset to a
caller-selected exact tag or accepted master-run commit, tree and timestamp:

```bash
python tools/compose_documentation.py \
  --verify-version-archive 1337-0.3.0-api-docs.tar.gz \
  --archive-manifest 1337-0.3.0-api-docs.manifest.json \
  --expected-version 0.3.0 --expected-revision FULL_MASTER_COMMIT \
  --expected-tree FULL_MASTER_TREE --expected-epoch COMMIT_UNIX_TIMESTAMP
```

The Documentation workflow uploads the sealed pair in the distinct
`api-docs-COMMIT-RUN_ATTEMPT` artifact. Release delivery must select the exact
accepted master run and attempt, reject missing/ambiguous/expired artifacts and
transfer these bytes to GitHub release assets. They are never PyPI distributions.
Once v0.3.0 exists, subsequent 0.3.0 documentation publications fetch that explicit
release pair and verify it against the tag before composing a fresh latest route.
Missing assets fail closed: the release freeze/recovery procedure restores the
original accepted artifact rather than generating replacement version bytes.
There is no automatic multi-version hosting catalog; extend the selection policy
explicitly before the next product version.

Retained acquisition uses the finite `--select-version-source` composer mode.
Only the exact repository's v0.3.0 tag/annotation/commit and release metadata are
admitted. Metadata reads stop at 1 MiB, the transfer manifest at 16 KiB and the
archive at 128 MiB while streaming, before any asset is written. Each original
HTTP read runs in an isolated child with a thirty-second parent-owned wall
deadline; the entire acquisition shares one 120-second monotonic allowance.
At most three explicit official asset-CDN redirects are followed. Metadata
redirects and other hosts/release paths are refused, and API credentials travel
only through private child stdin and API headers, never asset requests or argv.
Original bytes enter the retained directory only after tag-derived source and
transfer verification. Other package versions make no GitHub request.
