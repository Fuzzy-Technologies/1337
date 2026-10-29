# ADR 0116: Immutable versioned API artifacts from accepted master renders

## Status

Accepted — 2026-10-29

## Context

The API builder and Pages composer currently publish the moving
`/1337/api/latest/{locale}/` reference. The 0.3.0 delivery needs a release-specific
reference while preserving those routes and earlier published version bytes.
Copying latest HTML into a new directory would leave canonical URLs, language
navigation and sitemap entries pointing at a moving publication.

## Decision

Keep latest behavior. An explicit `--release-version 0.3.0` additionally renders
`/1337/api/0.3.0/{locale}/` independently from the same clean installed wheel.
The requested stable numeric version must match package metadata. Every route
gets its own site URL, language navigation, relative assets, search and sitemap.
The existing 180-second renderer allowance remains for latest alone; two
independent channels receive a finite 360-second allowance.
Release source links select the exact `v0.3.0` tag. English remains canonical;
RU/zh-cn remain visibly marked English fallback where translation is missing.

An immutable artifact requires committed reviewed source inputs. Embedded
`api-version-provenance.json` schema 1 binds version, commit, tree, commit-derived
source epoch, `/1337` mount, three locales and the complete generated file digest
inventory. A reproducible regular-files-only USTAR/gzip archive retains those
original bytes, with fixed metadata and no host paths. Its separate transfer
manifest binds archive filename, SHA-256, size and embedded provenance digest.

The exact accepted master Documentation run uploads
`1337-0.3.0-api-docs.tar.gz` and `1337-0.3.0-api-docs.manifest.json` in artifact
`api-docs-COMMIT-RUN_ATTEMPT`. Release delivery selects that accepted run/attempt
and exact artifact identity, validates source commit/tree/version/epoch and byte
checksums, and transfers the original archive to GitHub release assets. API
archives never enter the PyPI wheel/sdist upload directory. Release delivery must
not rebuild an already accepted master render as a replacement.

The composer accepts a separately rendered current version and one explicitly
selected retained version archive with its checksum. Retention is closed: at
most 128 MiB compressed, 512 MiB expanded tar and 20,000 regular files; no links,
traversal, duplicate paths, extra versions or unexplained file inventory. All
public allowlists and final composed link checks still apply. A repeated version
must have identical complete bytes or composition refuses. Retained artifacts
remain unchanged when latest advances.

For the finite first-release workflow, package metadata other than 0.3.0 keeps
the previous latest-only behavior. With 0.3.0 metadata and no v0.3.0 tag, build and
seal the independently rendered version. Once that exact tag exists, verify its
release archive/manifest against the fetched tag commit/tree/epoch and preserve
those bytes alongside a new latest build. An absent archive, failed query or
mismatching provenance fails closed. A genuine tag-not-found response alone
selects initial generation. There is no Pages crawl, cache trust or guessed latest
release. Later releases require an explicit reviewed extension of this finite
selection policy.

Retained network acquisition is finite during the read, not only after download:
1 MiB metadata, 16 KiB manifest and 128 MiB archive body caps apply before any
asset persistence. Isolated original read children have thirty-second wall
deadlines within one 120-second monotonic acquisition allowance. Only the fixed
repository/tag/commit/release sources and two exact asset names are admitted;
at most three validated official-CDN redirects carry no API credentials.
Metadata redirects and unknown sources fail closed. Tag dereferencing is bounded
and commit/tree/epoch come from the original fixed GitHub Git-object API, avoiding
an unconstrained repository fetch. The old package-version branch performs no
GitHub operation.

API credentials are opaque bounded Bearer values. Their envelope follows
[RFC 6750 section 2.1](https://www.rfc-editor.org/rfc/rfc6750#section-2.1)
(`b64token`), including its punctuation and trailing padding, rather than a
provider-specific token format. The existing 1024-character ceiling remains;
whitespace, control/non-ASCII characters and interior padding refuse before
transport. Credentials still travel only through private child stdin to the
fixed API request header and never to asset/CDN requests or child argv/environment.

## Consequences

- The release freeze prevents another master publication between first tag
  creation and verified archive attachment. If interrupted there, restore the
  assets from the exact accepted master run, then retry the publication; do not
  rebuild different source or replace the immutable route.
- Source-only tests use small static fixtures, including both channels and all
  three locales. They prove route, archive and refusal contracts without claiming
  an actual release, deployment or full-reference acceptance.
- Full exact-release builds, final rendered branding checks, accepted master CI,
  tag/asset transfer and public URL verification remain release gates.
