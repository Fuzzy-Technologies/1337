# Product and API artifact composition

The existing EN/RU/ZH Jekyll product site remains the product, architecture, and
vision entry point. API documentation is built separately, without importing the
security runtime, then mounted into the same Pages artifact. This standalone
composition tool implements the artifact and validation portion of Task #222;
the integrated build, navigation, publication workflow, and owner-reviewed
rendered result remain separate acceptance evidence.

## CLI contract

Run from the repository root with the locked developer environment:

```bash
uv run --locked --extra dev python tools/compose_documentation.py \
  --product-site .tmp/product-site \
  --api-root .tmp/api-reference \
  --output .tmp/composed-pages \
  --base-path /1337 \
  --revision "$GITHUB_SHA"
```

`--revision` requires a full lowercase Git object ID (40 or 64 hexadecimal
characters). The output parent must already exist; the output directory must
not exist. Stdout is a deterministic JSON provenance object. A validation or
filesystem error returns exit status 1 and an actionable stderr diagnostic.
Incorrect CLI argument combinations return argparse's exit status 2.

API input must contain exactly the locale trees `en/`, `ru/`, and `zh-cn/`, each
with `index.html`. The product input must contain `index.html`.

| Input subtree | Composed artifact location |
| :------------ | :------------------------- |
| Product site  | `/`                        |
| `en/`         | `/api/latest/en/`          |
| `ru/`         | `/api/latest/ru/`          |
| `zh-cn/`      | `/api/latest/zh-cn/`       |

The tool preserves every existing product file byte for byte. API renderers
must generate relative links or links rooted at their final `/1337/api/latest/`
locale mount. Composition does not rewrite HTML, marketing pages, or URLs.

## Safety and failure contract

- Input trees and output paths cannot overlap, contain lexical `..` segments,
  or pass through symlinks. Nested symlinks and non-regular entries are rejected.
- Product files cannot occupy `api/latest`, the `api` directory as a file, or
  the reserved `documentation-provenance.json` name.
- Composition first copies both inputs into private staging and validates all
  local links. Copied file hashes must match the pre-copy input inventories.
- Publication reserves the absent output directory exclusively. Existing output
  is never replaced, including output created during validation by another run.
- A final move failure removes only the newly reserved output and staging.
  Consumers must wait for command success before packaging the destination;
  the sequence of moves is transactional on failure, rather than an atomic
  directory swap visible to concurrent readers.
- The final artifact allows HTML, CSS, JavaScript, JSON, XML, text, web images,
  web fonts, web manifests, root `CNAME`, and root `.nojekyll`. It rejects unknown
  extensions, source maps, PDFs, source/package files, hidden paths, and explicit
  source/test/tool/contract/evidence/credential/build directory names. Arbitrary
  secrets disguised inside allowed HTML/JSON/assets cannot be recognized by a
  file-type gate; upstream reviewed source staging remains mandatory.
- The command does not deploy, call network services, or delete previous builds.
  The deployment workflow owns protected-branch and environment authorization.

Inputs must be completed, immutable build artifacts during composition.
Filesystem cleanup failures and process termination outside Python's cleanup
handling cannot provide a transactional guarantee; CI must use an isolated
workspace and upload only after successful exit.

## Local link and anchor gate

A composed directory can also be checked independently:

```bash
uv run --locked --extra dev python tools/compose_documentation.py \
  --validate-only .tmp/composed-pages --base-path /1337
```

The gate parses rendered HTML `href` and `src` references, including self-closing
HTML elements. It verifies local files, directory `index.html` destinations,
HTML `id` and legacy named-anchor fragments. Percent-encoded paths and fragments
are decoded once; malformed escapes, backslashes, NUL, escaped artifact paths,
and unsupported URL schemes fail closed. HTML `<base>` elements are rejected
because they change reference resolution.

Absolute and protocol-relative links to the canonical
`fuzzy-technologies.github.io` host under `/1337` are validated locally too.
HTTP(S) links to other hosts or other project mounts, and `mailto`, `tel`, and
`data` references, are counted as external and never fetched. Existence checks
apply to SVG and other non-HTML assets; their fragments are not interpreted as
HTML anchors because asset-specific fragment semantics differ. CSS URLs,
JavaScript-generated references, `srcset`, remote availability, and visual
layout are outside this gate and require their own build/render checks.

## Provenance and rollback

`documentation-provenance.json` contains schema version 1, the tested source
revision, base path, locale mounts, source and final file SHA-256 inventories,
local/external reference counts, and an artifact SHA-256 identity. The identity
hashes canonical JSON of the final file inventory before adding the manifest;
this avoids a self-referential hash. The manifest contains no absolute local
paths, timestamps, or random identifiers, so identical inputs and revision
produce identical bytes regardless of staging or output location.

Retain successful complete Pages artifacts with their manifest and deployment
receipt. For rollback, select a retained artifact by tested revision and artifact
identity, re-run local validation, and use the protected publication workflow.
This tool never overwrites the previous artifact or changes repository state.

## Verification

`tests/unit/test_compose_documentation.py` exercises deterministic assembly,
preserved product bytes, locale entry points, collisions, overlapping trees,
symlinks, encoded traversal, broken anchors/assets, canonical-host links,
rollback after a synthetic publication failure, and CLI status/provenance.
These tests complement the full repository gate; they do not prove the real
Jekyll/MkDocs renderer output or an actual Pages deployment.
