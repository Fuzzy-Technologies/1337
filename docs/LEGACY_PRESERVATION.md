# 1337Scope historical preservation ledger

The checked [source ledger](../tests/fixtures/legacy_preservation/ledger.v1.json)
records all **19 reviewed behavior families** and **60 numbered XSS design rows**
from the recovered WebEngine and authored QA archives. It is a preservation
snapshot for [issue #409](https://github.com/Fuzzy-Technologies/1337/issues/409),
with narrower accepted source/test references and explicit planned detector work.

The current source references are anchored to accepted `develop` commit
`c016e2f169b8fdf5142181d289a08db39faa606e`. A reference to an existing test
identifies its narrower contract; it is not a new test execution or evidence that
the full historical family has been transferred.

## Family ownership

The following table is checked against the same machine-readable ledger.
`partial` records a finite existing contract with stated remaining work;
`planned` records missing native behavior; `shared-foundation` reuses existing
modern infrastructure. None is an assertion of complete historical acceptance.
Each family also records its source byte hash, line anchors and distinctive
preservation requirements.

<!-- preservation-families:start -->
| Family                                               | Disposition       | Owning work                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ---------------------------------------------------- | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Request delivery and composite injection coordinates | partial           | [#58](https://github.com/Fuzzy-Technologies/1337/issues/58), [#207](https://github.com/Fuzzy-Technologies/1337/issues/207)                                                                                                                                                                                                                                                                                                                |
| Recursive JSON and XML mutation                      | partial           | [#207](https://github.com/Fuzzy-Technologies/1337/issues/207)                                                                                                                                                                                                                                                                                                                                                                             |
| Discovery, extraction, forms and combinations        | partial           | [#59](https://github.com/Fuzzy-Technologies/1337/issues/59), [#155](https://github.com/Fuzzy-Technologies/1337/issues/155), [#157](https://github.com/Fuzzy-Technologies/1337/issues/157)                                                                                                                                                                                                                                                 |
| Supplied authentication and session success          | planned           | [#146](https://github.com/Fuzzy-Technologies/1337/issues/146), [#155](https://github.com/Fuzzy-Technologies/1337/issues/155), [#157](https://github.com/Fuzzy-Technologies/1337/issues/157)                                                                                                                                                                                                                                               |
| Soft-404 and dynamic error calibration               | planned           | [#410](https://github.com/Fuzzy-Technologies/1337/issues/410)                                                                                                                                                                                                                                                                                                                                                                             |
| Technology and version observations                  | planned           | [#410](https://github.com/Fuzzy-Technologies/1337/issues/410), [#47](https://github.com/Fuzzy-Technologies/1337/issues/47)                                                                                                                                                                                                                                                                                                                |
| SQL error and boolean differential inference         | planned           | [#411](https://github.com/Fuzzy-Technologies/1337/issues/411), [#207](https://github.com/Fuzzy-Technologies/1337/issues/207)                                                                                                                                                                                                                                                                                                              |
| Bounded SQL timing inference                         | planned           | [#411](https://github.com/Fuzzy-Technologies/1337/issues/411)                                                                                                                                                                                                                                                                                                                                                                             |
| Reflected XSS context and filter inference           | planned           | [#412](https://github.com/Fuzzy-Technologies/1337/issues/412)                                                                                                                                                                                                                                                                                                                                                                             |
| Browser confirmation and stored XSS correlation      | planned           | [#412](https://github.com/Fuzzy-Technologies/1337/issues/412), [#155](https://github.com/Fuzzy-Technologies/1337/issues/155), [#157](https://github.com/Fuzzy-Technologies/1337/issues/157)                                                                                                                                                                                                                                               |
| File inclusion, traversal and resource proof         | partial           | [#413](https://github.com/Fuzzy-Technologies/1337/issues/413), [#147](https://github.com/Fuzzy-Technologies/1337/issues/147)                                                                                                                                                                                                                                                                                                              |
| Inert upload and returned-resource validation        | planned           | [#413](https://github.com/Fuzzy-Technologies/1337/issues/413)                                                                                                                                                                                                                                                                                                                                                                             |
| HTTP and meta redirect assessment                    | planned           | [#414](https://github.com/Fuzzy-Technologies/1337/issues/414)                                                                                                                                                                                                                                                                                                                                                                             |
| Header injection and response splitting              | planned           | [#414](https://github.com/Fuzzy-Technologies/1337/issues/414), [#97](https://github.com/Fuzzy-Technologies/1337/issues/97)                                                                                                                                                                                                                                                                                                                |
| Code, command, SSI and historical execution variants | planned           | [#415](https://github.com/Fuzzy-Technologies/1337/issues/415), [#98](https://github.com/Fuzzy-Technologies/1337/issues/98)                                                                                                                                                                                                                                                                                                                |
| XML parser and entity-resolution assessment          | planned           | [#416](https://github.com/Fuzzy-Technologies/1337/issues/416), [#207](https://github.com/Fuzzy-Technologies/1337/issues/207)                                                                                                                                                                                                                                                                                                              |
| Session, cookie, URL and HTTPS form posture          | planned           | [#417](https://github.com/Fuzzy-Technologies/1337/issues/417), [#146](https://github.com/Fuzzy-Technologies/1337/issues/146), [#155](https://github.com/Fuzzy-Technologies/1337/issues/155)                                                                                                                                                                                                                                               |
| Error exposure and bounded hidden resources          | partial           | [#410](https://github.com/Fuzzy-Technologies/1337/issues/410)                                                                                                                                                                                                                                                                                                                                                                             |
| Evidence, findings, jobs and deduplication           | shared-foundation | [#53](https://github.com/Fuzzy-Technologies/1337/issues/53), [#57](https://github.com/Fuzzy-Technologies/1337/issues/57), [#59](https://github.com/Fuzzy-Technologies/1337/issues/59), [#92](https://github.com/Fuzzy-Technologies/1337/issues/92), [#95](https://github.com/Fuzzy-Technologies/1337/issues/95), [#96](https://github.com/Fuzzy-Technologies/1337/issues/96), [#97](https://github.com/Fuzzy-Technologies/1337/issues/97) |
<!-- preservation-families:end -->

## Exact XSS source rows

Stable IDs `legacy.xss.001` through `legacy.xss.060` retain the actual numbered
source ordering: reflected/stored, GET/POST/cookie/header/URL, and six documented
output contexts. Each row binds the original QA page hash, source row number,
and SHA-256 of the exact extracted historical label encoded as UTF-8 without a
newline. Original Russian labels, payloads, target addresses and legacy code are
not copied into the public fixture. English structured columns preserve their
meaning; a source-label digest is not a digest of its English translation.

All 60 rows historically marked their target ready; exactly 21 marked an
autotest ready. These are documentation annotations, **not run results**. Every
current case remains `not-run`, with no invented current test ID or run evidence.
The finite native XSS implementation belongs to
[#412](https://github.com/Fuzzy-Technologies/1337/issues/412). Existing external
reflection checks cannot satisfy these native/browser/stored cases.

Six additional mindmap/design groups preserve quote/event/tag distinctions,
non-executable controls, redirect/meta/data contexts, browser support decisions
and protection levels. The historical 60 rows declare no protection; additional
protected-level cases are not fabricated as source rows. Browser-specific old
variants require a deliberate modern support/defer/retire decision.

The QA requirement records separately preserve exact discovery sets, loops and
duplicates, malformed MIME/framing/stress cases, AJAX/form behavior, supplied
authentication, transport/proxy profiles, result states, operator effort versus
scanner duration, release comparisons and finite SQL dialect/environment choices.

## Validation and report boundary

Run the finite contract selection with the locked development environment:

```bash
uv run --locked --extra dev pytest tests/contract/test_legacy_preservation.py \
  -o addopts='' --no-cov -n 2
```

The checks validate the strict schema, unique source/case identities, complete
19/60 conservation, exact 21 readiness annotations, live referenced test symbols,
all new detector owners and the five existing preservation owners. Negative
cases reject dropped rows, aliases, orphaned sources, unowned work and fabricated
runtime credit. The table above cannot drift from the manifest.

A producer/consumer check passes these historical case identities through the
existing `ScenarioOracle` / `BuildReport` / JSON, Markdown and HTML projections.
It deliberately supplies no scanner runs, preserving `not-run` and withholding
accuracy. These projections are contract evidence for the ledger/report boundary;
they do not execute the old or new scanner.

The original archives are identified by content hashes, but are not distributed.
The recovered wiki does not establish availability of every original executable
trap target or autotest. Recreating controlled modern fixtures, completing all
runtime mappings, expanding every mindmap variant and comparing two actual
versioned result bundles remain follow-on work under #409 and the detector tasks.
