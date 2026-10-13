# Owned image scan wire fixtures

These files prepare Task #142 consumer verification. They are private test
fixtures, not a production provider, execution grant or genuine Trivy result.
No fixture builds an image, runs a container, contacts a registry or downloads
a scanner/database. No source/input or credential metadata is discovered.

`fixture_image.py` creates a 20-KiB Docker-save-shaped tar with one inert layer,
config JSON, Docker manifest, separate OCI manifest and an enumerated scenario
member. Stable regular USTAR headers make the success archive byte-reproducible.
Docker/Trivy compatibility of these manually constructed bytes is unexecuted.
The fixture contains no installed vulnerable package: package/advisory output is
explicitly synthetic interpretation data for the consumer contract.

`producer.py` is standalone and portable with the exact interpreter prefix
`(absolute_sys_executable, "-I", "-S", staged_producer_path,
"--fixture-policy", absolute_material_policy_path)`. The #278 synthetic
profile must pin both interpreter and script content. The script needs no sibling
imports, shell, shebang or caller-selected interpreter arguments. It accepts only
the independent fixed Trivy archive/version flag sequences; profile additions
or changes fail with exit `64`. Image argv fixes `--cache-backend memory`.
Immutable `material/policy.json` has exactly `schema_version`, `fixture_id`,
`provider_version`, and `database_metadata`; values match the closed synthetic
fixture. It is not executable policy, a real database, source registration or
permission to run an arbitrary scanner. No fake SQLite files are created.

The producer reads only the fixed stage `input/image.tar` and
`material/policy.json` while its working directory stays under stage `scratch`.
The fixed cache path is `scratch/cache`; it is disposable and never a source
material. Archive reads are capped at 128 KiB, each of exactly five members at
16 KiB, and scenario JSON contains only an enumerated inert string. Members are
read in memory; nothing is extracted and no scenario content is executed. These
fixture checks do not replace #278 staging, authority or TOCTOU verification.

`oracle.json` is an independently reviewed, manually committed oracle. Tests
never rewrite it. It records distinct archive/config/manifest/layer hashes, the
package-version facts and the synthetic finding interpretation expected from
image normalization. It also records failure cases for the future assembled
governed workflow. The source provider is `synthetic.trivy`; the accepted native
image importer intentionally refuses that source. Full synthetic model ingestion
requires a separately reviewed explicit fixture importer after #278, with isolated
synthetic asset keys/check IDs and no alteration of native records. No receipt,
source ID or provider version is relabelled to bypass the native guard.

The closed asset prefix is `synthetic.trivy:owned-synthetic-image-wire-v1:` for
every config image, manifest image, package, OS, layer and license key. The
Finding check is `synthetic.supply-chain.vulnerability`. Matching digest/PURL
hints never create synthetic-to-native links or promotion. The oracle includes
six native-namespace asset seeds and a dismissed native Finding with colliding
domain claims; they are owned test baselines, not genuine discovery claims.
Future integration compares each entire saved object, attribution and operator
disposition byte-for-byte after collection and historical replay. Replay remains
read-only and never reacquires authority or starts a process.

The initial #278 factory allowlists only reviewed first-party producer bytes.
This richer fixture needs independent source review and a fixed source SHA entry
before governed execution. Pinning caller-selected code does not make it SAFE.
Native profiles remain metadata-only until supplied-runtime acceptance.

| Scenario         | Wire specimen                                         | Future model acceptance                                     |
| ---------------- | ----------------------------------------------------- | ----------------------------------------------------------- |
| success          | Valid schema-2 image JSON, exit zero                   | Only after accepted receipts and exact evidence attribution  |
| no_findings      | Valid inventory, zero vulnerability proposals          | Inventory only; completeness remains `not-assessed`          |
| provider_error   | Valid success-shaped image JSON, exit seven            | Reject; preserve original execution and raw output           |
| malformed        | Incomplete JSON, exit zero                             | Reject; preserve raw output                                 |
| version_mismatch | Native version contradicts independent version wire   | Reject                                                      |
| package_mismatch | Vulnerability names a package ID absent from inventory | Reject                                                      |
| output_limit     | 4 MiB stdout plus one detection byte                   | Reject; retain executor output-limit truth                   |
| hold             | Incomplete raw prefix, then a finite 30-second wait     | Timeout/cancellation reject; owner must await process cleanup |

Input/scanner/material receipts stay separate from the image importer's exact
`stdout`, `stderr`, `provider-version` record tuple. Their provenance and source
material must be accepted independently before image interpretation.
Reporting byte verification does not attest those receipt claims.

```bash
uv run --locked python -m pytest -q --no-cov tests/contract/test_image_scan_fixture.py
```

These tests prove deterministic fixture bytes and portable wire/process ownership.
They do not prove governed product integration, genuine scanner compatibility,
database freshness, vulnerability detection accuracy or the closure of #142.
Actual integration tests wait for accepted #278 and the explicit image fixture
import boundary. Reporting #271 is accepted, but report exports from this
assembled image workflow remain unexecuted.

Format references:

- [OCI image manifest 1.1](https://github.com/opencontainers/image-spec/blob/v1.1.0/manifest.md)
- [Docker image save](https://docs.docker.com/reference/cli/docker/image/save/)
