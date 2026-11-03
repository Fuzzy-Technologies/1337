# Inspect verified image packages and configured Docker use

`1337 sbom image` reads an existing image from the saved canonical model and
verifies its retained original evidence through the existing report owner.
[ADR 0112](adr/0112-read-only-image-sbom-view.md) defines this small Experimental
product interface. Its implementation module and schema-one result are Internal.

```bash
1337 sbom image /owned/workspace \
  --image-digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --image-digest-kind config --json
```

Supply both digest and kind explicitly. The image must already exist through an
accepted [SBOM import](SBOM_IMPORT.md), verified image scan or inventory workflow.
Config and manifest identities stay separate even when their digest bytes are
equal. No tag lookup, manifest-to-config inference, source retrieval or scanner
execution takes place.

The successful result includes:

| Field                               | Meaning                                                        |
| ----------------------------------- | -------------------------------------------------------------- |
| `model_revision`, `snapshot_sha256` | Exact observed saved model revision and canonical content hash |
| `image_reference`                   | Selected image object, with explicit digest and kind           |
| `package_references`                | Unique packages reached through original package containment   |
| `containment_relation_references`   | Original direct edges, including accepted nested containment   |
| `inventory_status`                  | `observed` package membership, otherwise `unknown`             |
| `docker_uses`                       | Existing explicit config-image/container associations          |

Each Docker use includes `container_reference` and `relation_reference`. These
resolve the existing [owned Docker inventory](DOCKER_INVENTORY.md) facts and their
original evidence attribution. Runtime reachability stays `unknown`, with reason
`not-evaluated`: this query does not assess runtime paths or whether a package
executes in a container. Empty `docker_uses` means no qualifying supplied
association in this snapshot. It does not prove that an image is unused.

Nested SPDX package membership is traversed without flattening or writing new
relations. Dependency claims, license declarations, OS/layer objects and other
images do not supply package containment. `observed` is an inventory observation,
not a complete inventory, clean scan, license decision or vulnerability verdict.

Known original SBOM custody and aliases retain the four-MiB source limit before
generic report reads. The existing report quotas govern all retained evidence.
Missing or corrupted originals, changed model/workspace bases and a result above
one MiB refuse the whole view. A successful query writes no owner state and
returns a pinned observed snapshot, without promising live freshness.

Exit 0 means a verified view; 2 means invalid explicit configuration; 4 means
refused state, integrity, storage or quota; 130 means interruption. Failure output
contains fixed categories and no partial inventory, raw source bytes or selected
paths. Without `--json`, the command presents a concise result with the same
inventory and correlation meanings.

## Explicit license-expression policy

An optional caller-authored policy compares **source assertions** with explicit
atom decisions. The following synthetic example declares local preferences; it
does not encode a project default or choose a license for an operator:

```bash
1337 sbom image /owned/workspace \
  --image-digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --image-digest-kind config --license-policy owned-review-v1 \
  --allow-license MIT --deny-license Apache-2.0 --json
```

The result adds `license_policy` only when explicitly selected. It identifies
the complete normalized allowed/denied atom table, caller ID, finite
`spdx-expression-policy-v1` profile and a reproducible SHA-256 policy digest.
At least one rule is required, with at most 64 unique atoms across both sets;
conflicting, duplicate or compound rules are invalid configuration.

The selected SPDX **2.3.1** grammar supports uppercase `WITH`, `AND`, `OR`,
parentheses and an adjacent `+` suffix, with case-insensitive identifiers.
`WITH` binds before `AND`, which binds before `OR`. Configure a license/exception
pair as its own quoted atom, such as
`--allow-license 'GPL-2.0-only WITH Classpath-exception-2.0'`. A base rule does
not apply to an exception pair, `+` suffix or a different `-or-later` spelling.
No license-list membership or compatibility is inferred.

An `AND` expression is denied by any denied conjunct, allowed if every conjunct
is allowed, otherwise unknown. An `OR` expression is allowed by any allowed
alternative, denied if every alternative is denied, otherwise unknown. Every
supported atom is exposed, including unconfigured atoms, and the complete source
must parse before a result is returned. Expressions are limited to 2048 UTF-8
bytes, 128 tokens and 16 parenthesis levels, using bounded ASCII identifiers and
spaces. Scoped LicenseRef/DocumentRef, invalid/unsupported syntax or excess
complexity return `unknown` without a partial decision.

The product route currently supports original owned SPDX 2.3 local-graph sources
from `sbom import spdx-graph`. It revalidates exact original custody and source
context, then reparses unchanged raw bytes with the existing graph owner.
Assertions retain original observation references, acquisition manifest IDs,
document hashes and local SPDX aliases. Shared canonical packages do not borrow
declarations from another image or an equal-byte different digest kind.

Declared and concluded assertions remain separate; conflicting results are
visible separately. Omitted, NONE and NOASSERTION source information remains
unknown. Older unsupported source profiles and packages without a selected
supported assertion also remain unknown. Native/CycloneDX license assets alone
cannot supply a policy result. There is no aggregated package/image compliance
verdict, license obligation analysis or Finding creation. Exit 0 means the
verified view completed, regardless of an assertion's allow/deny/unknown result.

At most 64 original source contexts and 4096 package/assertion rows may be
projected, inside the unchanged one-MiB output bound. Exceeded quotas, original
source mismatch or changed saved bases refuse the complete view. Source facts,
triage and saved owner bytes remain unchanged. See
[ADR 0125](adr/0125-sbom-license-expression-policy.md) for the exact contract.

## Executed consumer evidence

Installed-console evidence imports original config and manifest SPDX graphs and
an owned Docker inspect document, verifies the handwritten nested-package oracle
and exact original Docker association provenance, checks equal-byte kind
separation, proves no saved bytes change, and refuses a corrupted retained raw
source. This is deterministic offline workflow evidence, not live daemon or
native scanner acceptance. The explicit policy consumer additionally preserves
conflicting declared/concluded results, exact source aliases and unknown
information states after relocation and deletion of the original selected file.

Broader image/SBOM formats, layer/file attribution, license obligations and live
Docker/Kubernetes correlation continue in [M4 task #377](https://github.com/Fuzzy-Technologies/1337/issues/377).
