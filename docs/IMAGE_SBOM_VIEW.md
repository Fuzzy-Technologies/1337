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

Installed-console evidence imports original config and manifest SPDX graphs and
an owned Docker inspect document, verifies the handwritten nested-package oracle
and exact original Docker association provenance, checks equal-byte kind
separation, proves no saved bytes change, and refuses a corrupted retained raw
source. This is deterministic offline workflow evidence, not live daemon or
native scanner acceptance.

Broader image/SBOM formats, layer/file attribution, license evaluation and live
Docker/Kubernetes correlation continue in [M4 task #377](https://github.com/Fuzzy-Technologies/1337/issues/377).
