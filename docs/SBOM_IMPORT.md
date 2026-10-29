# Owned offline SPDX graph import

`1337 sbom import spdx-graph` exposes the accepted
[local SPDX graph profile](SBOM_GRAPH.md) through an Experimental version-one
product command. It acquires one explicitly selected non-secret original JSON
file, applies the existing SDK graph interpretation and persists the canonical
model and workspace through their independent owners.
[ADR 0082](adr/0082-owned-offline-spdx-graph-import.md) defines this product slice.

The workspace, canonical model and selected workspace-local scope already exist.
Scope records offline attribution; it supplies no read or execution grant.
The caller explicitly declares image digest semantics. The SPDX CONTAINER root
checksum must match the selected digest; `config` and `manifest` stay separate
identities even when their checksum bytes are equal. The SDK creates the image
and reuses canonical package identities.

## Original file acquisition

Select the original file, actor/read-consent references, source ID/version and
current model/workspace revision bases explicitly. Provider version is optional
caller-declared metadata; it does not assert an observed scanner invocation.

```bash
1337 sbom import spdx-graph /owned/workspace \
  --file /owned/selected/inventory.spdx.json \
  --owner owner:local --read-consent-reference read:owned-sbom \
  --source-id inventory.owned-spdx --source-version declared-export-v1 \
  --provider-version declared-exporter-v1 \
  --image-digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --image-digest-kind config --scope owned --run run:owned-spdx \
  --expected-revision 0 --expected-workspace-revision 0 --json
```

The command performs a bounded four-MiB read of one regular, single-link original
file. Source links and linked parent directories are refused; full same-view
physical identities must remain stable throughout the read. The owned file
descriptor is closed on successful and failed paths. Original bytes remain
unredacted evidence, separate from normalized graph facts. Select only owned
non-secret exports; read references describe this acquisition and grant no
broader authority.

Both current revision bases, existing scope and workspace object references
validate before selected bytes are read. Before any generic owning evidence
reader in either mode, every known original SBOM blob fits its four-MiB ceiling
and physical size. All same-SHA/same-locator aliases in model/workspace references
and retained manifests preserve that original role/media/size. Model-only known
custody IDs are independently verified even if an earlier workspace save failed.
Older original source/provider/scope fields remain unchanged, with each older
scope checked through its own existing owner. Unrelated larger non-SBOM evidence
retains its own existing owner budgets.

## Known original replay

Use the original `evidence_id` returned by a successful product import. It is the
immutable acquisition-manifest ID, distinct from `source_sha256`. Keep its
original image digest/kind, run and scope, and select the current revision bases.
This works after moving the entire owning workspace.

```bash
1337 sbom import spdx-graph /owned/moved-workspace \
  --evidence sha256:ORIGINAL_MANIFEST_DIGEST \
  --image-digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --image-digest-kind config --scope owned --run run:owned-spdx \
  --expected-revision 1 --expected-workspace-revision 1 --json
```

Replay verifies the prior original-manifest-bound `sbom-import-source` custody
fact before reading selected raw bytes. File-mode owner/read/source/provider
overrides are refused. Changed image semantics, run, scope or an equal-content
different acquisition manifest cannot borrow this original custody. An SDK
raw-only acquisition without known product custody remains available to its
existing direct SDK interface and is refused by product replay. A distinct image
kind requires its own explicit original file acquisition.

Exact original replay changes neither model nor workspace bytes. The graph SDK
and custody observation form one model revision on a changed import. Canonical
image/package links, original source relationship indexes/directions, shared
aliases and inert license facts remain source interpretations. Existing detector
findings and operator triage stay intact. Dependency claims remain UNKNOWN for
runtime reachability without separate verified assessments.

## Actual outcomes

`--json` emits one Internal schema-one summary with original acquisition ID,
content hash, observed byte/time facts and independent `acquisition_commit`,
`model_commit` and `workspace_commit` acknowledgements. Acknowledgements distinguish
`not-attempted`, `unknown`, `confirmed` and explicit CAS `not-committed` refusal.
The original raw source and selected paths are excluded from terminal output.

| Exit | Meaning                                                                   |
| ---- | ------------------------------------------------------------------------- |
| 0    | Original import and both saved owners confirmed                           |
| 2    | Invalid explicit configuration                                            |
| 4    | Source/integrity/normalization/storage refusal or unknown acknowledgement |
| 130  | Interrupted acquisition or persistence                                    |

A later failure preserves earlier confirmed acknowledgements. Lost publication
acknowledgements remain nonzero even if an original manifest or saved revision
is present. Reopen the owning stores before deciding how to recover. The command
claims no atomic cross-store transaction, implicit rollback, scanner execution,
remote retrieval, inferred score or license compliance result.

Inspect saved accepted image packages and explicit configured Docker use with
[`1337 sbom image`](IMAGE_SBOM_VIEW.md). The read-only view keeps config/manifest
identity distinct and runtime reachability unknown.
