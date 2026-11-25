# Owned offline CycloneDX inventory import

`1337 sbom import cyclonedx` exposes the existing verified CycloneDX 1.6 JSON
inventory SDK through an Experimental offline operator command.
[ADR 0154](adr/0154-owned-offline-cyclonedx-import.md) reuses the established
[SPDX operator ownership and persistence flow](SBOM_IMPORT.md). The accepted SDK
format, canonical identities and inert license-declaration behavior are unchanged.

## Original file operation

The physical workspace, model and selected workspace-local offline scope already
exist. Select one caller-owned non-secret original file and its exact source
SHA-256. Actor/read-consent references describe this actual read. Source ID/version
and optional provider version are caller-declared metadata, not an observed
scanner execution. Scope attributes the source and grants no collection or
runtime authority.

```bash
1337 sbom import cyclonedx /owned/workspace \
  --file /owned/selected/inventory.cdx.json \
  --expected-sha256 EXPECTED_ORIGINAL_SHA256 \
  --owner owner:local --read-consent-reference read:owned-cyclonedx \
  --source-id inventory.owned-cyclonedx --source-version declared-export-v1 \
  --provider-version declared-exporter-v1 \
  --image-digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --image-digest-kind config --scope owned --run run:owned-cyclonedx \
  --expected-revision 0 --expected-workspace-revision 0 --json
```

Replace the expected-source placeholder with the actual agreed 64-character
lowercase SHA-256, and use the real image digest and current owner revisions.
Validate source metadata and both revisions before a bounded original read.
The byte pin must match before immutable evidence publication. The existing
four-MiB regular single-link file, non-following path, stable physical identity,
closed descriptor and known-original alias checks apply unchanged.

The container root must retain exactly the selected image SHA-256 under the
existing SDK rules. Digest kind remains an explicit caller mapping; equal hash
bytes do not establish the other image domain. Only the existing supported
top-level library/application/framework components with consistent versioned
PURLs are admitted. Unsupported versions or nested structures refuse the whole
interpretation. Declared licenses remain source facts without a compliance verdict.

Successful original interpretation records profile `cyclonedx` in its
original-manifest-bound `sbom-import-source` fact. It retains actual original read
times, actor/read descriptions, source metadata and explicit image/run mapping.
Raw bytes remain unredacted original evidence. The result returns `evidence_id`,
which identifies the original acquisition manifest, separately from the source
content SHA-256.

## Exact original replay

```bash
1337 sbom import cyclonedx /owned/moved-workspace \
  --evidence sha256:ORIGINAL_PRODUCT_MANIFEST_DIGEST \
  --image-digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --image-digest-kind config --scope owned --run run:owned-cyclonedx \
  --expected-revision 1 --expected-workspace-revision 1 --json
```

Use the original returned `evidence_id` and actual current revisions. Keep its
exact original profile, image kind/digest, scope and run. Replay forbids file-mode
source/read overrides and a replacement `--expected-sha256`; it verifies the
original manifest and complete original source instead. The external file can
be removed after the whole workspace is moved. Exact replay changes no model,
workspace or evidence bytes and calls no new acquisition clock.

An arbitrary SDK raw-only record remains outside product replay even when listed
in workspace references or already normalized through the SDK. It has no original
product read custody. Use its unchanged direct SDK interface, or perform a new
explicit owned file operation; do not invent a historical acquisition.

## Actual outcomes

The Internal schema-one result identifies `sbom.import.cyclonedx` and separate
acquisition/model/workspace acknowledgements. A changed import uses one model
revision and the independent workspace CAS owner. Previous evidence, model facts
and operator triage remain retained. A later failure can leave earlier durable
state; lost responses stay unknown and do not prove rollback.

Retained recovery is available only when the original product-custody fact is
actually present in the saved model, including a save whose acknowledgement was
lost. Reopen the saved owners, then retry that original product manifest with
their current revisions. If normalization was refused or the model never saved
the custody fact, an acquisition manifest alone cannot supply product replay.
Correct or repeat the explicit owned-file operation with its source byte pin,
read descriptions and current saved revisions. Do not promote retained bytes to
a successful historical product interpretation. No cross-store atomic transaction
is claimed.

Exit `0` requires confirmed completion, `2` is invalid configuration, `4` is
integrity/format/storage refusal or uncertainty, and `130` is interruption.
Rejected paths, source contents and exception text are excluded from diagnostics.
Inspect accepted saved packages through the existing `sbom image` view.

No network, scanner/engine, archive decoding, layer attribution, license policy,
vulnerability verdict or new model schema is added. #377 remains open.
