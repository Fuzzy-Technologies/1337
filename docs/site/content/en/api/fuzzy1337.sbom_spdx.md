# fuzzy1337.sbom_spdx

This Experimental library interprets verified offline SPDX 2.3 JSON package
inventory through the existing image/model/evidence contracts. The supported
surface is `SPDX_IMPORT_VERSION` and `ApplyVerifiedSpdx`; other helpers remain
Internal. One described CONTAINER root, explicit flat package containment and
versioned PURLs are required. Original bytes remain immutable.

The returned model/delta requires an explicit existing model-store save. Scoped
source aliases preserve document identities, declared/concluded licensing roles
remain distinct, and exact replay preserves prior finding triage. A generic SPDX
checksum verifies equality to a caller-declared image digest, not its OCI kind or
artifact completeness. The importer grants no execution or retrieval authority.
General dependency/file graphs, external documents, scoped LicenseRef meanings,
VEX, signatures, SPDX 3 and complete SPDX validation are outside this delivery.
See [Verified SPDX inventory](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/SBOM_SPDX.md).

::: fuzzy1337.sbom_spdx
