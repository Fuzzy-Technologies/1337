# fuzzy1337.image_sbom_view

This Internal command implementation projects one explicitly selected image from
an evidence-verified saved workspace. `ImageSbomView`, `RunImageSbomView` and
`MAX_IMAGE_SBOM_VIEW_BYTES` are implementation details, not supported Python SDK
extension contracts. Use the installed `1337 sbom image` product interface.

The view pins the saved model revision and snapshot digest. It follows original
package containment and reports only explicit configured Docker image-use links.
Config and manifest digest kinds remain distinct even for equal checksum bytes.
Original source custody, source-specific byte limits and the existing report
owner are verified before output. The command performs no tool invocation,
network request, evidence write or model/workspace Save.

Returned package and relation references preserve original attribution. Missing
inventory and runtime reachability remain unknown; license facts establish no
compliance result. Output is bounded to one MiB, changed saved bases refuse, and
retained original corruption prevents a successful view. See
[Owned SBOM commands](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/SBOM_IMPORT.md).

::: fuzzy1337.image_sbom_view
