# Internal bounded Docker-save identity verification

VerifyDockerSave reads only the bounded in-memory Docker-save stream. It requires one
ordinary config member whose full SHA-256 equals the original inspect identity;
archive bytes, config identity and distribution manifests remain distinct. It never
extracts paths or establishes current execution authority. LocalImageArchivePin
describes the accepted bytes for a separately approved native archive operation.

See `docs/LOCAL_IMAGE_REFERENCE.md` and ADR 0114.

::: fuzzy1337.local_image_archive
