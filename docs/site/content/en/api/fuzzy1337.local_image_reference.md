# Experimental local Docker selection

LocalImageSelection declares an absolute trusted executable, physical local Unix
endpoint, exact tagged reference or full image config ID, explicit read consent and
owning workspace. Manifest and Target produce the pure closed docker-local-
reference.v1 source descriptor without reading files or contacting Docker. The
descriptor grants neither source access nor archive scan authority. Invocation
builders, resource limits and reference parser helpers are Internal. No implicit
latest tag, ambient Docker context, registry lookup or image mutation is selected.

See `docs/LOCAL_IMAGE_REFERENCE.md` and ADR 0114.

::: fuzzy1337.local_image_reference
