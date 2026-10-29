# Internal governed local image execution authority

The local-export capability is image.local-reference-export with provider
native.docker-local, SAFE impact and explicit local-docker-read privilege. Each
inspect/export/recheck command requires a separate original grant and durable one-use
claim. Current scope, actor, permission, material, invocation and exclusive expiry
remain mandatory at launch and acceptance. Original resolution and accepted archive
associations are bound to the original issuer and cannot be recreated from
dictionaries. These helpers and ArtifactPolicyEngine delegates are Internal, not
authority-issuing extension APIs.

See `docs/LOCAL_IMAGE_REFERENCE.md` and ADR 0114.

::: fuzzy1337.local_image_policy
