# Internal native configuration material worker

This fixed installed reader handles only private create/verify requests on
supported Linux x86_64 ownership. It copies one explicitly read-authorized source
with a 4096-byte admission limit, the selected executable with a 256-MiB limit,
and empty material. It never executes Trivy.

Verification checks the exact staged source and scanner bytes, selected original
executable, manifests, physical identities and pinned candidate hash. UTF-8 is
decoded from those same bounded verified source bytes. The original source is
not reopened after capture. Existing 64-KiB reads may return one over-limit
buffer during growth; refusal occurs before that buffer is hashed or copied.

Private controls and responses require strict canonical JSON within 64 KiB and
exact request, owner, workspace and stage associations. Unknown files or changed
scratch identity refuse observation. Returned metadata is descriptive; only the
original parent observer can issue an instance-bound material proof after
confirmed terminal cleanup. See ADR 0109.

::: fuzzy1337.native_configuration_material_worker
