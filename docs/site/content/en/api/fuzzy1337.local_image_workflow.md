# Experimental governed local Docker export

PlanLocalImageExport creates a pure source descriptor without filesystem reads, scope
mutation or process execution. ExportLocalImage requires independently registered
source scope, current permission and explicit SAFE workflow approval. It inspects the
original local reference, saves only its immutable config ID, verifies original
Docker-save bytes and rechecks the original reference.

LocalImageExportSummary returns an accepted archive pin only after a terminal
completed job and an exact typed workspace Save acknowledgement followed by exact
expected-revision readback. Suppressed, stale, wrong or lost acknowledgements retain
explicit uncertainty and expose no accepted pin. A file left after failed
acknowledgement does not establish export acceptance. The canonical model is
unchanged by export.

Use a separate scope, native Trivy permission and workflow approval to scan the
resulting archive. The optional expected_image_identity is checked against fresh
Metadata.ImageID before candidate projection or model Save. Low-level
LocalImageExportWorkflow and its persistence/lifecycle helpers are Internal. Genuine
daemon/provider acceptance is a distinct CI requirement; source or inert tests alone
do not establish it.

See `docs/LOCAL_IMAGE_REFERENCE.md` and ADR 0114.

::: fuzzy1337.local_image_workflow
