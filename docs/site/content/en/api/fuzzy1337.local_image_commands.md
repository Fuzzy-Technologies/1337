# Internal local image CLI controller

RunLocalImageCommands enrolls the Experimental image export-local command in the
installed CLI and interactive shell. Planning produces a pure exact source
descriptor. Execution requires the selected actor, existing scope and policy plus
explicit approve-local-image. The generated archive is never automatically registered
or scanned. Command handlers and parser details are Internal; the documented command
is the product surface.

See `docs/LOCAL_IMAGE_REFERENCE.md` and ADR 0114.

::: fuzzy1337.local_image_commands
