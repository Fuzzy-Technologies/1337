# fuzzy1337.workspace

This Experimental version 1 library owns portable workspace metadata and explicit
creation, reading, and revision-checked saving. Scope and object references remain
opaque context; they do not authorize execution or implement a domain model.
Lifecycle consumers use `WorkspaceStore`, `WorkspaceConfiguration`,
`WorkspaceState`, and `LocalWorkspaceStore.Create`, `.Open`, and `.Save`.
Other implementation helpers remain internal.

::: fuzzy1337.workspace
