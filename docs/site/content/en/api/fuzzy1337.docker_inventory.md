# fuzzy1337.docker_inventory

This Experimental offline input profile imports caller-owned Docker container
inspect JSON evidence into the existing Security Object Model. It connects to no
daemon or socket and executes no Docker commands or breakout techniques.

`DockerInventoryLimits` and `ApplyVerifiedDockerInspect` are the supported surface.
Other helpers remain Internal. The importer requires an existing explicit literal
HOST reference, an immutable owning `docker-inspect`/`application/json` record and
exact source/workspace/scope/version/time/reference attribution. Typed input
invariants and fixed byte/collection ceilings are revalidated before owning reads.

Host-scoped container, network, configured service and mount resource facts reuse
existing canonical identities. Image config digests reuse `ImageIdentity` and keep
manifest digests separate. Selected configuration, state, addresses, ports and
mount relationships retain original evidence; unknown facts remain unknown.
Environment, labels, commands, health output and arbitrary provider fields are
omitted from normalized metadata.

Direct OPEN findings describe configured conditions, preserving operator triage
on source refresh. Relations issue no reachability or physical exploitability
assertion; explicit existing reachability projections remain UNKNOWN without
independent admitted assessments. One in-memory transition is ready for the
caller's canonical save; exact replay and workspace relocation preserve identity.
See [Owned Docker inventory](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/DOCKER_INVENTORY.md)
and [ADR 0070](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/adr/0070-owned-docker-inspect-inventory.md).

::: fuzzy1337.docker_inventory
