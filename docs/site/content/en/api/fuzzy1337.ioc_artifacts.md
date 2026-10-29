# Explicit IOC artifact evidence

Experimental schema-one offline acquisition and replay of explicitly supplied,
caller-owned IOC bytes. The closed `ascii-ioc-tsv-v1` profile accepts literal IPv4,
unscoped IPv6, fully qualified ASCII DNS and SHA-256 candidates. Every occurrence
retains its raw token, logical source locator, physical line and byte range,
normalization and optional original timestamp/timezone declaration. Receiver
acquisition times remain separately observed facts.

Supported symbols are `IocSource`, `IocLimits`, `IocCandidate`, `IocRequest`,
`IocSnapshot`, `IocAcquisition`, `ParseIocArtifact`, `AcquireIocArtifact`,
`ReplayIocArtifact` and `LoadIocArtifact`. Exact first-party runtime types,
reconstruction, finite budgets and immutable owning raw/receipt/snapshot manifests
protect their boundaries. `ReplayIocArtifact` requires the independent original
acquisition receipt record beside its selected snapshot record; `LoadIocArtifact`
requires both manifest identities. Callers supply the original receipt anchor
independently of the candidate snapshot. Replay reparses original bytes after
reopening or relocation; altered rehashed snapshots and coherent alternative
receipt substitutions are rejected. Refused digest/parse outcomes preserve bounded original bytes and a
truthful terminal receipt without a usable snapshot.

`Text`, `Identity`, `ObjectFields`, `JsonBytes`, `Metadata`, `Checked`,
`RequestPin`, `NormalizeToken`, `NormalizeIpv6`, `ObservationTime`, `IocEvidenceStore`,
`AcquisitionClock`, `OriginalRecord`, `Header` and module constants remain Internal.
Direct result construction or serialization never replaces original evidence
verification. Offline execution and invocation provenance remain None. Public
hashes establish local integrity, not publisher signatures or protection against
replacement of a whole trusted chain and its identifiers.

ADR 0076 and `docs/IOC_ARTIFACTS.md` define this bounded contract. Candidates do
not establish maliciousness, incidents, observed attack paths or current scope
authority. This API performs no network resolution, probing, external file
acquisition, process launch, Finding creation or canonical Core mutation. Wider
DFIR log/entity/process and incident/event schemas remain separate owner work.

::: fuzzy1337.ioc_artifacts
