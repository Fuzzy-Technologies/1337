# fuzzy1337.ioc_commands

The installed CLI and foreground shell expose Experimental contract-version-one
`trace ioc import|inspect`. This module is their Internal implementation: all
classes, methods, functions and helpers, including `IocParser` and
`RunIocCommands`, remain Internal and do not establish a supported Python SDK.
`IocFailure`, `IocArgumentParser`, `SelectedPath`, `ReadOwnedIoc` and
`VerifiedAcquisition` keep that same implementation status.

Import requires an existing physical workspace and one absolute explicitly owned
non-secret source file. Source ID/version, opaque logical locator, license
name/locator, exact lowercase expected SHA-256, collection scope and owner/read
references are required. The existing `ArtifactReadConsent` declaration is
validated before reading; it is neither principal authentication nor assessment
authority. The unchanged IOC receipt keeps its existing source/budget/acquisition
attribution and gains no collector-identity or consent fields. Declared locators
are data and are never opened or fetched.

Five independent positive caller budgets retain the unchanged SDK ceilings:
64 KiB bytes, 256 lines/items and 512 bytes per line/token. Original file guards
observe physical ancestors, regular kind, one link and nonzero identity before
bounded reading. Full device/inode/size/mtime/ctime identity remains equal within
the path view and within the owned handle view. The existing Windows cross-view
ctime allowance never relaxes either same-view equality. Oversize files are
refused before acquisition; one overflow byte cannot become silently truncated
source evidence. Owned read descriptors are closed after failure/interruption.
These observed guards do not claim hostile-writer OS isolation.

The handler calls the unchanged offline ASCII TSV IOC acquisition owner and
requires exact original result/record/snapshot types. It verifies raw/receipt
manifest identity, provenance, role/media/byte budgets and original request pins,
then independently reparses successful snapshots using the separately retained
receipt anchor. Supplied IPv4/IPv6/DNS/SHA-256 occurrences retain their original
tokens, coordinates and source-declared timestamps in evidence. Receiver
acquisition clocks remain separate from source-declared observation times.

Inspect requires both original snapshot and independent original receipt
manifest IDs. The candidate cannot select its own trusted receipt. Owning
manifest verification and exact original-byte reparse work after workspace
relocation and source-file removal. Source/consent overrides, current external
file reads, dataset discovery, acquisition, model/workspace saves, processes and
network operations are absent from inspection.

Schema-one terminal summaries contain counts, observed source hash/length,
acquisition times and immutable identifiers. Original tokens/source bodies,
physical filenames, declared source/license text and owner/read references do
not enter summaries or generic diagnostics. Digest/parse refusal retains
verified original raw and receipt records, supplies no usable snapshot and
remains exit `4`. `evidence_commit: confirmed` follows owning-record verification;
`unknown` after acquisition starts permits existing immutable orphan records
without claiming rollback or an atomic three-record transaction. Inspection
uses `not-attempted` because it never writes. Exit `0` means verified acquisition
or replay, `2` invalid selections and `130` interruption. Core mutation remains
`none`; publisher authentication and supplied-candidate maliciousness are not
assessed. Broader incident/entity/process/timeline semantics remain separate work.

See [IOC artifact commands](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/IOC_ARTIFACT_CLI.md)
and [ADR 0080](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/adr/0080-explicit-local-ioc-cli.md).

::: fuzzy1337.ioc_commands
