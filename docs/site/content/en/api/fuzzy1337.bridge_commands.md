# fuzzy1337.bridge_commands

Internal IMPORT-only operator facade over existing physical-file and evidence
owners. `bridge sarif import` requires an explicit existing file, SHA, workspace,
scope and actor/read-consent descriptions; `inspect` requires independently
selected original/receipt/SHA pins. It starts no provider and changes no
canonical model/workspace state.

`BridgeParser`, `BridgeArguments` and `BridgeRoot` reject malformed selections
before physical access. `RunBridgeCommands` uses `ReadArtifactFile`, complete
pure source normalization and independent original/receipt publications.
Unreturned publications remain unknown; a refusal emits no source projection.

`BridgeTerminal` stages complete portable ASCII-safe JSON or labelled source
facts within the actual byte ceiling. Source URI/path/Markdown text never becomes
an action. Failed/short writes are not retried; inspection uses retained originals
without an input file, provider, clock or owner write.

See the [operator guide](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/BRIDGE_SARIF_IMPORT.md).
All helpers remain Internal; the terminal profile is Experimental version one.

::: fuzzy1337.bridge_commands
