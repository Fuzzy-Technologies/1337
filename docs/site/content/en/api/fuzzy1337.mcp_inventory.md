# fuzzy1337.mcp_inventory

The Experimental version-one API imports one explicitly owned offline MCP
inventory into the existing Workbench model. `ParseMcpInventory` checks and
redacts bounded JSON bytes. `ImportMcpInventory` imports a selected local
file with explicit scope and read attribution and returns the model delta,
immutable snapshot observation and redacted evidence record.

The inventory preserves declared capabilities, schemas, annotations, resources,
templates and prompts as bounded inert metadata. An explicit complete empty
section is distinguishable from an unsupported, unknown or incomplete one.
`McpInventoryImport` is the acknowledged import result. Local file and
workspace storage are the only I/O performed by the API.

::: fuzzy1337.mcp_inventory
