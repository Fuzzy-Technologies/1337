# fuzzy1337.mcp_inventory

The Experimental version-one API retains explicitly owned MCP inventories
in the existing Workbench model. `ParseMcpInventory` checks and
redacts bounded JSON bytes. `ImportMcpInventory` imports a selected local
file with explicit scope and read attribution and returns the model delta,
immutable snapshot observation and redacted evidence record.

The inventory preserves declared capabilities, schemas, annotations, resources,
templates and prompts as bounded inert metadata. An explicit complete empty
section is distinguishable from an unsupported, unknown or incomplete one.
`CollectAndImportMcpMetadata` uses the reviewed HTTP metadata collector
for one approved endpoint and binds the negotiated revision, exact scope
and operator consent to redacted model history. `McpInventoryImport` is
the acknowledged import result for either source. Publication and
historical receipt-validation helpers are Internal.

::: fuzzy1337.mcp_inventory
