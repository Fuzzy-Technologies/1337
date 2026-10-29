# Offline API import

Experimental bounded OpenAPI/Swagger JSON or explicitly selected YAML import into existing symbolic requests,
source provenance, schema summaries and authentication annotations. No server,
reference, session or authentication endpoint is contacted.

The supported parser, projection, concrete scope preflight and remaining runtime
boundaries are defined in `docs/OPENAPI.md`. Parsing helpers and direct result
constructors are Internal. Actual request values and execution remain separate.

`ImportOpenApi(..., document_format="yaml")` selects the optional
`1337[openapi-yaml]` event parser. JSON remains the default; unsafe YAML
representations and resource excess are refused before structural interpretation.
Original bytes retain their source identity and no imported source grants authority.

::: fuzzy1337.openapi
