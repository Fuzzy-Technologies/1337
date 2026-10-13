# Offline API import

Experimental bounded OpenAPI/Swagger JSON import into existing symbolic requests,
source provenance, schema summaries and authentication annotations. No server,
reference, session or authentication endpoint is contacted.

The supported parser, projection, concrete scope preflight and remaining runtime
boundaries are defined in `docs/OPENAPI.md`. Parsing helpers and direct result
constructors are Internal. Actual request values and execution remain separate.

::: fuzzy1337.openapi
