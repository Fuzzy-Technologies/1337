# Synthetic API request generation

Experimental offline generation of one anonymous synthetic request preview from
the exact original OpenAPI/Swagger JSON/YAML and canonical selected operation. The
producer validates original supported assertions, source/context identity,
serialization and encoded byte limits without traffic or authentication assembly.

`docs/API_REQUEST_GENERATION.md` and ADR 0042 define the exact partial profile,
ephemeral values, reference metadata and actual-target scope handoff. Preview
construction grants no method, impact, scope, session or execution permission.
Direct record constructors and parsing/rendering helpers remain Internal.

`GenerateOpenApiRequest(..., document_format="yaml")` must use the same explicit
interpretation as the original import. Exact source bytes and context remain
bound; previews perform no transport, authentication assembly or model Save.

::: fuzzy1337.api_request_generation
