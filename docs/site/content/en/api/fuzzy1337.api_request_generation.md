# Synthetic API request generation

Experimental offline generation of one anonymous synthetic request preview from
the exact original OpenAPI/Swagger JSON and canonical selected operation. The
producer validates original supported assertions, source/context identity,
serialization and encoded byte limits without traffic or authentication assembly.

`docs/API_REQUEST_GENERATION.md` and ADR 0042 define the exact partial profile,
ephemeral values, reference metadata and actual-target scope handoff. Preview
construction grants no method, impact, scope, session or execution permission.
Direct record constructors and parsing/rendering helpers remain Internal.

::: fuzzy1337.api_request_generation
