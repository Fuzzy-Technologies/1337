# fuzzy1337.graphql_import

This Experimental version-1 library imports explicitly supplied owned
introspection JSON bytes and a caller-selected endpoint. Typed root operations,
argument wrappers and input definitions retain original byte hashes and JSON
Pointers. Imported descriptions grant no authentication, scope or transport authority.

`ImportGraphQl` validates the bounded structural profile. `GenerateGraphQlRequest`
reimports the exact source/context and prepares ephemeral query or mutation
previews with finite built-in scalar, enum, list and input-object values.
Unsupported synthesis and input cycles are refused; subscriptions remain
descriptive. `ProjectGraphQl` builds existing model request metadata with caller
provenance. `CheckGraphQlTarget` checks existing exact scope membership and grants
no invocation authorization. Context helpers and decoder functions are Internal.
Consumers reject inconsistent operation/template targets and imported workspace,
source-digest or named-type contexts before projection or scope admission.

ADR 0065 and `docs/GRAPHQL_IMPORT.md` define limits and the supported subset.
Source acquisition, model persistence and evidence verification remain with their
existing owners. No live introspection, SDL parsing or request execution occurs.

::: fuzzy1337.graphql_import
