# Internal OpenAPI YAML decoding

Internal optional event decoding supports the documented `fuzzy1337.openapi`
import and `fuzzy1337.api_request_generation` interfaces. These helpers construct
only bounded JSON-compatible values; they perform no file or network access,
invoke no YAML constructors, and issue no authorization. Use the owning import
APIs for exact source identity and structural validation.

The explicit restricted scalar, key, tag, alias and resource contract is described
in ADR 0061 and `docs/OPENAPI.md`; it is not a general YAML compatibility promise.

::: fuzzy1337.openapi_yaml
