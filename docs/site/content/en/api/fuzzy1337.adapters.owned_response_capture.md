# Internal original-response record admission

This pure boundary validates the closed `owned-response-capture.v1` record against
the independently selected literal URL and frozen non-secret wire catalog. It
checks canonical JSON, exact types, original request/header/body bytes, strict
base64 and byte lengths/digests. It grants no execution authority and creates no
security Finding.

See `docs/OWNED_RESPONSE_CAPTURE_CONTRACT.md` and ADR 0095.

::: fuzzy1337.adapters.owned_response_capture
