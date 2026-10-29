# Internal original-content response admission

This pure implementation boundary validates the closed
`owned-content-response-capture.v1` record against an independently selected
canonical anonymous literal-loopback URL. It checks canonical JSON, exact record
fields, original request/header/body bytes, strict base64 and byte lengths/digests.
Only the bounded HTTP/1.1 200, Content-Length and UTF-8 HTML/plain-text profile is
admitted; a safe refusal contains no rejected response bytes or hashes.

These Internal helpers make no contact and grant no execution, retention or
assessment authority. They are not a supported extension API. The governed
workflow owns original custody and the separate explicit acquisition/retention
selections. See `docs/OWNED_CONTENT_RESPONSE_CAPTURE_CONTRACT.md`.

::: fuzzy1337.adapters.owned_content_response
