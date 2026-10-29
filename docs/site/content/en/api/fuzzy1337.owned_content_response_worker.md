# Internal bounded original-content response worker

The installed worker sends one exact anonymous GET to an explicitly selected
canonical literal-loopback URL. One five-second monotonic deadline covers
connection, send, reads and actual EOF. It admits complete bounded Content-Length
responses with UTF-8 HTML or plain-text bodies before emitting original byte
descriptors. Closed refusals contain only a fixed safe category.

This is an Internal worker protocol, not a supported extension API. Direct
invocation grants no acquisition or retention permission. The governed workflow
owns authorization, cancellation, original evidence custody and persistence; the
worker performs no security assessment. See
`docs/OWNED_CONTENT_RESPONSE_CAPTURE_CONTRACT.md`.

::: fuzzy1337.owned_content_response_worker
