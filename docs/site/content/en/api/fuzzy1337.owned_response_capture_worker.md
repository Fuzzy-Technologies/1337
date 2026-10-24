# Internal fixed original-response worker

The installed isolated worker sends one exact request to the selected owned
literal-loopback listener. A single monotonic deadline covers connection, send,
reads and actual EOF. Only a completely admitted catalog response can produce
byte-bearing output; closed refusals contain no rejected response bytes or hashes.

The worker grants no permission, follows no redirect and performs no security
assessment. See `docs/OWNED_RESPONSE_CAPTURE_CONTRACT.md`.

::: fuzzy1337.owned_response_capture_worker
