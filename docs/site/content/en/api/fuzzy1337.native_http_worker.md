# fuzzy1337.native_http_worker

Internal executable helper for the Experimental native HTTP adapter under ADR 0036.
Consumers use `NativeDiscoveryProvider` and governed execution. Calling this worker
directly does not establish consent or satisfy the product authorization contract.
The bounded literal socket/TLS path returns status-only records, suppresses response
content and does not resolve hosts or follow redirects.

::: fuzzy1337.native_http_worker
