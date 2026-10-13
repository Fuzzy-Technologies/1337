# fuzzy1337.page_capture_worker

Internal packaged ADR 0052 one-connection worker for an already governed owned
loopback request. Direct invocation establishes no authorization. It independently
rechecks exact URL, canonical argv tokens, closed catalog and numeric quotas before
the socket is created. No DNS, environment proxy, browser, credentials, redirect,
retry or additional request is supported.

One monotonic deadline covers connection, send, complete strict CRLF headers,
exact declared body and final EOF. Only a complete status-200 UTF-8 HTML response
whose exact 541-byte body matches the reviewed SHA-256 is retained. Status reason
and unknown header values are discarded. Unsupported encodings/framing, excess,
truncated, changed or timed-out responses emit only a fixed canonical failure
record and truthful process exit code, with no stderr or exception text.

Successful stdout contains exact measured normalized metadata and base64 of only
already admitted known non-secret bytes. Parent record/evidence validation remains
independent. The hash allowlist is neither general secret detection nor collector,
service ownership or transport authentication.

::: fuzzy1337.page_capture_worker
