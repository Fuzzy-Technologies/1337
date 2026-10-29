# Internal native crawl wire worker

This fixed installed first-party worker is an internal process boundary, not a
public alternative to the governed SDK. It accepts one bounded canonical input
argument and makes one literal-loopback GET to its selected source, with no DNS,
redirect, retry, session, caller header or additional transport mechanism.

Complete bounded framing/EOF and HTML lexical admission precede any successful
digest/frontier output. Only the original admitted URL set can enter the report;
rejected href values remain transient and exclusion counters stay closed.
Non-HTML/4xx records are terminal source observations. Closed refusals have no
partial body metadata; the original worker streams are never fabricated by the
parent. Direct invocation establishes no scope, consent or permission.
See the [record boundary](fuzzy1337.adapters.native_crawl.md).

::: fuzzy1337.native_crawl_worker
