# fuzzy1337.adapters.prometheus_exposition

Internal bounded legacy Prometheus exposition predicate for the Experimental
`native.prometheus-exposition` check. It validates transient UTF-8 response bytes
and supported whole-line metadata/sample syntax without retaining metric values.
Direct use establishes neither source custody nor permission to acquire a target.
See [Native web checks](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/NATIVE_WEB_CHECKS.md)
and ADR 0103 for framing, bounds and the descriptive Finding contract.

::: fuzzy1337.adapters.prometheus_exposition
