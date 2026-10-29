# fuzzy1337.policy

This Experimental subsystem is documented by ADR 0025.
Its typed contracts are versioned independently of the product release.
Preparing or inspecting these records grants no execution authority.

`GovernedLocalExecutor.Execute(..., own_descendants=True)` forwards the optional
Linux descendant-ownership mode after the same exact-request and current-policy
checks. Its default stays `False`; request serialization and result shapes are
unchanged. Cleanup failure cannot become successful execution or authorization.
The opt-in repeats current launch validation after helper readiness and before
the worker-start acknowledgement, preserving denial before worker execution.

::: fuzzy1337.policy
