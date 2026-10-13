# fuzzy1337.test_runner

Developer pytest orchestration keeps the per-test deadline independent of each
complete invocation's finite budget. `TestOptions` retains its existing positional
fields and adds `suite_timeout_seconds` at the end (default 600 seconds).
Both timeout domains support only integer values from 1 through
`MAX_TIMEOUT_SECONDS` (3600 seconds); unsupported values reject before dispatch,
evidence mutation or child startup without reflecting the rejected value.
`RunPytest(..., timeout_seconds)` receives that whole-invocation budget directly;
the per-test default remains 120 seconds in pytest arguments. Missing fresh JUnit
evidence cannot produce a successful result, even when the child exits zero.

::: fuzzy1337.test_runner
