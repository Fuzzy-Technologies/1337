# Internal bounded pytest progress diagnostics

The shared developer runner explicitly loads this optional pytest plugin to
retain bounded completed-case diagnostics during a gate. Normal scanner and CLI
startup do not import it. Worker files contain hashed full case identities,
sanitized labels, measured durations and fixed outcomes; parameter values are
omitted. Each of at most twelve worker files is capped at 1 MiB per phase.

A partial summary can help investigate a terminated invocation. It is not JUnit,
coverage, a complete test inventory or acceptance evidence. Timeout and missing
fresh JUnit remain failures; no retry, test-selection or budget change is added.

::: fuzzy1337.test_progress
