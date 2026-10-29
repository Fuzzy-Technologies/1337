# fuzzy1337.dev_commands

Developer gates use bounded registered steps, without arbitrary shell dispatch.
`1337-dev check` accepts `--suite-timeout` and `--fail-fast`. Fail-fast stops on
an actual failure; a successful run still executes the complete parallel/serial
test selection, unchanged coverage requirements and build. Defaults remain
unchanged, and nondefault worker counts, per-test deadlines or serial-only
selection remain rejected for `check`. Other non-test gates accept neither
test-execution option. No automatic retry is introduced.

::: fuzzy1337.dev_commands
