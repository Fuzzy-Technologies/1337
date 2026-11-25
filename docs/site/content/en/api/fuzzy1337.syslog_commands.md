# fuzzy1337.syslog_commands

This module is Internal CLI/shell transport. All classes, functions and helpers,
including `RunSyslogCommands`, are implementation details.
The installed development-wheel operation `trace syslog import|inspect` is
Experimental at contract version one. It delegates source bytes, parsing and
original ownership to the [SDK facade](fuzzy1337.syslog_artifacts.md); routing is
additive to the existing `trace ioc` family and does not change its TSV/receipt v1.

Import requires all original file/source/hash/framing/scope/read declarations.
Before reporting success the handler independently reopens and compares the
actual original receipt chain. Inspect requires the independently retained
original receipt ID and original raw checksum, verifies before presenting any
record and never saves model/workspace/evidence. Defaults expose original header
inventory, NIL/offset semantics, provenance, numeric codes and byte coordinates
without MSG content or SD values. `inspect --export-records --json` explicitly
includes ordered decoded SD values; it still excludes MSG body.

The finite schema-one `saved-syslog-cli-v1` terminal envelope reports separate
raw/receipt acknowledgements and their basis. All source strings are ASCII JSON
escaped, including human record lines; diagnostics contain fixed categories.
Invalid selections exit `2`, parse/storage/integrity/presentation refusal exits
`4`, interruption exits `130` and complete verified success exits `0`.
Presentation is staged before one checked write; an incomplete write is not
retried. Discovery/help grants no authority or inferred source selection.

See the
[operator guide](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/SYSLOG_SAVED_IMPORT.md)
for actual console syntax, file framing and independent saved-source replay.

::: fuzzy1337.syslog_commands
