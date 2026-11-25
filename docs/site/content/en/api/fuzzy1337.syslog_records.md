# fuzzy1337.syslog_records

Experimental SDK version one exposes only `ParseSavedSyslog(payload,
expectedSha256=..., framing=...)`. It accepts a complete bounded saved RFC 5424
version-one original and an independent lowercase SHA-256, without I/O or custody.
It returns immutable canonical UTF-8 JSON bytes containing source fields, exact
original byte coordinates, NIL/offset knowledge, ordered SD values and message
span/hash metadata. It never returns MSG body. Other symbols, including parser
helpers, limits and diagnostic implementation, are Internal.

The explicit `single` framing preserves the whole message, including binary
unmarked MSG and LF/control bytes. `lines` is a separate saved-export restriction:
only byte LF or CRLF delimiters separate messages; significant spaces and Unicode
line separators remain data. Duplicate SD IDs refuse, repeated parameter names
remain ordered, unknown escapes retain their backslash, and UTF-8 controls in
parameter values remain data. BOM-marked MSG requires valid UTF-8; unmarked MSG
is opaque octets. Timestamp/NIL and unknown `-00:00` offset remain source facts;
derived UTC is optional and separately labelled.

Profile bounds and complete grammar are documented in the
[operator guide](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/SYSLOG_SAVED_IMPORT.md)
and [ADR 0156](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/adr/0156-owned-saved-rfc5424.md).
Malformed or over-limit originals return no partial document. Parser output is
source-only, without entity, Core Event, incident, identity or risk semantics.
For genuine local acquisition and retained verification use the
[original owner facade](fuzzy1337.syslog_artifacts.md).

::: fuzzy1337.syslog_records
