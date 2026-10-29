# Internal raw command boundary

`fuzzy1337.raw_commands` is Internal command parsing and presentation for the
Experimental `1337 raw plan|run|replay` interface. It supplies explicit workspace,
scope, actor, typed policy and trusted absolute executable inputs to the dedicated
SDK. It owns no separate authority, process, model or evidence implementation.

A literal `--` separates wrapper options from the exact native token tail. Native
tokens never become wrapper help, version or JSON flags. The initial supported
matrix is Nmap TCP connect and light service discovery; arbitrary native options
and additional tools remain unsupported.

Plan and replay return JSON. Run delivers bounded collected original stdout and
stderr separately without wrapper framing or lossy transcoding, unless the
operator explicitly selects `--json` before the separator. That mode emits one
structured outcome instead of native stream bytes. This is collected passthrough,
not an interactive or unlimited stream. Safe diagnostic messages do not echo
rejected arguments, policy documents or underlying exception details.

Native process status is preserved only after complete original custody and
required persistence acknowledgements. Usage, denial, wrapper failure and
cancellation return 2, 3, 4 and 130. The SDK owns cleanup, exact confirmation,
version metadata, original receipts, acknowledgement truth and historical replay.
Replay accepts only workspace and original receipt selection, without native
arguments, current policy or an executable.

See the [raw CLI guide](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/RAW_CLI.md)
and ADR 0111 for the full operator and custody contract.

::: fuzzy1337.raw_commands
