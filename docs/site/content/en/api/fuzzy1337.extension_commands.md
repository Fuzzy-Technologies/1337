# Internal extension manifest CLI transport

`fuzzy1337.extension_commands` is Internal parsing, bounded local input admission
and presentation for the Experimental `1337 extension validate <manifest>`
command. Its Python functions and parser classes are not a Stable extension SDK.
The canonical packaged extension-manifest v1 JSON Schema remains the Stable
structural contract; this transport does not change its version acceptance.

The optional `1337[validate]` extra supplies the pinned Draft 2020-12 validator.
The base installation provides help and reports `validator-unavailable` on an
actual validation attempt without the extra. Validation always reads the
installed distribution's canonical schema, with no repository or network
fallback. The reference registry has no external retrieval callback.

One selected regular UTF-8 JSON file is admitted within 64 KiB, 4,096 value nodes
and depth 32. Ambiguous duplicate members, invalid JSON and numeric/parser limits
are operational refusals, distinct from schema-invalid metadata. Results include
the complete admitted input and installed schema digests and at most 64 safe
keyword/JSON-pointer diagnostics with explicit truncation. Rejected source values,
filenames and exception messages are omitted.

Source schema locators remain instance data. Entry points are not resolved,
extension modules are not imported or activated, and Core release ranges are not
evaluated. A structurally valid manifest does not establish full SemVer
conformance, compatibility, registration or execution approval. The command
does not write input files or open a workspace. The shell uses the same handler
and excludes manifest arguments from its command history.

Exit codes are 0 for accepted metadata, 1 for invalid metadata, 2 for input/setup refusal,
4 for unusable installed schema and 130 for interruption. The JSON output is
Experimental profile one. See the
[Compatibility Contract](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/COMPATIBILITY.md#extension-manifest)
and [ADR 0153](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/adr/0153-offline-extension-validation.md)
for the consumer boundary and optional wheel installation.

An explicit `--version-profile semver-2.0.0` additionally checks the extension's
own version-string grammar after canonical structural acceptance. Numeric
prerelease identifiers forbid leading zeros; build metadata permits them.
The Internal `IsSemVer200` helper uses ASCII string checks without integer
conversion, precedence/range evaluation or an additional digit limit.
The existing manifest bounds still apply. It does not trim whitespace.

Only opt-in outcomes add `version_profile: "semver-2.0.0"`. A supplemental
invalidity uses exit 1 and a fixed `semver-2.0.0` diagnostic at
`/extension/version`, without rejected values. Unknown profiles fail
configuration admission before input reads. Canonical errors, installed schema
bytes, default command results and the optional validator requirement remain
unchanged. This is an Experimental CLI policy, not a Stable Python SDK.

::: fuzzy1337.extension_commands
