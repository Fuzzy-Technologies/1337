# ADR 0142: Selected CWE HTTPS CLI

## Status

Proposed for #43 and #47. Integration requires the accepted SDK from #425.

## Decision

Add the experimental `intel cwe https fetch` and `intel cwe https inspect`
commands. Dispatch the exact `cwe https` prefix before the existing local CWE
route. Load the HTTPS SDK only after help and argument admission. Retain the
existing local commands and global flag normalization.

Fetch requires an existing workspace, an explicit supported catalog version,
a lowercase original SHA-256 pin, one to 64 selected CWE identifiers and an
explicit scope reference. The SDK owns the fixed source URLs, full captured
notice and finite byte/time budgets. Inspect requires the exact selection and
receipt manifest IDs. It performs read-only original-byte verification without
accepting source, selection or limit overrides.

The separate `cwe-https-selected-cli` version-one presentation binds command,
transport, source, custody, selected facts and observed failure state. Fetch
success requires complete SDK success and confirmed raw, selection and receipt
acknowledgements. Preserve returned partial evidence IDs and acknowledgement
states on failure. If acquisition does not return an outcome, preserve unknown
publication state. Inspect reports verified-present custody separately from
the original caller's publication acknowledgements. A failed outcome has no
usable selection payload.

Stage bounded terminal output before writing. JSON uses lossless ASCII escaping
and human output uses safe ASCII escapes for non-ASCII source text. Preserve
the complete notice and distinguish matched, unsupported and unmatched IDs.
Keep model commit, publisher authentication, legal rights, notice applicability
and target applicability explicit. A display failure cannot emit a partial
successful selection. The command exits 0 on success or exact help, 2 for
invalid configuration, 4 for acquisition, integrity or presentation failure,
and 130 on interruption.

## Verification

Exercise the actual command route and installed entry point with controlled
synthetic receiver inputs, real evidence stores and exact offline replay.
Cover bounded invalid input, partial and uncertain publication, corruption,
relocation and strict ASCII/CP1252 stdout. Genuine HTTPS acceptance is tracked
separately from retained-byte or synthetic verification.
