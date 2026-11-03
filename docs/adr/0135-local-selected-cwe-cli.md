# ADR 0135: Bounded local selected CWE CLI consumer

Status: Accepted for this bounded implementation.

## Context

ADR 0133 establishes original local ZIP, selected envelope and receipt custody.
An SDK interface alone is not an assembled command workflow. The new consumer
must preserve its strict source, notice, selection and independent acknowledgement
contracts without changing the SDK or the legacy intelligence commands.

## Decision

Add only `intel cwe import WORKSPACE FILE` with exact `--catalog-version`, mandatory
`--expected-sha256`, repeated `--identifier`, `--scope`, and optional `--max-bytes`;
add `intel cwe inspect WORKSPACE --selection ID --receipt ID`. A minimal lazy
router enrollment delegates to a new internal `intelligence_cwe_commands` owner.
The existing top-level CLI consumes global help/JSON flags before dispatch; exact
help and duplicate scalar checks apply to the forwarded arguments that remain.
The consumer cannot reject original spellings erased by that normalization.

Validate one to 64 identifier occurrences, sort lexically without deduplicating,
and delegate immutable admission to the unchanged SDK validator. Validate source,
pin, scope and effective 1..4 MiB original-byte budget before any path/store read.
Validate both inspection roots as `sha256:` plus 64 lowercase hexadecimal digits
before workspace access. Valid absent or corrupt roots are integrity failures.
Only existing workspaces and the unchanged regular singly-linked file reader are
used. Its `read(max+1)` reaches EOF at or below max, while max+1 proves overflow;
the SDK retains only max bytes as incomplete raw prefix. Stat size is not proof.

Use separate schema-one/profile-one `cwe-local-selected-cli` terminal JSON. Usable
source/selection content requires actual SDK succeeded state, complete body,
three confirmed ACKs and all returned handles. Preserve actual returned failure
ACKs/handles. Unreturned SDK calls leave unknown ACKs and unavailable facts null.
`source_sha256` is the actual confirmed raw artifact digest, including partial
prefixes on overflow, never the requested expected pin. Import `ack_basis` is
`sdk-returned`; inspection is `verified-present`, which does not rewrite a lost
historical publication return. Inspection uses original acquisition times and
reparses exact roots through the unchanged strict loader; it writes nothing.

Stage complete canonical JSON or complete escaped human text before stdout.
Encode JSON with lossless ASCII Unicode escapes and human non-ASCII characters
with explicit backslash escapes before counting the expanded bytes. This UTF-8
subset supports redirected strict CP1252 and ASCII streams without changing
original source/notice bytes or requiring an environment encoding override.
Each has its own 2 MiB actual UTF-8 byte ceiling, including final framing newline.
Human output gives readable named source/provenance fields, complete captured
notice text line by line, Weakness records, known unsupported kinds and absent
IDs separately. No ZIP/XML source body is printed. A presentation refusal uses a
separate bounded 64 KiB failed fallback preserving actual ACKs/handles but removing
usable source/selection fields. Rendering interruption similarly returns 130.
Any nonzero status strips usable content before rendering, including interruption
between success-field assembly and the final successful process status.

Exit zero means exact forwarded help, complete acknowledged import or verified
inspection; two means invalid configuration/file preflight; four means workspace
integrity, acquisition, replay or presentation failure; 130 means interruption.
Diagnostics never echo rejected source values or exception text. A successful
source declaration does not establish legal rights, historical notice applicability,
publisher authentication, target applicability or risk probability.

## Consequences

This is a local consumer over the accepted custody family. It adds no network
receiver, latest/discovery, model apply/save, source override, full XSD validation
or compatibility change. Existing generic/EPSS/CVE commands and all SDK/notice/
decoder budgets and identities remain unchanged. The inert historical notice
fixture preserves exact original HTML and complete text with attribution; it
executes no HTML and requires no fetch. Focused owning-store and assembled CLI
checks establish this consumer's behavior; installed retained-catalog acceptance
and shared CI remain separate recorded evidence. #43/#47 remain open.
