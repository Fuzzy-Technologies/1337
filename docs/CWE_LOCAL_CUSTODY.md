# Local selected CWE custody

The Experimental SDK retains one explicitly supplied original CWE ZIP in an
existing workspace. It supports catalog 5.0/schema 8 and 4.21/schema 7 through the
unchanged pure selected decoder. Supply one to 64 already sorted unique CWE IDs,
an exact SHA-256 byte pin and the fixed complete notice profile.

```python
from hashlib import sha256
from fuzzy1337.intelligence_cwe_acquisition import (
    CweLocalSource, CweLocalRequest, AcquireLocalCweSelection, LoadAcquiredCweSelection,
)

source = CweLocalSource("5.0", sha256(original_zip).hexdigest())
request = CweLocalRequest(source, original_zip, ("CWE-79", "CWE-89"))
outcome = AcquireLocalCweSelection(workspace_root, request, scope_reference="scope:owned")
if outcome.state.value == "succeeded":
    selected = LoadAcquiredCweSelection(
        workspace_root, outcome.selection_record.evidence_id, outcome.receipt.evidence_id,
    )
```

This example assumes an existing workspace and explicitly supplied local bytes;
it does not fetch a catalog or authorize any security action. SDK success requires
confirmed raw, envelope and receipt publications. Failures preserve actual partial
or acknowledged artifacts and report uncertain acknowledgements independently.
A lost acknowledgement does not establish rollback.

Replay verifies exact source/notice content, effective byte limit, manifest owner,
acquisition provenance, receipt and complete original ZIP reparse. It writes no
model or evidence and works after workspace relocation without the caller file.
An unsupported Category/Grouping/View stays separate from an absent ID; neither
becomes a zero-risk Weakness. Catalog dates retain civil-day precision.

The fixed bundle includes the complete captured terms-page text, all disclaimers
and footer, raw HTML/text hashes and deterministic extraction provenance. This
preserves technical notice content; legal rights, historical notice applicability
and publisher authentication remain not assessed. Source URLs and publisher names
are declarations, and source hashes establish byte identity only.

Original bytes are bounded to at most 4 MiB, envelope to 2 MiB and receipt to
64 KiB. The caller can lower the original-byte ceiling; it participates in the
envelope and receipt identity. Existing decoder and generic source limits remain
unchanged. The SDK custody boundary adds no network receiver, model application
or live feed. See [ADR 0133](adr/0133-local-selected-cwe-custody.md); the additive
local CLI consumer is described below.

## Explicit local CLI consumer

The Experimental local command imports one supplied file into an existing
workspace. The example selects identifiers explicitly; input order is sorted
lexically and duplicates are rejected. Replace the digest placeholder with the
exact lowercase SHA-256 of the supplied original ZIP.

```bash
1337 intel cwe import ./workspace ./cwec_v5.0.xml.zip \
    --catalog-version 5.0 --expected-sha256 ORIGINAL_SHA256 \
    --identifier CWE-89 --identifier CWE-79 --identifier CWE-999999999 \
    --scope scope:owned --max-bytes 4194304 --json
1337 intel cwe inspect ./workspace --selection SELECTION_MANIFEST_ID \
    --receipt RECEIPT_MANIFEST_ID --json
```

Use the returned `selection_id` and `receipt_id`, each exactly `sha256:` plus
64 lowercase hexadecimal characters. Both are mandatory. Inspection verifies the
original stored ZIP and complete source/notice declaration, works after input
file deletion and workspace relocation, and changes no owning files or model.
It uses the retained selection; additional `--identifier` flags are rejected.

Only catalogs 5.0 and 4.21, one to 64 canonical unique CWE IDs, an exact mandatory
byte pin, and the fixed captured notice profile are admitted. Source, selection,
scope and budget are checked before file reads. The unchanged physical regular
singly-linked file reader reads at most `max+1` bytes: EOF at max is complete;
an extra byte proves overflow and only the first max bytes are retained as an
incomplete prefix. The caller can lower, never increase, the 4 MiB ceiling.

JSON uses the separate `cwe-local-selected-cli` schema-one/profile-one terminal
family. Fully successful import requires confirmed raw, selection and receipt
ACKs and all returned handles. Failure retains actual confirmed handles and
independent unknown ACKs; a lost return does not establish rollback. Import
`ack_basis=sdk-returned` describes returned SDK facts. Inspection uses
`ack_basis=verified-present` for exact artifacts verified now; this does not
rewrite the original publication acknowledgement. `source_sha256` is the actual
confirmed raw artifact digest, including a partial prefix on overflow. The
expected source pin remains a separate declaration.

Both JSON and human output are staged within independent 2 MiB UTF-8 ceilings,
including framing. Human output shows source fields, complete notice text and
provenance, Weakness records, known unsupported kinds and absent IDs separately;
terminal controls and non-ASCII characters are escaped. JSON uses lossless Unicode
escapes (including surrogate pairs); human lines use explicit backslash escapes.
The staged bytes are ASCII, a UTF-8 subset, so redirected strict CP1252/ASCII
streams preserve complete output without an environment encoding override. A small failed fallback preserves actual handles
and ACKs without usable selected content if presentation exceeds its budget or
is interrupted. Source declarations and notices establish no legal, authenticity,
applicability or risk assessment.

Exit zero means complete import, verified inspection or help; two means invalid
configuration/file preflight; four means integrity, acquisition or presentation
failure; 130 means interruption. Rejected values and exception diagnostics are
not echoed. `intel cwe --help`, `import --help` and `inspect --help` are accepted
at the adapter boundary. The existing top-level CLI consumes global help/JSON
flags before forwarding: original help order and repeated global flags can be
normalized before this consumer sees them. Other repeated scalar options,
abbreviations, unsupported actions and extra operands are rejected.

This consumer adds no source download, latest discovery, apply or model save.
See [ADR 0135](adr/0135-local-selected-cwe-cli.md). The broader #43/#47 source,
assurance and licensing work remains open.

## New IDs from the same retained original

When a saved catalog was originally selected for one set of IDs, an operator can
query a different explicit set without restoring the external ZIP or recording
another acquisition:

```bash
1337 intel cwe lookup ./workspace --selection ORIGINAL_SELECTION_MANIFEST_ID \
    --receipt ORIGINAL_RECEIPT_MANIFEST_ID \
    --identifier CWE-20 --identifier CWE-1000 --identifier CWE-9999999 --json
```

The complete owning workspace can first be copied or relocated and the caller's
original ZIP removed. Both exact original manifest roots remain mandatory.
The command validates one to 64 canonical unique IDs before storage access and
sorts them lexically like import. It accepts no replacement catalog, hash, scope,
notice, source path or acquisition metadata.

Lookup first performs the existing exact custody reopening, including complete
notice/source/receipt joins and reparse of the original saved selection. Only
then does the same bounded decoder reparse the verified retained full ZIP for
the newly requested IDs. Original ZIP/XML/selection ceilings are unchanged.
Corrupt, missing or mixed custody refuses before any on-demand result is emitted.
Weakness matches, known unsupported Category/Grouping/View entries and genuinely
absent IDs remain three separate source partitions.

The distinct Experimental terminal profile is
`cwe-local-original-lookup-cli`, schema one/profile one. Top-level `selection`,
`selection_reference`, `selection_id` and `receipt_id` still describe the
original verified saved selection and custody. The separate `lookup.selection`
contains the on-demand decoder result; `lookup.selection_reference` is only its
pure `cwe-selection:` content reference. It is not a stored acquisition,
receipt, normalized snapshot or model observation. `lookup.persistence` is
`not-attempted`. Original source version, original-byte hash, full notices,
acquisition times and `ack_basis=verified-present` retain their earlier meaning.
Human output explicitly labels both selections.

Default `import` and `inspect` output and accepted inspection grammar remain
unchanged. Lookup writes no workspace, evidence or model bytes and calls no
acquisition/provider or clock. It grants no legal rights, publisher authenticity,
target applicability or score. It does not turn unsupported or absent IDs into
Weaknesses or zero risk.

The existing finite terminal ceilings still apply. Configuration refusal is two,
custody/lookup/presentation refusal is four and interruption is 130. A failed
response contains no usable original or on-demand selection. A caller-stream
failure propagates after one write attempt rather than returning false success;
no output retry or implicit acquisition follows.
See [ADR 0155](adr/0155-read-only-retained-cwe-lookup.md).
