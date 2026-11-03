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
terminal controls are escaped. A small failed fallback preserves actual handles
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
