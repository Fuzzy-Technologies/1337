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
unchanged. There is no CLI, network receiver, model application or live feed in
this slice. See [ADR 0133](adr/0133-local-selected-cwe-custody.md).
