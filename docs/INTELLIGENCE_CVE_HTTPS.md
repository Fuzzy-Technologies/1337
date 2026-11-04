# Pinned selected CVE HTTPS acquisition

The Experimental `intel cve https fetch|inspect` profile acquires one explicitly
pinned CVE Record from the official `CVEProject/cvelistV5` repository. Version one
admits exactly wire `dataVersion="5.2"`, `dataType="CVE_RECORD"` and source state
`PUBLISHED`, with the requested canonical CVE ID. Other versions/states are
outside this finite profile. Existing local and legacy readers keep their own
contracts, including their treatment of rejected records.

## Explicit source selection

Create an existing workspace with `1337 workspace create`. Fetch requires an
exact lowercase 40-hex repository commit, one canonical CVE and the mandatory
lowercase SHA-256 of the original JSON. The source locator is derived only as
`https://raw.githubusercontent.com/CVEProject/cvelistV5/<commit>/cves/<year>/<range>/<identifier>.json`.
The range is the CVE serial prefix before its last three digits followed by
`xxx`. Arbitrary URLs, branches/tags, current discovery, credentials, query
strings, redirects and fallback requests are not admitted.

This Python example works with an installed package on Windows, Linux and macOS.
It selects fixed historical bytes; it does not claim current catalog coverage.
Run it beside an existing `workspace` directory:

```python
import json
import subprocess
import sys

command = [sys.executable, "-m", "fuzzy1337", "intel", "cve", "https"]
fetched = subprocess.run([
    *command, "fetch", "./workspace",
    "--commit", "124afead838875e8bf8f5f0bbaf929340216d81b",
    "--identifier", "CVE-2024-3094", "--expected-sha256",
    "f9f0858cc058006963ed8338b802cadaf559f4fa5c501c53752407dfaf3227f9",
    "--scope", "scope:pinned-official-data", "--max-bytes", "23216",
    "--timeout-seconds", "30", "--json",
], check=True, capture_output=True, text=True)
result = json.loads(fetched.stdout)
print(result)
subprocess.run([
    *command, "inspect", "./workspace", "--selection", result["selection_id"],
    "--receipt", result["receipt_id"], "--json",
], check=True)
```

Every scalar flag may appear only once, including `--identifier`. Source and
finite limits are validated before acquisition. Success requires actual complete
HTTP 200, matching raw SHA-256, admitted original source and three independently
confirmed publications. The default total receive budget is 15 seconds, with
0.05–60 seconds allowed. It includes child startup. The standard-library child
uses isolated Python, an empty environment, certificate verification and the
unchanged JSON/identity resource mode. It refuses redirects and unsupported
framing/HTTP content encoding. There is no retry.

## Bounded original custody

The profile permits at most one MiB of original JSON, two MiB of selected envelope
and 32 KiB of terminal receipt. A caller may lower the raw limit. Shared limits
and the existing CISA/EPSS source admission remain unchanged. The existing bounded
CVE parser retains supported source assertions and explicit unsupported metrics;
wire tags alone do not establish complete JSON-schema or universal corpus support.
The source update clock cannot follow observed receive completion.

The unchanged normalized `IntelligenceSnapshot` is nested inside a distinct
version-one HTTPS selection envelope. Source identity, original raw manifest,
snapshot and actual request byte/deadline limits bind into the
`cve-https-selection:` content reference. This is separate from the original
`selection_id` and `receipt_id` evidence manifest IDs and the nested legacy
snapshot content reference.

Inspect requires the exact original selection and receipt roots. Expected roles,
media and per-role budgets precede content allocation; source/acquisition/raw
provenance joins precede interpretation. The loader compares exact receipt facts
and reparses all original JSON. Another acquisition, workspace or source-family
root cannot replace the original. Inspection works after moving the whole owning
workspace, without a receive, model save or original external input file.

Raw, selection and receipt publication acknowledgements remain independent.
`unknown` means publication may have happened. Partial receives and failed
parsing/hash/storage retain honest terminal facts and bounded evidence where
possible. Later failure can leave earlier immutable records; an oversized
generated receipt is refused while preserving earlier acknowledgements. Failure
is not complete successful custody and never supplies zero risk.

## Explicit selected batch SDK

`fuzzy1337.intelligence_cve_batch.AcquireHttpsCveBatch` accepts a tuple of two
to four `CveHttpsRequest` selections. Use unique CVE IDs at one pinned commit,
with independent SHA-256 and receive limits. The SDK validates all requests
before collection, then processes them serially in the same owning workspace.
The sum of byte ceilings is at most 4 MiB and the sum of configured receive
timeouts is at most 60 seconds. Each member retains the single-record limits.

The result separates verified custody, attempted failure and not-attempted
members. A partial batch can retain successful selections and independent
acknowledgements. Reopen each successful selection with its own receipt through
`LoadHttpsCveSelection`. Batch output has no persistent aggregate receipt or
model write. The existing CLI continues to select one record at a time.

The [batch design](adr/0145-pinned-selected-cve-https-batch.md) records the
ownership and interruption boundaries. Genuine batch HTTPS acceptance remains
pending.

## Attribution and interpretation

The source identity retains [CVE Program Terms of Use](https://www.cve.org/Legal/TermsOfUse),
the required observed MITRE copyright designation and the complete relevant
LICENSE/DISCLAIMERS text from a pinned primary terms source. Notice provenance
and its observed date accompany that text. The schema repository's CC0 license
is not substituted for CVE data terms. `legal_rights` and
`publisher_authentication` remain `not-assessed`: preserving notices and matching
expected bytes do not establish downstream entitlement or a publisher signature.

CNA/ADP assessments, source CVSS values and unsupported information remain source
facts. This profile does not recompute CVSS, infer target applicability, associate
a Finding or save canonical model state. Source membership is not an exploitation
probability, and source severity is not M5 contextual risk.

See [ADR 0130](adr/0130-pinned-selected-cve-https-custody.md) and the
[source acceptance record](INTELLIGENCE_SOURCE_ACCEPTANCE.md). Owned fixtures,
retrieved research bytes, genuine isolated HTTPS and final integration CI remain
distinct evidence. The wider #43/#47 batch/delta, CWE/archive and assurance scope
stays open.
