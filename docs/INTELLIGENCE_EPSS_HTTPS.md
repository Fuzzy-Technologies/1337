# Pinned selected EPSS HTTPS acquisition

The Experimental `intel epss https fetch|inspect` profile acquires one explicitly
pinned historical EPSS gzip and retains only requested CVE assertions. It uses
the actual isolated SDK receiver and its own remote custody family. The
[local selected profile](INTELLIGENCE_EPSS_SELECTION.md) remains separately
available; importing a downloaded file through it does not establish HTTPS
custody.

## Explicit acquisition

Create an existing workspace with `1337 workspace create`. Fetch requires four
source pins: lowercase 40-hex archive commit, calendar day, expected model
revision and lowercase raw SHA-256. The locator is derived exclusively beneath
`raw.githubusercontent.com/empiricalsec/epss_scores/<commit>/<year>/` with the
filename `epss_scores-<day>.csv.gz`. No arbitrary URL, moving alias, query,
credential, alternate port, discovery or fallback download is accepted.

For the fixed historical source selected for acceptance, this Python invocation
works with an installed package on Windows, Linux and macOS. It performs one
public-data fetch; it is not a security scan. Save and execute it beside an
existing `workspace` directory:

```python
import json
import subprocess
import sys

command = [sys.executable, "-m", "fuzzy1337", "intel", "epss", "https"]
fetched = subprocess.run([
    *command, "fetch", "./workspace",
    "--commit", "489cd9fcf989cdc3ec87168b873c858938a53517",
    "--score-date", "2026-11-02", "--model-version", "v2026.06.15",
    "--expected-sha256",
    "86885067d459c6f3ca888bfeb6219d536b428afda9a776c14b48c82bb6a85635",
    "--identifier", "CVE-1999-0001", "--identifier", "CVE-2023-20914",
    "--identifier", "CVE-9999-9999", "--scope", "scope:pinned-official-data",
    "--max-bytes", "2796673", "--timeout-seconds", "30", "--json",
], check=True, capture_output=True, text=True)
result = json.loads(fetched.stdout)
print(result)
subprocess.run([
    *command, "inspect", "./workspace", "--selection", result["selection_id"],
    "--receipt", result["receipt_id"], "--json",
], check=True)
```

Success requires an observed complete HTTP 200 body, matching mandatory hash,
successful full gzip validation and three independently confirmed publications.
The total receive deadline includes child startup; its allowed range is
0.05–60 seconds. The default is 15 seconds. The child has an empty environment,
certificate verification and bounded framing, and refuses redirects and HTTP
content encoding. Gzip is the resource format; `Accept-Encoding` stays `identity`.
There are no retries. Model state and Findings are never saved by either command.

## Finite selection and original custody

The existing profile ceilings remain 4 MiB compressed, 16 MiB decoded, 500,000
original rows and 1–64 unique requested CVEs. A caller may lower the compressed
ceiling but cannot raise it. Complete single-member EOF/CRC, no trailing content,
unique valid IDs and bounded numeric assertions are checked across every original
row. Normalized records are retained only for the requested IDs. An absent ID
stays unmatched; it never becomes a zero-score assertion.

The actual original header supplies the model and full score clock. It must
agree with the explicit pins and cannot postdate receive completion. Decimal
spelling, including `6e-05`, is retained. EPSS source probabilities and percentiles
are separate assertions; neither linguistic membership nor contextual risk is
calculated by acquisition.

Raw gzip, selected envelope and terminal receipt have distinct manifest IDs.
The `epss-https-selection:` content reference is a separate identity. Inspect
requires the exact original selection and receipt IDs, verifies roles/media and
allocation bounds before content reads, joins owning workspace/acquisition/raw
provenance, and reparses the complete original gzip. It can run after moving the
whole workspace with no network request. Copying artifacts to another workspace,
mixing acquisitions or supplying local-profile roots does not transfer custody.

Failures return nonzero status with observed transport facts and independent
`raw_ack`, `selection_ack` and `receipt_ack`. `unknown` means publication may have
happened. A later storage failure can leave earlier confirmed immutable records;
it does not imply rollback or complete successful custody. Oversized terminal
receipts are refused with these earlier acknowledgements preserved.

## Source terms and assurance

The profile retains fixed [FIRST data guidance](https://www.first.org/epss/data),
[attribution guidance](https://www.first.org/epss/faq) and
[public-service terms](https://www.first.org/about/policies/terms). Attribution
identifies FIRST EPSS and Empirical Security. `data_license` is
`not-established`; the code does not invent an SPDX data license or interpret
legal rights. `publisher_authentication` stays `not-assessed`. A caller-supplied
byte pin establishes expected content identity, not a publisher signature.

The [source acceptance record](INTELLIGENCE_SOURCE_ACCEPTANCE.md) distinguishes
actual local transport failures, deterministic owned tests and hosted original
source acceptance. `tools/epss_https_acceptance.py` verifies the installed CLI,
the exact body and decode facts, original manifests, offline relocation and
unchanged model state. A failed or unexecuted acceptance is not a success.
This profile does not establish latest-feed coverage, universal CVE acquisition,
CWE schema support, target applicability or M5 contextual risk.
