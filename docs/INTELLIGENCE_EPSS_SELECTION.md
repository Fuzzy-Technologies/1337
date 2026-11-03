# Local selected EPSS gzip imports

`intel epss import|inspect` is a separate Experimental local profile. It keeps
one original gzip corpus in the owning workspace, validates every CSV row and
retains assertions only for explicit selected CVEs. Missing IDs remain unmatched.
It does not change the legacy `intel import|inspect|apply` snapshot family.

Create an existing workspace first with `1337 workspace create`. The following
small example works from Python on Windows, Linux and macOS in an environment
with the installed package. It generates explicitly fictional training data;
the publisher and terms below are synthetic declarations, not real FIRST terms.
Save it as `epss_demo.py` and run `python epss_demo.py` beside that workspace.

```python
import gzip
import json
import subprocess
import sys
from pathlib import Path

source = Path("owned-scores.csv.gz")
source.write_bytes(gzip.compress(
    b"#model_version:synthetic-1,score_date:2026-10-12T00:00:00Z\n"
    b"cve,epss,percentile\nCVE-1900-9999,0.2,6e-05\n", mtime=0,
))
command = [sys.executable, "-m", "fuzzy1337", "intel", "epss"]
imported = subprocess.run([
    *command, "import", "./workspace", str(source),
    "--model-version", "synthetic-1", "--score-date", "2026-10-12",
    "--identifier", "CVE-1900-9999", "--identifier", "CVE-1900-8888",
    "--origin", "synthetic", "--publisher", "Owned training fixture",
    "--source-url", "https://example.invalid/scores.csv.gz",
    "--license-name", "Synthetic training terms",
    "--license-url", "https://example.invalid/LICENSE",
    "--terms-url", "https://example.invalid/terms", "--scope", "scope:owned",
    "--json",
], check=True, capture_output=True, text=True)
result = json.loads(imported.stdout)
print(result)
source.unlink()
subprocess.run([
    *command, "inspect", "./workspace", "--selection", result["selection_id"],
    "--receipt", result["receipt_id"], "--json",
], check=True)
```

Import should succeed with independent `raw_ack`, `selection_ack` and
`receipt_ack` values of `confirmed`. The selected CVE retains source `0.2` and
`6e-05`; the absent CVE remains in `unmatched_ids`. Inspection succeeds after
the original input is deleted, because it verifies the saved original bytes.
Move the entire owning workspace to relocate it; artifact copying does not
transfer ownership to another workspace. Neither command saves the model.

For real local data, use `--origin external` and declare the actual publisher,
source URL, model revision, archive day, license/attribution name and policy URLs.
The original header supplies the score clock; no midnight time or model version
is inferred. Source clocks after observed acquisition are refused. Relevant
publisher guidance includes [EPSS data](https://www.first.org/epss/data),
[attribution guidance](https://www.first.org/epss/faq) and
[FIRST public services terms](https://www.first.org/about/policies/terms).
Storing caller declarations does not verify their legal interpretation or
authenticate the publisher. Declared URLs are never fetched by this profile.

The fixed ceilings are 4 MiB compressed, 16 MiB decoded, 500,000 original rows
and 64 requested IDs. `--max-bytes` can lower the compressed ceiling; it cannot
raise it. `--expected-sha256` can pin the exact original gzip. One complete gzip
member is required, with EOF/CRC and no trailing or concatenated data. All rows,
including unselected ones, must have unique valid CVEs and finite bounded
numeric assertions. Original ordinary/scientific decimal spelling is retained.

Inspection selects both exact `selection_id` and `receipt_id`; these are manifest
identifiers, distinct from the `epss-acquired-selection:` content reference.
It validates role/type/bounds before content reads, original ownership, source
terms, requested scope, raw hashes and receipt facts, then reparses the complete
gzip. It cannot enlarge the saved selection. Unsupported `apply`, remote
collection, automatic matching and publisher authentication remain unavailable.

Failures return nonzero status with explicit acquisition state and independent
acknowledgements. Unknown acknowledgement means publication may have happened;
it does not prove rollback. A partial or failed import is not complete custody.
Only actual successful outcomes and exact original replay establish this profile.
