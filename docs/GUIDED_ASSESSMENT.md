# Understand a finding, its source assertions and an offline report

This walkthrough connects the installed first-party Git HEAD check, verified
local intelligence and a readable HTML report. Use a reviewed development wheel
with **Python 3.13 or newer** and its pinned FuzzyRoutines runtime dependency.
The [installation guide](QUICKSTART.md#install-a-reviewed-wheel) explains source
identity and clean installation. This development walkthrough adds no PyPI
publication claim.

The detector and the training source deliberately say different things:

| Item                             | What it establishes                                                                                            |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Owned Git HEAD response          | One real LOW-severity metadata-exposure Finding, supported by the selected HTTP response                       |
| Fixed HTTP 404 control           | No new Finding for that different endpoint; it does not resolve the original Finding                           |
| Fictional `CVE-1900-9999`        | Synthetic source data for learning import, inspection and candidate association                                |
| Source CVSS 3.1 score `8.1 / 10` | The fictional source's own numeric assertion, separate from the detector's LOW severity                        |
| Five-level fuzzy scale           | A reproducible linguistic interpretation of that source score, not attack probability or a target risk verdict |

## 1. Produce the real Finding and stop the target

Complete the [owned Git HEAD recipe](OWNED_GIT_HEAD_RECIPE.md), including its
separately approved fixed control and **Reopen and export after the fixture
stops**. Use its exact two URLs, current consent, independent STANDARD policy and
separate actual confirmation digests. Each approved check makes one request to
the repository-defined loopback fixture. Planning and missing confirmation make
no request. No Internet service is scanned.

Keep its resulting `git-head-demo/workspace`, `git-head-demo/model.json` and
original reports. The fixture terminal must report two requests, `exposed` and
`fixed`, and `listener_closed: true`. The saved model contains one open LOW
Finding. Everything below runs after this owned target has stopped.

## 2. Save the explicitly synthetic source

Download [the complete UTF-8 training JSON](examples/guided-assessment.cve.json)
to `git-head-demo/training.cve.json`, or save the following exact JSON there in a
UTF-8 editor. It contains no real vulnerability identifier or affected product.
Do not substitute a real CVE and infer that it applies to the Git check.

```json
{
  "dataType": "CVE_RECORD",
  "dataVersion": "5.2",
  "cveMetadata": {
    "cveId": "CVE-1900-9999",
    "state": "PUBLISHED",
    "dateUpdated": "2026-01-01T00:00:00Z"
  },
  "containers": {
    "cna": {
      "providerMetadata": {
        "orgId": "1337-owned-training-fixture",
        "shortName": "Owned synthetic training data"
      },
      "descriptions": [{
        "lang": "en",
        "value": "Fictional training record. This is not a real CVE and does not describe the Git HEAD exposure check or its target. Its CVSS score demonstrates source interpretation only."
      }],
      "affected": [{
        "vendor": "Fictional training vendor",
        "product": "Fictional training product",
        "defaultStatus": "unknown"
      }],
      "metrics": [{
        "cvssV3_1": {
          "version": "3.1",
          "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "baseScore": 8.1
        }
      }]
    }
  }
}
```

## 3. Import, inspect and explicitly associate training data

Choose the commands for your shell. Both versions execute the same 1337 commands
and select identifiers from the actual earlier results. The source's URL and
license are declared synthetic metadata; importing this local file fetches no
URL. The 1 MiB bound and one-day acquisition-freshness budget are explicit. For this
CVE source, freshness measures acquisition age; it does not make the fictional
publisher date current or authenticate its content.

The final `apply` is an explicit **candidate association exercise**. It appends
source assertions to the selected existing Finding. It does not authenticate a
publisher, match a product version, change the Finding's LOW severity or confirm
target applicability. Skip `apply` if you only want read-only source inspection.

### Bash on Linux or macOS

```bash
FINDING=$(python -c 'import json; print(json.load(open("git-head-demo/model.json"))["findings"][0]["reference"])')
REVISION=$(python -c 'import json; print(json.load(open("git-head-demo/model.json"))["model_revision"])')
1337 intel import git-head-demo/workspace git-head-demo/training.cve.json --feed cve-record-5 --catalog-version training-1 --origin synthetic --publisher "Owned synthetic training data" --source-url https://example.invalid/training.cve.json --license-name "Apache-2.0 synthetic fixture" --license-url https://example.invalid/LICENSE --scope scope:local --max-bytes 1048576 --json > git-head-demo/intel-import.json
SNAPSHOT=$(python -c 'import json; print(json.load(open("git-head-demo/intel-import.json"))["snapshot_id"])')
RECEIPT=$(python -c 'import json; print(json.load(open("git-head-demo/intel-import.json"))["receipt_id"])')
AS_OF=$(python -c 'import json; from datetime import datetime,timedelta; print((datetime.fromisoformat(json.load(open("git-head-demo/intel-import.json"))["finished_at"])+timedelta(seconds=1)).isoformat())')
1337 intel inspect git-head-demo/workspace --snapshot "$SNAPSHOT" --receipt "$RECEIPT" --identifier CVE-1900-9999 --json > git-head-demo/intel-inspect.json
1337 intel apply git-head-demo/workspace --snapshot "$SNAPSHOT" --receipt "$RECEIPT" --finding "$FINDING" --identifier CVE-1900-9999 --expected-revision "$REVISION" --as-of "$AS_OF" --max-age-seconds 86400 --scope scope:local --run run:guided-training --json > git-head-demo/intel-apply.json
1337 workspace open git-head-demo/workspace --json
1337 report export git-head-demo/workspace --format json --output git-head-demo/assessment.json --json
1337 report export git-head-demo/workspace --format html --output git-head-demo/assessment.html --json
```

### PowerShell on Windows

```powershell
$Original = Get-Content -Raw git-head-demo/model.json | ConvertFrom-Json
$FINDING = $Original.findings[0].reference
$REVISION = $Original.model_revision
1337 intel import git-head-demo/workspace git-head-demo/training.cve.json --feed cve-record-5 --catalog-version training-1 --origin synthetic --publisher "Owned synthetic training data" --source-url https://example.invalid/training.cve.json --license-name "Apache-2.0 synthetic fixture" --license-url https://example.invalid/LICENSE --scope scope:local --max-bytes 1048576 --json > git-head-demo/intel-import.json
$Imported = Get-Content -Raw git-head-demo/intel-import.json | ConvertFrom-Json
$SNAPSHOT = $Imported.snapshot_id
$RECEIPT = $Imported.receipt_id
$AS_OF = ([DateTimeOffset]::Parse($Imported.finished_at)).AddSeconds(1).ToString("o")
1337 intel inspect git-head-demo/workspace --snapshot "$SNAPSHOT" --receipt "$RECEIPT" --identifier CVE-1900-9999 --json > git-head-demo/intel-inspect.json
1337 intel apply git-head-demo/workspace --snapshot "$SNAPSHOT" --receipt "$RECEIPT" --finding "$FINDING" --identifier CVE-1900-9999 --expected-revision "$REVISION" --as-of "$AS_OF" --max-age-seconds 86400 --scope scope:local --run run:guided-training --json > git-head-demo/intel-apply.json
1337 workspace open git-head-demo/workspace --json
1337 report export git-head-demo/workspace --format json --output git-head-demo/assessment.json --json
1337 report export git-head-demo/workspace --format html --output git-head-demo/assessment.html --json
```

Check each exit status before continuing (`echo $?` immediately after a command
in Bash, `$LASTEXITCODE` in PowerShell). All commands above should exit **0**.
If an earlier command fails, preserve its result and diagnose it before running
the dependent command. Terminal output redirected to `intel-*.json` is a command
receipt, not the imported source or the report.

Expected results:

- Import retains the exact source, snapshot and receipt with actual acquisition
  times. It leaves model revision and Finding unchanged.
- Selected inspection returns the one fictional record, its original score and
  source product's `unknown` status. `target_applicability: not-evaluated` and
  `publisher_authentication: not-assessed` remain explicit. Inspection writes no
  model state.
- Apply reports `model_commit: confirmed` and the saved new revision. The sole
  Finding remains open and LOW. Its source association is `candidate`; synthetic
  data and its numeric score do not replace the detector's interpretation.
- A stale `--expected-revision` is refused. Repeating the same interpretation
  with the current saved revision is a no-op, not another Finding or source.

## 4. Read the report offline

Open `git-head-demo/assessment.html` in a browser: double-click it in a file
manager, use `Start-Process git-head-demo/assessment.html` in PowerShell, or
`open git-head-demo/assessment.html` on macOS / `xdg-open git-head-demo/assessment.html`
on desktop Linux. The file is self-contained and requires no running target or
network connection.

Start with the summary of retained work, then the endpoint and Finding cards.
The Git metadata exposure explanation and available remediation belong to the
LOW detector Finding. The separate training source shows its own CVSS score and
five-level interpretation with library/profile versions. Expand evidence and
technical details only when you need the retained references and hashes.
Membership values are not probabilities. No combined business risk, exploit
applicability, scanner completeness or reviewed CVE match is established.

Open a saved model interactively with `1337 shell`, then enter:

```text
model git-head-demo/workspace
view model --json
lens pentest --json
context
quit
```

These foreground shell commands inspect the saved model. A later import or scan
requires reopening the model; lens selection grants no execution permission.
The concurrent split-pane terminal interface is separate roadmap work.

## 5. Preserve results and handle refusals

Keep the complete workspace and reports. Exported HTML remains tied to its
original saved revision after later changes. Existing report files are refused;
use a fresh filename for a new export. Nothing below silently overwrites evidence
or resolves the original Finding.

| Exit | Meaning in this walkthrough                                           |
| ---- | --------------------------------------------------------------------- |
| 0    | The selected operation completed; this is not a clean-target verdict  |
| 2    | Invalid configuration, path or existing export destination            |
| 3    | The scan lacked current authority or exact confirmation               |
| 4    | Acquisition, source integrity, revision, execution or storage failure |
| 130  | Interrupted; retain actual partial state and receipts                 |

A failed acknowledgement may leave committed model state or a complete report.
Read `model_commit` / `output_published`, reopen the workspace and preserve the
original files before retrying. Do not broaden scope, delete retained evidence,
reuse confirmation for a changed target or convert unknown values to zero.
See [Intel CLI](INTELLIGENCE_CLI.md), [offline reports](REPORT_EXPORT.md) and
[fuzzy assessments](FUZZY_ASSESSMENTS.md) for the exact contracts.
