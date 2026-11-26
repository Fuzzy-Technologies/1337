# Review an offline MCP inventory

Use the installed wheel built from the same reviewed development checkout as
these fixtures. The Experimental `1337 bridge mcp` profile imports a selected,
caller-owned [version-one MCP inventory JSON file](MCP_INVENTORY.md), records an
explicit approval of an immutable baseline, and reviews another verified
snapshot from the same workspace and MCP server. File and workspace I/O are
local. Tool, resource, prompt, and server instruction declarations are inert
metadata.

The shared catalog example uses [the baseline](../tests/contract/fixtures/mcp.inventory.v1.json)
and [a change that adds one tool](../tests/contract/fixtures/mcp.inventory.changed.v1.json).
Run the commands in Bash from the reviewed checkout. The scope's documentation
address supplies the required scope rule. File-read attribution and baseline
approval are explicit, independent selections.

## Import and approve a baseline

Review the baseline JSON before issuing its approval. The timestamps below
are fixed for this reproducible example. For your own inventories, supply the
acquisition and decision times with UTC offsets and use attributable
non-secret owner, read-consent and decision references.

```bash
work=$(mktemp -d)
workspace="$work/catalog-workspace"
fixtures=tests/contract/fixtures

field() {
  python -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

1337 workspace create "$workspace" --id mcp-catalog --name "Offline MCP example"
1337 scope create "$workspace" --id catalog --allow-ip 192.0.2.1

baseline=$(1337 bridge mcp import "$workspace" "$fixtures/mcp.inventory.v1.json" \
  --server-key catalog --scope catalog --owner actor:collector \
  --read-consent-reference read:catalog-example --observed-at 2026-11-26T12:30:00+00:00 \
  --expected-model-revision 0 --json)
server=$(field server_reference <<< "$baseline")
snapshot=$(field snapshot_reference <<< "$baseline")
revision=$(field model_revision <<< "$baseline")

approved=$(1337 bridge mcp approve "$workspace" --server-reference "$server" \
  --snapshot-reference "$snapshot" --owner actor:operator \
  --approval-reference approval:baseline --approved-at 2026-11-26T12:45:00+00:00 \
  --expected-model-revision "$revision" --json)
revision=$(field model_revision <<< "$approved")

clean=$(1337 bridge mcp review "$workspace" --server-reference "$server" \
  --snapshot-reference "$snapshot" --expected-model-revision "$revision" --json)
test "$(field status <<< "$clean")" = unchanged
revision=$(field model_revision <<< "$clean")
```

## Review the change and save a report

```bash
candidate=$(1337 bridge mcp import "$workspace" "$fixtures/mcp.inventory.changed.v1.json" \
  --server-key catalog --scope catalog --owner actor:collector \
  --read-consent-reference read:catalog-example --observed-at 2026-11-26T12:30:00+00:00 \
  --expected-model-revision "$revision" --json)
snapshot=$(field snapshot_reference <<< "$candidate")
revision=$(field model_revision <<< "$candidate")

code=0
1337 bridge mcp review "$workspace" --server-reference "$server" \
  --snapshot-reference "$snapshot" --expected-model-revision "$revision" \
  --json > "$work/review.json" || code=$?
test "$code" -eq 1
test "$(field status < "$work/review.json")" = drift
revision=$(field model_revision < "$work/review.json")

human_code=0
1337 bridge mcp review "$workspace" --server-reference "$server" \
  --snapshot-reference "$snapshot" --expected-model-revision "$revision" || human_code=$?
test "$human_code" -eq 1

1337 report export "$workspace" --format json --output "$work/model.json"
1337 report export "$workspace" --format sarif --output "$work/model.sarif"
```

The review reports `mcp.tool-added` for `catalog_tags` and its canonical
`subject_reference`. The report JSON finding uses the same rule and subject.
The SARIF result uses the rule as `ruleId` and the subject as its logical
location's `fullyQualifiedName`. Both reports export the entire saved
workspace, including earlier findings. Use the command receipt for the
current comparison. Schema paths and acquisition provenance remain in
the redacted evidence referenced by `evidence_manifest`.

To make the candidate the next baseline after human review, call
`approve` with its server and snapshot references, the acknowledged
`model_revision`, a new decision reference, and the exact `review_reference`
from `review.json`. Repeating the same comparison retains its evidence and
finding references. Replaying approved history verifies the original
evidence and keeps the active baseline in place.

## CI outcomes

Run the same `review --json` command and retain its stdout and actual exit
code. The checked-in change is an expected exit 1 for the example. A CI
gate can preserve the same exit after saving artifacts so reviewed drift
fails the job. For machine decisions use the version-one receipt's
`status`, `changes`, `unknowns`, and `finding_references`.

| Exit  | Review status | Meaning                                                            |
| ----- | ------------- | ------------------------------------------------------------------ |
| `0`   | `unchanged`   | No proven change or incomplete comparison.                         |
| `1`   | `drift`       | A known declaration changed. Unknown fields may coexist.           |
| `2`   | `failed`      | Invalid arguments or selected path syntax.                         |
| `3`   | `no-baseline` | Verified snapshot has no approved baseline.                        |
| `4`   | `failed`      | Evidence, model revision, local input or storage operation failed. |
| `5`   | `incomplete`  | Comparison lacks coverage and has no proven change.                |
| `130` | `failed`      | Operation was interrupted.                                         |

A verified incomplete review retains a review reference and unknown fields,
with `failure: null`. An operational failure identifies a fixed failure
category. Refresh the acknowledged revision before retrying a model
conflict. The underlying [declaration review profile](MCP_DECLARATION_REVIEW.md)
defines section completeness, optional hints and opaque instruction
fingerprints. A partial inventory cannot establish that an unlisted
tool or locator was removed. Baseline approval applies to these
metadata comparisons.
