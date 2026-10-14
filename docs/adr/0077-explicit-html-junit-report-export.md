# ADR 0077: Explicit HTML and JUnit product report export

## Status

Accepted bounded consumer decision — 2026-10-14. Advances Task #40; the accepted
report SDK from ADR 0039 remains the sole renderer owner.

## Decision

Extend the existing Experimental `1337 report export <workspace> --format`
selection with `html` and `junit`, alongside unchanged `json` and `sarif`.
The product consumer calls the existing pure `RenderHtml` or `SerializeJunit`
over the same exact verified saved `ReportSnapshot`. No renderer, finding,
reference, risk, model, evidence or execution semantics change.

Preserve ADR 0049's selected input and publication boundary: reopen the owning
workspace/model/scopes, verify every retained acquisition and linked raw
reference within existing quotas, render completely, recheck the full original
snapshot and publish to a new explicit outside destination through the same
atomic no-clobber owner. Original failed executions and operator dispositions
remain report facts. Reading historical scope never supplies current authority.
Confirmed publication remains visible after interruption or lost acknowledgement.

Add only `html` and `junit` to both format enums in the Experimental schema-v1
report-export outcome. Existing fields, error categories, quotas, version and
exit values remain unchanged. `--json` still emits the command outcome rather
than report bytes. Existing CLI/shell routing requires no new namespace or
handler. Rendering/export success exits zero even when JUnit contains failure
cases; this command is not a finding-threshold or CI gate.

HTML retains the accepted self-contained, script-free dark report, inert native
disclosures, escaped hostile text and canonical evidence/object fragments.
JUnit retains one case per Finding: open/confirmed dispositions fail and
dismissed/resolved dispositions skip. Empty state contains zero cases rather
than passed security checks. All formats keep `scan_completeness: not-assessed`.
Source metadata must already satisfy the existing authorized non-secret model
contract; renderers neither acquire nor sanitize raw source data.

## Evidence and limits

Contract tests compare each actual command producer with the unchanged owning
SDK format and validate the additive outcome schema. Product subprocess tests
create/open real owning state, export all four formats and check independent
literal HTML escaping, fragments and JUnit disposition/property assertions.
Tests cover empty state, source mutation, relocation, invalid/foreign/missing
evidence, concurrent output, interrupted publication and lost acknowledgement.
Unit checks exercise new-format renderer failures, complete snapshot drift and
input/output quotas while preserving the existing no-process/network tripwires.
Existing no-process/no-network tripwires remain active on consumer paths.

This adds no browser, Web UI, remote assets, scripts, raw evidence bundle,
reference inference, authorization decision, scanner, schema trust contract,
package publication or release. It supersedes only ADR 0049's initial two-format
selection. Task #40 remains open for its other onboarding/release acceptance.
