# ADR 0039: Evidence-linked report projections

- Status: Accepted implementation decision under ADRs 0020, 0023, and 0027
- Date: 2026-10-13
- Related work: #44, #49, #50

## Decision

Reports are immutable projections of one canonical `ModelState` revision, not a
new security database, scan, authorization decision, or compliance assessment.
The Experimental `reporting` contract renders a bounded schema-v1 document with
the exact model content digest, canonical object/relation/observation references,
normalized findings, attributable executions, and explicit reference context.
No current clock, local installation path, raw artifact bytes, or inferred
reachability/attack edge enters an export.

Pure reports identify artifact integrity as unverified. An explicit verification
boundary checks workspace ownership and every linked artifact through the existing
`LocalEvidenceStore` before returning a checked projection. A missing, corrupt,
unsafe, or incorrectly sized artifact fails the whole verification; no partial
success is returned. Verification is byte integrity at projection creation, not
scanner completeness, authenticated provenance, exploitability, or authorization.

Reference links are display projections with fixed publisher HTTPS templates for
CVE, CWE, CAPEC, ATT&CK, ATLAS, and OWASP Top 10 2021. Caller-supplied catalog
versions remain visible; a link to a current publisher page does not pin that
page to a historical catalog. Explicit finding-reference bindings require a
rationale and attribution to evidence already linked to that canonical finding.
They are context, not a verified classifier match, observed behavior, or approved
standards mapping. Existing Intel/standards identities can supply these fields;
reports create no reference catalog and infer no mappings from finding text.

The `report_formats` surface produces escaped offline HTML, canonical JSON,
SARIF 2.1.0, and a documented JUnit XML adapter. HTML follows the existing Fuzzy
Technologies dark cyan/pink palette and uses native disclosure/navigation for
executive counts, technical finding details, evidence, provenance, and actual
model relations. It loads no scripts, remote assets, raw evidence, or arbitrary
URLs. Untrusted controls and bidirectional formatting characters are displayed
as visible escapes before HTML/XML encoding.

SARIF emits only open/confirmed findings as results and retains closed
dispositions in run properties. It invents no passed checks, scan invocation
success, source-code coordinates, fixed baseline, or attack paths. JUnit emits
one case per retained finding: active dispositions fail, dismissed/resolved
dispositions skip. Empty snapshots have zero cases, not evidence of a clean
scan. Both adapters retain snapshot/provenance/integrity metadata and explicitly
declare that scan completeness was not assessed.

## Validation

Deterministic unit/schema/golden tests cover all four formats, empty snapshots,
dispositions, failed execution attribution, canonical IDs, reference allowlists,
HTML/URL/XML injection, controls, Unicode, and output bounds. Integration tests
use real workspace/model/evidence stores, reject foreign/corrupt evidence, and
prove export leaves stored bytes unchanged. Exact HTML DOM assertions replace
browser execution for this work. CLI commands, shell integration, graph analysis,
catalog synchronization, and inferred compliance remain separate work.
