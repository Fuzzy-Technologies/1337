# Evidence-linked reports

`fuzzy1337.reporting` and `fuzzy1337.report_formats` are Experimental library
contracts implementing [ADR 0039](adr/0039-evidence-linked-report-projections.md).
They render one canonical model revision as dark offline HTML, schema-v1 JSON,
SARIF 2.1.0, or JUnit XML. No exporter scans, authorizes execution, saves model
state, invents paths, or establishes compliance.
The three report/context dataclasses and their methods, `VerifyReportEvidence`,
and the four documented format exporters are Experimental. Validation, escaping,
fragment, and bound helpers remain Internal despite their house-style names.

## Source and integrity

`ReportSnapshot(state, reference_bindings=())` owns an immutable view of an existing
`ModelState`, bounded by the canonical snapshot byte limit. The exact model content
SHA-256, workspace ID, revision, normalized findings, actual stored relations,
observation history, and original execution outcomes remain attached to the view.
Counts describe retained interpretations, not scanner coverage or proved
vulnerabilities. `scan_completeness` is always `not-assessed`.

Pure reports retain all linked artifact references as unverified.
`VerifyReportEvidence(report, workspace_root)` checks actual workspace ownership
and each unique reference through `LocalEvidenceStore.Read`, then returns a new
checked projection. Missing, unsafe, corrupt, or incorrectly sized bytes fail the
whole verification. The original report and all stored files remain unchanged.
Verification describes exact byte integrity at projection creation. It does not
authenticate source claims or upgrade failed execution into a successful scan.
Re-verification is explicit; a previously checked projection is not a live health
monitor of files that might later disappear.

No acquired raw bytes, local workspace path, or wall-clock generation time is
embedded. Exported model/context metadata must already be authorized and non-secret
under the existing model contract; these APIs do not discover or redact secrets.
Every output is bounded to 32 MiB and oversized output fails before publication.

```python
from pathlib import Path

from fuzzy1337.model import LocalModelStore
from fuzzy1337.reporting import ReportSnapshot, VerifyReportEvidence
from fuzzy1337.report_formats import RenderHtml, SerializeJson, SerializeSarif, SerializeJunit

root = Path("owned-workspace")
report = ReportSnapshot(LocalModelStore(root).Open())
checked = VerifyReportEvidence(report, root)
html_bytes = RenderHtml(checked)
json_bytes = SerializeJson(checked)
sarif_bytes = SerializeSarif(checked)
junit_bytes = SerializeJunit(checked)
```

The caller owns file publication and downstream transport. A report JSON document
is a projection, not a second model snapshot format; only its embedded `model`
member can pass through the existing canonical model decoder.

## Reference context

`ReportReference(family, external_id, catalog_version)` produces fixed publisher
HTTPS links for `cve`, `cwe`, `capec`, `attack`, `atlas`, and `owasp-top10`.
Identifier/version fields may come from existing Intel or standards identities;
the report creates no reference catalog. ATT&CK sub-technique IDs receive canonical
path navigation. OWASP Top 10 currently supports the exact 2021 catalog; other
OWASP editions/frameworks need an explicit additional link contract.

Except for the versioned OWASP route, the link opens the publisher's current page;
the caller's historical catalog version remains visibly separate. Syntax acceptance
does not prove upstream membership, pin the remote content, or acquire that page.
Arbitrary source/remediation URLs remain inert text; credentials, query injection,
traversal, unsupported families, controls, and invalid UTF-8 cannot enter fixed
link identity fields.

`FindingReferences(finding_reference, references, rationale, provenance)` associates
explicit contextual links with a finding that exists in the same report snapshot.
Attribution must contain evidence already linked to that finding. A rationale is
required, no more than 32 unique references may be supplied per finding, and the
report permits at most 1024 unique finding bindings within a 1-MiB context bound.
Context is labelled `attributed-context`; it is not a verified classifier match,
approved mapping, observed technique, or fulfilled control. Reports never infer
relations by parsing finding summaries or traversing a mapping pack.

## Format semantics

| Output | Contract                                                                                                                                                                                                                                                                                         |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| HTML   | Self-contained dark Fuzzy Technologies palette; executive counts, technical details, native disclosure, canonical object/evidence fragments, stored relations, and escaped provenance/history. No scripts, remote assets, raw artifact links, or browser requirement.                            |
| JSON   | Exact schema-v1 projection at `contracts/report.schema.json`, including original model content and integrity/context metadata.                                                                                                                                                                   |
| SARIF  | Version `2.1.0`; only open/confirmed findings become results. Dismissed/resolved findings remain in run properties. Snapshot, context, outcomes, and byte-integrity metadata stay attached. No passed checks, physical source coordinates, successful invocation, or fixed baseline is inferred. |
| JUnit  | One case per retained finding; open/confirmed dispositions fail, dismissed/resolved dispositions skip. Zero findings mean zero cases, not a completed clean scan. Snapshot, context, outcomes, and integrity properties accompany the XML.                                                       |

SARIF severity adapts unknown/medium to `warning`, informational/low to `note`, and
high/critical to `error`; original normalized severity/confidence remains in result
properties. These are presentation levels, not recalculated risk. The adapter is
validated against the pinned official
[OASIS SARIF 2.1.0 schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json).
JUnit is a documented interoperability adapter rather than a claim of a universal
JUnit schema or actual test execution duration.

HTML/XML rendering displays controls and bidirectional formatting characters as
visible escapes before encoding. JSON preserves exact canonical normalized strings.
DOM tests verify tag/attribute safety, fixed hyperlink targets, unique/resolved
fragments, native interaction, and the dark default without executing a browser.

## Verification

```bash
uv run --locked --extra dev pytest -q -o addopts='' \
  tests/unit/test_reporting.py tests/contract/test_reporting_contract.py \
  tests/integration/test_reporting_integration.py
```

The tests include hostile serialization, dispositions, failure attribution, byte
bounds, strict schema checks, four golden artifacts, real artifact reads,
corruption/ownership failures, workspace relocation, and unchanged stored files.
CLI integration, live jobs, mature graph analysis, source catalog synchronization,
and automatic standards conclusions remain separate capabilities.
