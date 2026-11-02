# ADR 0121: Readable offline assessment reports

## Status

Accepted implementation decision — 2026-11-02. Implements Task #394 as an HTML
presentation continuation of ADRs 0039 and 0077.

## Decision

Preserve the canonical model, `ReportSnapshot`, report schema version one,
command outcomes, and JSON/SARIF/JUnit serialization. Improve only the HTML
presentation over explicitly retained facts. The HTML golden fixture changes
intentionally; the other three format fixtures remain byte-identical.

The default reading order explains the retained result, recorded execution
outcomes, hosts/ports/services/addresses, finding dispositions and remediation,
source intelligence, evidence integrity, and stored relationships. Findings and
advisory steps remain visible without opening JSON. Digests, canonical identifiers,
complete provenance and observations remain available through native disclosure.
Missing inventory fields and execution outcomes remain unknown. Failed execution
records stay failed; their count does not become a count of distinct jobs.

A discovery source records responses and model objects; its profile does not
become a vulnerability detector. Zero findings cannot establish a secure target.
Scan completeness remains unassessed. A resolved disposition alone does not prove
that a repeated check succeeded. Recommendations come from retained remediation
or a clearly generic request to inspect evidence and select a correction.

Readable `finding-intelligence` observations preserve explicit candidate
association, source origin/publisher/version/time, freshness and unmatched
identifiers. CVSS technical severity, KEV known-exploitation assertions and EPSS
forecasts retain separate meanings. Source presence never proves target
applicability. Independent CVSS2/applicability source inspections are not inferred
from records that do not contain them.

For an actual retained numeric CVSS base score, the renderer consumes the pinned
FuzzyRoutines-backed `InterpretSeverity` profile from ADR 0122. Five labeled
membership meters and the source score are shown separately from normalized
Finding severity and conventional CVSS labels. Absent or malformed scores receive
unknown interpretation and no numeric meters. Full input, grades, library version,
scale profile and selection rule are retained in a disclosure. This is linguistic
severity presentation, not probability of compromise or action prioritization.

## Safety and verification

The output remains self-contained, script-free and offline, with its existing
content security policy, strict finite output bound and escaped text/control
handling. Endpoint and advisory URLs remain inert text; only the existing fixed
publisher reference URLs are clickable. Relationship links use saved natural
labels and canonical anchors, without inferring paths or new relations.

DOM tests check plain-view explanations independently of the generated golden,
unknown/empty state, retained failures, inventory, source meanings, malformed
assertions, UFS input semantics, hostile strings, native disclosure, fragment
resolution and safe external links. Existing product export, relocation and
byte-integrity tests consume the same renderer. Installed-package walkthrough
acceptance is verified separately with the assembled dependency/platform changes.
