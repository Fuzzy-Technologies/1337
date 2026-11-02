# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic offline HTML, JSON, SARIF, and JUnit adapters for report snapshots."""

from __future__ import annotations

import hashlib
import html
from http import HTTPStatus
from typing import cast
from xml.etree import ElementTree

from fuzzy1337.adapters.contracts import EvidenceReference, JsonValue
from fuzzy1337.assessments import InterpretSeverity
from fuzzy1337.findings import Finding, FindingSeverity, FindingStatus
from fuzzy1337.intelligence import IntelligenceFeed
from fuzzy1337.model import CanonicalModelJson, ObjectKind, SecurityObject
from fuzzy1337.reporting import MAX_REPORT_BYTES, REPORT_SCHEMA_VERSION, ReportSnapshot

__all__ = ["RenderHtml", "SerializeJson", "SerializeSarif", "SerializeJunit"]
_CSS = """
:root {color-scheme:dark;--bg:#07090d;--panel:#0b1117;--text:#b9dce8;
--muted:#7f9da8;--cyan:#55e7ff;--pink:#ff5bd8;--green:#5dff8d;--border:#00eaff4d}
* {box-sizing:border-box} body {margin:0;background:var(--bg);color:var(--text);
font:16px/1.65 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main {max-width:1180px;margin:auto;padding:2rem 1rem} h1,h2,h3 {color:var(--cyan)}
a {color:var(--pink);overflow-wrap:anywhere} .brand {color:var(--green)}
.muted {color:var(--muted)} nav {display:flex;gap:1rem;flex-wrap:wrap}
.cards {display:flex;flex-wrap:wrap;gap:1rem}.card,details {background:var(--panel);
border:1px solid var(--border);border-radius:8px;padding:1rem;margin:1rem 0}
.card {flex:1;min-width:160px} .count {font-size:2rem;color:var(--green)}
.finding {background:var(--panel);border:1px solid var(--border);border-left:4px solid
var(--pink);border-radius:8px;padding:1.2rem;margin:1rem 0}.finding h3 {margin-top:0}
.badge {display:inline-block;padding:.1rem .5rem;border:1px solid var(--border);
border-radius:4px;font-size:.85rem}.notice {border-left:3px solid var(--cyan);padding-left:1rem}
.meter {display:flex;gap:.25rem;align-items:end;min-height:3rem;margin:1rem 0}
.meter div {flex:1;text-align:center;background:#15212b;padding:.4rem;font-size:.85rem}
.meter strong {display:block;font-size:1.3rem;color:var(--green)}
.meter meter {display:block;width:100%;accent-color:var(--green)}
code,pre {font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
caption {text-align:left;color:var(--muted);margin:.5rem 0}
@media(max-width:600px) {main {padding:1rem .7rem}th,td {padding:.4rem}
.cards {gap:.4rem}.card {padding:.7rem}.meter {flex-wrap:wrap}.meter div {min-width:70px}}
summary {cursor:pointer;color:var(--green)} code,pre {overflow-wrap:anywhere}
pre {white-space:pre-wrap;background:#101820;padding:1rem;border-radius:6px}
.table {overflow:auto} table {border-collapse:collapse;width:100%}
th,td {text-align:left;vertical-align:top;padding:.65rem;border-bottom:1px solid var(--border)}
th {color:var(--cyan)} a:focus-visible,summary:focus-visible {outline:2px solid var(--cyan)}
@media print {body {background:white;color:black} a,h1,h2,h3,summary {color:black}}
"""


def ReportBytes(payload: bytes) -> bytes:
    """Enforce a shared finite artifact bound before handing bytes to a caller.

    Args:
        payload: Complete serialized artifact; no partial output is published.

    Returns:
        The same bytes when within the configured report bound.

    Raises:
        ValueError: Serialized bytes exceed the output limit.
    """

    if len(payload) > MAX_REPORT_BYTES:
        raise ValueError("report output exceeds the byte limit")

    return payload


def RequireReport(report: ReportSnapshot) -> None:
    """Reject arbitrary dictionaries or writable persona state at export boundaries.

    Args:
        report: Candidate immutable report projection.

    Raises:
        ValueError: The value does not use the typed report contract.
    """

    if not isinstance(report, ReportSnapshot):
        raise ValueError("report must be a ReportSnapshot")


def Text(value: object) -> str:
    """Display controls and bidirectional formatting as visible escapes before markup encoding.

    Args:
        value: Already validated report scalar or an explicitly formatted count.

    Returns:
        Valid UTF-8 display text with nonprintable characters shown as literal escapes.

    Raises:
        ValueError: Scalar text cannot encode as valid UTF-8.
    """

    text = str(value)
    CanonicalModelJson(text)

    return "".join(
        character if character.isprintable() else (
            f"\\u{ord(character):04x}" if ord(character) <= 0xFFFF else f"\\U{ord(character):08x}"
        ) for character in text
    )


def Html(value: object) -> str:
    """Escape display text in HTML text or quoted attribute positions.

    Args:
        value: Validated report scalar whose controls must remain visible.

    Returns:
        Quote-aware HTML-escaped text, without executable markup.

    Raises:
        ValueError: Scalar text cannot encode as valid UTF-8.
    """

    return html.escape(Text(value), quote=True)


def EvidenceId(reference: EvidenceReference) -> str:
    """Address one displayed artifact-reference record including role, media type, and size.

    Args:
        reference: Typed canonical artifact metadata already collected from the model.

    Returns:
        Stable ASCII fragment identity for the complete artifact reference.
    """

    return "evidence-" + hashlib.sha256(CanonicalModelJson(reference)).hexdigest()


def ObjectLink(reference: str, label: str | None = None) -> str:
    """Render a fragment link using a previously validated canonical object reference.

    Args:
        reference: Canonical object reference resolved by the enclosing model snapshot.
        label: Optional natural object label instead of a technical identifier.

    Returns:
        In-document anchor with escaped display text and an existing object fragment.
    """

    return f'<a href="#object-{reference[7:]}">{Html(reference if label is None else label)}</a>'


def JsonBlock(value: object) -> str:
    """Display detached strict JSON as inert escaped HTML text.

    Args:
        value: Validated first-party JSON metadata, never acquired artifact bytes.

    Returns:
        Escaped preformatted metadata block with no active elements.

    Raises:
        ValueError: Metadata is not bounded valid UTF-8 JSON.
    """

    return "<pre>" + Html(CanonicalModelJson(value).decode("utf-8")) + "</pre>"


def SerializeJson(report: ReportSnapshot) -> bytes:
    """Export the bounded schema-v1 projection, preserving canonical state and exact metadata.

    Args:
        report: Typed immutable report projection; pure snapshots retain unverified byte state.

    Returns:
        Deterministic UTF-8 JSON with a trailing newline; no raw evidence bytes are included.

    Raises:
        ValueError: The input contract or serialized output bound is invalid.
    """

    RequireReport(report)

    return ReportBytes(CanonicalModelJson(report.ToDict()) + b"\n")


def ObjectLabel(entity: SecurityObject) -> str:
    """Use a retained natural key or finding summary without inventing a display identity.

    Args:
        entity: Validated saved object from the enclosing immutable report snapshot.

    Returns:
        Unescaped natural identity text, or the normalized summary of a finding.

    Raises:
        ValueError: A finding object cannot decode through its owning finding contract.
    """

    if entity.identity.kind is ObjectKind.FINDING:
        return Finding.FromObject(entity).summary

    return entity.identity.kind.value.title() + ": " + entity.identity.key


def AttributeText(entity: SecurityObject, *names: str) -> str:
    """Show the first explicitly retained scalar field, leaving missing structured data unknown.

    Args:
        entity: Saved object whose retained attributes supply the display value.
        names: Attribute names in display preference order; structured values are skipped.

    Returns:
        HTML-escaped scalar text or an explicit missing-value label. Known HTTP response
        codes retain their numeric value and standard phrase; unknown codes stay numeric.
    """

    for name in names:
        value = entity.attributes.get(name)

        if entity.identity.kind is ObjectKind.ENDPOINT and name == "status" and type(value) is int:
            try:
                return Html(f"{value} {HTTPStatus(value).phrase}")

            except ValueError:
                return Html(value)

        if isinstance(value, (str, int, float, bool)):
            return Html(value)

    return "Not recorded"


def ObjectTables(report: ReportSnapshot) -> str:
    """Present retained objects as readable inventory without claiming discovery or reachability.

    Args:
        report: Immutable canonical projection supplying objects and their saved attributes.

    Returns:
        An offline HTML inventory section with readable tables, canonical anchors and
        disclosed object metadata; no objects, relationships or reachability are inferred.
    """

    lines = [
        '<section id="model"><h2>Retained assets and addresses</h2>',
        '<p>These are saved model objects. A listed address or service is not itself a '
        'vulnerability, and its presence does not establish current reachability.</p>',
    ]
    groups = (
        (ObjectKind.HOST, "Hosts", (("Address", ("address",)), ("Reported state", ("state",)))),
        (ObjectKind.PORT, "Ports", (("Protocol", ("protocol",)), ("Number", ("number",)),
                                   ("Reported state", ("state",)))),
        (ObjectKind.SERVICE, "Services", (("Name", ("name",)), ("Version", ("version",)))),
        (ObjectKind.ENDPOINT, "Web addresses", (("Method", ("method",)),
                                               ("HTTP status", ("status",)))),
    )

    for kind, heading, fields in groups:
        entities = report.state.Objects(kind)
        lines.append(f"<h3>{heading} ({len(entities)})</h3>")

        if not entities:
            lines.append("<p>No objects of this kind were retained.</p>")

            continue

        lines.append('<div class="table"><table><thead><tr><th>Saved identity</th>')
        lines.extend(f"<th>{Html(label)}</th>" for label, _ in fields)
        lines.append("<th>Details</th></tr></thead><tbody>")

        for entity in entities:
            lines.append(f'<tr id="object-{entity.Reference()[7:]}">'
                         f"<td>{Html(entity.identity.key)}</td>")
            lines.extend(f"<td>{AttributeText(entity, *names)}</td>" for _, names in fields)
            lines.append("<td><details><summary>Technical object</summary>"
                         + JsonBlock(JsonValue(entity)) + "</details></td></tr>")

        lines.append("</tbody></table></div>")

    primary = {kind for kind, _, _ in groups} | {ObjectKind.FINDING}
    others = [entity for entity in report.state.objects if entity.identity.kind not in primary]

    if others:
        lines.append("<h3>Other retained objects</h3>")

        for entity in others:
            lines.append(f'<details id="object-{entity.Reference()[7:]}"><summary>'
                         + Html(ObjectLabel(entity)) + "</summary>"
                         + JsonBlock(JsonValue(entity)) + "</details>")

    lines.append("</section>")

    return "\n".join(lines)


def RetainedOperations(report: ReportSnapshot, document: dict[str, object]) -> str:
    """Explain exact execution provenance without guessing jobs, checks, scope, or completeness.

    Args:
        report: Owning immutable snapshot accompanying the detached report document.
        document: Validated result of that snapshot's ToDict method, including original
            execution outcomes rather than inferred jobs or successful checks.

    Returns:
        An HTML section explaining retained outcomes and unknown coverage, with complete
        execution attribution confined to technical disclosures. No execution is started.
    """

    outcomes = cast(list[dict[str, object]], document["execution_outcomes"])
    lines = ['<section id="operations"><h2>What is recorded</h2>']

    if not outcomes:
        lines.append("<p>No execution outcomes were retained. This snapshot cannot establish "
                     "which checks ran or whether any operation completed.</p>")

    else:
        lines.extend([
            "<p>The table shows retained execution records, which can repeat one run for "
            "different targets. A successful tool exit does not establish that a target is "
            "safe.</p>",
            '<div class="table"><table><thead><tr><th>Recorded source</th>'
            '<th>Operation profile</th><th>Outcome</th><th>Observed at (UTC)</th>'
            '<th>Details</th></tr></thead><tbody>',
        ])

        for outcome in outcomes:
            execution = cast(dict[str, object], outcome["execution"])
            profile = {
                "native.http": "HTTP response discovery; no vulnerability check",
                "native.web-check": "Bounded response check; consult the retained finding/check",
            }.get(str(outcome["source_id"]), "Source-specific operation; consult retained details")
            lines.append(f"<tr><td>{Html(outcome['source_id'])}</td><td>{Html(profile)}</td>"
                         f"<td>{Html(execution['state'])}; exit {Html(execution['exit_code'])}</td>"
                         f"<td>{Html(outcome['observed_at'])}</td>"
                         "<td><details><summary>Execution attribution</summary>"
                         + JsonBlock(outcome) + "</details></td></tr>")

        lines.append("</tbody></table></div>")

    lines.append("<p>What was not checked: this report has no complete inventory of attempted "
                 "or omitted checks. Scan completeness was not assessed. Historical results "
                 "do not establish the present state of a target.</p></section>")

    return "\n".join(lines)


def SeverityScale(value: object) -> str:
    """Render actual CVSS membership grades, retaining malformed or absent scores as unknown.

    Args:
        value: Explicit source CVSS base score in 0..10. Missing, nonnumeric, boolean,
            nonfinite or out-of-range values receive the unknown interpretation.

    Returns:
        Five labeled library membership grades and meters for a valid score, or unknown
        labels without numeric meters. A disclosure retains exact input, grades and
        versioned scale policy; no probability or action priority is calculated.
    """

    score = float(value) if (
        isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 10
    ) else None
    assessment = InterpretSeverity(score)
    lines = [
        "<p>Five-level UFS interpretation of this source score: <strong>"
        + Html(assessment.label) + "</strong>.</p>",
        "<p>Interpreted by FuzzyRoutines " + Html(assessment.library_version) + ".</p>",
        "<p>The numeric input is the CVSS base score divided by ten. These linguistic levels "
        "use the Universal Fuzzy Scale profile; conventional CVSS severity labels have a "
        "separate definition. Membership grades are not probabilities of exploitation "
        "or action priorities.</p>",
        '<div class="meter" role="group" aria-label="Five membership grades from zero to one">',
    ]

    for membership in assessment.memberships:
        grade = "Unknown" if membership.grade is None else f"{membership.grade:.3f}"
        lines.append("<div>" + Html(membership.label) + "<strong>" + grade + "</strong>")

        if membership.grade is not None:
            lines.append(f'<meter min="0" max="1" value="{membership.grade}" '
                         f'aria-label="{Html(membership.label)} membership">{grade}</meter>')

        lines.append("</div>")

    lines.append("</div><details><summary>Scale input, full membership trace and versions</summary>"
                 + JsonBlock(assessment.ToDict()) + "</details>")

    return "\n".join(lines)


def IntelligenceDetails(report: ReportSnapshot, finding_reference: str) -> str:
    """Explain retained source assertions without assigning target applicability or risk.

    Args:
        report: Immutable saved projection containing source-attributed observations.
        finding_reference: Canonical finding reference whose retained intelligence is selected.

    Returns:
        Readable HTML for selected CVE/CWE/KEV/EPSS assertions with separate source meanings,
        freshness and candidate association. Missing or unsupported details remain explicit;
        complete original assertions stay disclosed and no target verdict is inferred.
    """

    observations = [item for item in report.state.observations
                    if item.subject_reference == finding_reference
                    and item.kind == "finding-intelligence"]

    if not observations:
        return "<p>No vulnerability-intelligence assertions were retained for this finding.</p>"

    lines = ["<h4>Vulnerability intelligence</h4>",
             "<p>These are source assertions associated by an explicit identifier. A candidate "
             "association does not prove that this target is affected. CVSS describes technical "
             "severity, KEV records known exploitation, and EPSS is a source forecast.</p>"]

    for observation in observations:
        attributes = cast(dict[str, object], JsonValue(observation.attributes))
        unmatched = attributes.get("unmatched_identifiers")

        if isinstance(unmatched, list) and unmatched:
            lines.append("<p>Requested identifiers with no retained match: "
                         + ", ".join(Html(item) for item in unmatched) + ".</p>")

        assertions = attributes.get("source_assertions")

        if not isinstance(assertions, list):
            lines.append("<p>Readable source details are unavailable; original metadata is "
                         "preserved below.</p>")

            continue

        for assertion in assertions:
            if not isinstance(assertion, dict) or not isinstance(assertion.get("record"), dict):
                lines.append("<p>Unsupported assertion structure retained in "
                             "technical details.</p>")

                continue

            record = assertion["record"]
            data = record.get("data")

            if not isinstance(data, dict):
                lines.append("<p>Readable assertion fields were not retained.</p>")

                continue

            feed = record.get("feed")
            source = assertion.get("source")
            publisher = source.get("publisher", "Not recorded") if isinstance(source, dict) else (
                "Not recorded"
            )
            origin = source.get("origin", "Not recorded") if isinstance(source, dict) else (
                "Not recorded"
            )
            stale = assertion.get("stale")
            freshness = "stale" if stale is True else "within the selected age budget" if (
                stale is False
            ) else "unknown"
            lines.append('<div class="card"><h4>' + Html(record.get("identifier", "Unknown"))
                         + " · " + Html(feed) + "</h4>"
                         + f"<p>Source origin: {Html(origin)} · Publisher: {Html(publisher)}"
                         + " · source version: "
                         + Html(record.get("catalog_version", "Not recorded")) + "</p>"
                         + "<p>Source date: " + Html(record.get("effective_at", "Not recorded"))
                         + f" · Freshness: {freshness}.</p>")

            if feed == IntelligenceFeed.CVE.value:
                lines.append("<p>Source state: " + Html(data.get("state", "Unknown")) + ". "
                             + Html(data.get("description", "No description retained")) + "</p>")
                assessments = data.get("cvss")

                if isinstance(assessments, list):
                    for assessment in assessments:
                        if not isinstance(assessment, dict):
                            continue

                        lines.append("<p>CVSS " + Html(assessment.get("version", "Unknown"))
                                     + " base score: "
                                     + Html(assessment.get("base_score", "Unknown"))
                                     + "/10 · assessor: "
                                     + Html(assessment.get("assessor", "Not recorded")) + ".</p>")
                        lines.append(SeverityScale(assessment.get("base_score")))

            elif feed == IntelligenceFeed.KEV.value:
                lines.append("<p>The source lists known exploitation for this CVE; it does not "
                             "establish exploitation of this target. "
                             + Html(data.get("name", "No name retained")) + "</p>"
                             + "<p>Source required action: "
                             + Html(data.get("required_action", "Not recorded")) + "</p>")

            elif feed == IntelligenceFeed.EPSS.value:
                lines.append("<p>Source EPSS probability: "
                             + Html(data.get("probability", "Unknown"))
                             + " (0–1); percentile: " + Html(data.get("percentile", "Unknown"))
                             + " (0–1). This is the publisher's CVE forecast, "
                             "not a probability of compromise for this target.</p>")

            elif feed == IntelligenceFeed.CWE.value:
                lines.append("<p>Weakness: " + Html(data.get("name", "Not recorded"))
                             + " · source status: " + Html(data.get("status", "Unknown")) + ".</p>")

            lines.append("<p>Target applicability: not determined by this report. Association: "
                         + Html(assertion.get("association_state", "Unknown")) + ".</p>"
                         + "<details><summary>Original assertion and provenance</summary>"
                         + JsonBlock(assertion) + "</details></div>")

    return "\n".join(lines)


def RenderHtml(report: ReportSnapshot) -> bytes:
    """Explain retained results as inert offline HTML while preserving every machine contract.

    Args:
        report: Canonical model/finding projection and explicitly attributed reference context.

    Returns:
        Self-contained UTF-8 HTML with readable facts, advice and technical disclosures;
        no scripts, remote assets, artifact bytes, inferred coverage or guessed relations.

    Raises:
        ValueError: The input contract or serialized output bound is invalid.
    """

    RequireReport(report)
    document = report.ToDict()
    summary = cast(dict[str, object], document["summary"])
    bindings = {item.finding_reference: item for item in report.reference_bindings}
    objects = {entity.Reference(): entity for entity in report.state.objects}
    lines = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta name="color-scheme" content="dark">',
        '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; '
        'style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">',
        f"<title>1337 Evidence report</title><style>{_CSS}</style></head><body><main>",
        '<p class="brand">Fuzzy Technologies · Security Workbench</p>'
        '<h1>Security assessment report</h1>',
        f"<p>Workspace: {Html(report.state.workspace_id)} · "
        f"saved revision {report.state.revision}</p>",
        '<nav aria-label="Report sections"><a href="#executive">Overview</a>'
        '<a href="#operations">Recorded operations</a><a href="#model">Assets</a>'
        '<a href="#findings">Findings</a><a href="#evidence">Evidence</a>'
        '<a href="#relations">Relationships</a></nav>',
        '<section id="executive"><h2>Result at a glance</h2><div class="cards">',
    ]

    for label, value in (
        ("Hosts", len(report.state.Objects(ObjectKind.HOST))),
        ("Services", len(report.state.Objects(ObjectKind.SERVICE))),
        ("Web addresses", len(report.state.Objects(ObjectKind.ENDPOINT))),
        ("Open or confirmed findings", summary["active_findings"]),
        ("Execution records that did not succeed", summary["failed_execution_records"]),
    ):
        lines.append(f'<div class="card"><span class="count">{Html(value)}</span>'
                     f"<p>{label}</p></div>")

    lines.append("</div>")

    if summary["active_findings"]:
        lines.append("<p class=\"notice\">Open or confirmed findings need attention. Read each "
                     "finding's evidence and disposition, confirm its relevance to the subject, "
                     "and follow the retained remediation advice before repeating the check.</p>")

    else:
        lines.append("<p class=\"notice\">No open or confirmed vulnerability findings "
                     "are retained. "
                     "Zero findings do not establish that a target is secure. Discovery records "
                     "describe objects and responses; they are not vulnerability checks.</p>")

    if summary["failed_execution_records"]:
        lines.append("<p>Some retained execution records did not succeed. Review their outcomes "
                     "and missing evidence before relying on the result; export success does "
                     "not change those failures.</p>")

    lines.extend([
        "<p>Scan completeness was not assessed. Counts describe this retained snapshot.</p>",
        '<details><summary>Snapshot identity and technical summary</summary>'
        + f"<p>Canonical snapshot: <code>{report.SnapshotDigest()}</code></p>"
        + JsonBlock(summary) + "</details></section>",
        RetainedOperations(report, document), ObjectTables(report),
        '<section id="findings"><h2>Findings and next actions</h2>',
    ])

    if not report.state.Objects(ObjectKind.FINDING):
        lines.append("<p>No finding records were retained. To assess a vulnerability, run an "
                     "appropriate authorized check and retain its evidence; opening this "
                     "report does not perform one.</p>")

    for entity in report.state.Objects(ObjectKind.FINDING):
        finding = Finding.FromObject(entity)
        reference = entity.Reference()
        status_explanation = {
            FindingStatus.OPEN: "Retained interpretation awaiting an operator disposition.",
            FindingStatus.CONFIRMED: "An operator confirmed this interpretation.",
            FindingStatus.DISMISSED: "An operator dismissed this interpretation; "
                                     "history is retained.",
            FindingStatus.RESOLVED: "Marked resolved by an operator; successful retesting is not "
                                    "established by this disposition alone.",
        }[finding.status]
        lines.extend([
            f'<article class="finding" id="finding-{reference[7:]}">'
            + f'<span class="badge">{Html(finding.severity.value.upper())}</span> '
            + f'<span class="badge">{Html(finding.status.value)}</span>'
            + f"<h3>{Html(finding.summary)}</h3>",
            "<p>Subject: " + ObjectLink(finding.subject_reference,
                                        ObjectLabel(objects[finding.subject_reference])) + "</p>",
            f"<p>Check: {Html(finding.check_id)} · location: {Html(finding.location_key)}</p>",
            "<p>Disposition: " + status_explanation + " Reason: "
            + Html(finding.status_reason or "No reason recorded") + "</p>",
            f"<p>Attributed confidence: {finding.confidence}. This retained detector metadata "
            "is not a probability of compromise.</p>",
            "<h4>What to do next</h4><p>" + Html(finding.remediation.summary or
                "No remediation advice was retained. Review the evidence and determine an "
                "appropriate correction before repeating the check.") + "</p>",
        ])

        if finding.remediation.steps:
            lines.append("<ol>" + "".join("<li>" + Html(step) + "</li>"
                                          for step in finding.remediation.steps) + "</ol>")

        if finding.remediation.references:
            lines.append("<p>Retained advisory references (inert text): "
                         + "; ".join(Html(item) for item in finding.remediation.references)
                         + "</p>")

        lines.append(IntelligenceDetails(report, reference))
        lines.append("<h4>Evidence for this interpretation</h4><ul>")
        references = {item for record in entity.provenance for item in record.evidence_references}

        for index, evidence_reference in enumerate(sorted(references, key=CanonicalModelJson), 1):
            lines.append(f'<li><a href="#{EvidenceId(evidence_reference)}">'
                         f"Evidence {index}: {Html(evidence_reference.role)}</a></li>")

        lines.append("</ul>")
        binding = bindings.get(reference)

        if binding is not None:
            lines.append("<h4>Attributed reference context</h4>"
                         "<p>Context links do not prove classification, observed behavior, "
                         "exploitability, or control fulfillment.</p><ul>")

            for external_reference in binding.references:
                lines.append(f'<li><a href="{Html(external_reference.Url())}" '
                             'rel="noopener noreferrer">'
                             f'{Html(external_reference.external_id)}</a>'
                             f" · catalog {Html(external_reference.catalog_version)}"
                             f" · {Html(external_reference.ToDict()['link_revision'])}</li>")

            lines.append("</ul><details><summary>Reference attribution</summary>"
                         + JsonBlock(binding.ToDict()) + "</details>")

        observations = [JsonValue(item) for item in report.state.observations
                        if item.subject_reference == reference]
        lines.append(f'<details id="object-{reference[7:]}"><summary>Technical finding record '
                     "and observation history</summary>" + JsonBlock(JsonValue(entity))
                     + JsonBlock(observations) + "</details></article>")

    lines.extend([
        '</section><section id="evidence"><h2>Evidence and byte integrity</h2>',
        "<p>Follow a finding's evidence link to its retained reference. Byte verification "
        "checks content integrity; it does not authenticate the publisher, establish "
        "provenance, scan success, or completeness. Raw artifact bytes are not embedded.</p>",
        '<div class="table"><table><thead><tr><th>Evidence</th><th>Role</th><th>Size</th>'
        '<th>Integrity</th><th>Technical reference</th></tr></thead><tbody>',
    ])
    integrity_metadata = cast(dict[str, object], document["evidence_integrity"])
    checked = {CanonicalModelJson(item) for item in cast(
        list[object], integrity_metadata["checked_references"],
    )}

    for index, evidence_reference in enumerate(report.EvidenceReferences(), 1):
        integrity = (
            "verified bytes" if CanonicalModelJson(evidence_reference) in checked
            else "not verified"
        )
        lines.append(f'<tr id="{EvidenceId(evidence_reference)}">'
                     f"<td>Evidence {index}</td><td>{Html(evidence_reference.role)}</td>"
                     f"<td>{evidence_reference.size_bytes} bytes</td><td>{integrity}</td>"
                     "<td><details><summary>Digest and metadata</summary>"
                     + JsonBlock(JsonValue(evidence_reference)) + "</details></td></tr>")

    lines.extend([
        '</tbody></table></div></section><section id="relations"><h2>Stored relationships</h2>',
        "<p>Only stored relations appear here. No reachability or attack paths are inferred.</p>",
        '<div class="table"><table><thead><tr><th>From</th><th>Relationship</th>'
        '<th>To</th><th>Attribution</th></tr></thead><tbody>',
    ])

    for relation in report.state.relations:
        lines.append("<tr><td>" + ObjectLink(relation.source_reference,
                     ObjectLabel(objects[relation.source_reference])) + "</td>"
                     f"<td>{Html(relation.kind.value.replace('-', ' '))}</td><td>"
                     + ObjectLink(relation.target_reference,
                                  ObjectLabel(objects[relation.target_reference])) + "</td>"
                     "<td><details><summary>Relationship provenance</summary>"
                     + JsonBlock(JsonValue(relation)) + "</details></td></tr>")

    lines.extend([
        "</tbody></table></div></section>",
        "<details><summary>Canonical observation history</summary>"
        + JsonBlock(JsonValue(report.state.observations)) + "</details>",
        "</main></body></html>\n",
    ])

    return ReportBytes("\n".join(lines).encode("utf-8"))


def SerializeSarif(report: ReportSnapshot) -> bytes:
    """Export active finding interpretations as SARIF 2.1.0 without inventing scan invocations.

    Args:
        report: Canonical findings, original execution outcomes, and explicit reference context.

    Returns:
        Deterministic UTF-8 SARIF with closed dispositions retained in run properties.

    Raises:
        ValueError: The input contract or serialized output bound is invalid.
    """

    RequireReport(report)
    document = report.ToDict()
    bindings = {item.finding_reference: item.ToDict() for item in report.reference_bindings}
    rules = sorted({Finding.FromObject(item).check_id for item in report.state.Objects(
        ObjectKind.FINDING,
    )})
    results = []
    closed = []
    levels = {
        FindingSeverity.UNKNOWN: "warning", FindingSeverity.INFORMATIONAL: "note",
        FindingSeverity.LOW: "note", FindingSeverity.MEDIUM: "warning",
        FindingSeverity.HIGH: "error", FindingSeverity.CRITICAL: "error",
    }

    for entity in report.state.Objects(ObjectKind.FINDING):
        finding = Finding.FromObject(entity)
        context = {
            "canonicalReference": entity.Reference(), "normalized": finding.ToAttributes(),
            "provenance": JsonValue(entity.provenance),
            "referenceContext": bindings.get(entity.Reference()),
        }

        if finding.status in (FindingStatus.DISMISSED, FindingStatus.RESOLVED):
            closed.append(context)

            continue

        results.append({
            "ruleId": finding.check_id, "ruleIndex": rules.index(finding.check_id),
            "kind": "fail", "level": levels[finding.severity],
            "message": {"text": finding.summary},
            "partialFingerprints": {"1337/finding/v1": finding.Fingerprint()},
            "locations": [{"logicalLocations": [{
                "fullyQualifiedName": finding.subject_reference,
            }]}],
            "properties": context,
        })

    payload = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0", "runs": [{
            "tool": {"driver": {
                "name": "1337 Security Workbench", "organization": "Fuzzy Technologies",
                "informationUri": "https://fuzzy-technologies.github.io/1337/",
                "rules": [{"id": identifier} for identifier in rules],
            }},
            "results": results,
            "properties": {
                "reportSchemaVersion": REPORT_SCHEMA_VERSION,
                "workspaceId": report.state.workspace_id, "modelRevision": report.state.revision,
                "canonicalSnapshotSha256": report.SnapshotDigest(),
                "scanCompleteness": "not-assessed", "closedFindings": closed,
                "evidenceIntegrity": document["evidence_integrity"],
                "executionOutcomes": document["execution_outcomes"],
            },
        }],
    }

    return ReportBytes(CanonicalModelJson(payload) + b"\n")


def SerializeJunit(report: ReportSnapshot) -> bytes:
    """Adapt retained findings to JUnit failures/skips without asserting passed security checks.

    Args:
        report: Canonical model/finding projection; XML controls are rendered as visible escapes.

    Returns:
        UTF-8 XML with snapshot/integrity properties and one case per retained finding.

    Raises:
        ValueError: The input contract or serialized output bound is invalid.
    """

    RequireReport(report)
    entities = report.state.Objects(ObjectKind.FINDING)
    findings = [(entity, Finding.FromObject(entity)) for entity in entities]
    active = sum(finding.status in (FindingStatus.OPEN, FindingStatus.CONFIRMED)
                 for _, finding in findings)
    root = ElementTree.Element("testsuite", {
        "name": "1337 retained findings", "tests": str(len(findings)),
        "failures": str(active), "errors": "0", "skipped": str(len(findings) - active),
    })
    properties = ElementTree.SubElement(root, "properties")

    for name, value in (
        ("report_schema_version", REPORT_SCHEMA_VERSION),
        ("workspace_id", report.state.workspace_id),
        ("model_revision", report.state.revision), ("snapshot_sha256", report.SnapshotDigest()),
        ("scan_completeness", "not-assessed"),
        ("evidence_integrity", CanonicalModelJson(
            report.ToDict()["evidence_integrity"],
        ).decode("utf-8")),
        ("execution_outcomes", CanonicalModelJson(
            report.ToDict()["execution_outcomes"],
        ).decode("utf-8")),
        ("reference_context", CanonicalModelJson(
            report.ToDict()["reference_bindings"],
        ).decode("utf-8")),
    ):
        ElementTree.SubElement(properties, "property", {"name": name, "value": Text(value)})

    for entity, finding in findings:
        case = ElementTree.SubElement(root, "testcase", {
            "classname": finding.check_id, "name": finding.Fingerprint(),
        })
        kind = (
            "failure" if finding.status in (FindingStatus.OPEN, FindingStatus.CONFIRMED)
            else "skipped"
        )
        detail = ElementTree.SubElement(case, kind, {
            "message": Text(finding.summary if kind == "failure" else finding.status_reason),
            "type": "SecurityFinding" if kind == "failure" else finding.status.value,
        })
        detail.text = Text(CanonicalModelJson({
            "canonical_reference": entity.Reference(), "normalized": finding.ToAttributes(),
            "provenance": JsonValue(entity.provenance), "scan_completeness": "not-assessed",
        }).decode("utf-8"))

    return ReportBytes(ElementTree.tostring(root, encoding="utf-8", xml_declaration=True) + b"\n")
