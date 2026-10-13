# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic offline HTML, JSON, SARIF, and JUnit adapters for report snapshots."""

from __future__ import annotations

import hashlib
import html
from typing import cast
from xml.etree import ElementTree

from fuzzy1337.adapters.contracts import EvidenceReference, JsonValue
from fuzzy1337.findings import Finding, FindingSeverity, FindingStatus
from fuzzy1337.model import CanonicalModelJson, ObjectKind
from fuzzy1337.reporting import MAX_REPORT_BYTES, REPORT_SCHEMA_VERSION, ReportSnapshot

__all__ = ["RenderHtml", "SerializeJson", "SerializeSarif", "SerializeJunit"]
_CSS = """
:root {color-scheme:dark;--bg:#07090d;--panel:#0b1117;--text:#b9dce8;
--muted:#7f9da8;--cyan:#55e7ff;--pink:#ff5bd8;--green:#5dff8d;--border:#00eaff4d}
* {box-sizing:border-box} body {margin:0;background:var(--bg);color:var(--text);
font:15px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
main {max-width:1180px;margin:auto;padding:2rem 1rem} h1,h2,h3 {color:var(--cyan)}
a {color:var(--pink);overflow-wrap:anywhere} .brand {color:var(--green)}
.muted {color:var(--muted)} nav {display:flex;gap:1rem;flex-wrap:wrap}
.cards {display:flex;flex-wrap:wrap;gap:1rem}.card,details {background:var(--panel);
border:1px solid var(--border);border-radius:8px;padding:1rem;margin:1rem 0}
.card {flex:1;min-width:180px} .count {font-size:2rem;color:var(--green)}
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


def ObjectLink(reference: str) -> str:
    """Render a fragment link using a previously validated canonical object reference.

    Args:
        reference: Canonical object reference resolved by the enclosing model snapshot.

    Returns:
        In-document anchor with escaped display text and an existing object fragment.
    """

    return f'<a href="#object-{reference[7:]}">{Html(reference)}</a>'


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


def RenderHtml(report: ReportSnapshot) -> bytes:
    """Render a dark offline report with native disclosure, canonical fragments, and safe links.

    Args:
        report: Canonical model/finding projection and explicitly attributed reference context.

    Returns:
        Self-contained UTF-8 HTML; no scripts, remote assets, artifact bytes, or guessed edges.

    Raises:
        ValueError: The input contract or serialized output bound is invalid.
    """

    RequireReport(report)
    document = report.ToDict()
    summary = cast(dict[str, object], document["summary"])
    bindings = {item.finding_reference: item for item in report.reference_bindings}
    lines = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta name="color-scheme" content="dark">',
        '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; '
        'style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">',
        f"<title>1337 Evidence report</title><style>{_CSS}</style></head><body><main>",
        '<p class="brand">Fuzzy Technologies · Security Workbench</p>'
        '<h1>1337 / Evidence report</h1>',
        f"<p>Workspace {Html(report.state.workspace_id)} · revision {report.state.revision}</p>",
        f'<p class="muted">Canonical snapshot: <code>{report.SnapshotDigest()}</code></p>',
        '<nav aria-label="Report sections"><a href="#executive">Summary</a>'
        '<a href="#findings">Findings</a><a href="#evidence">Evidence</a>'
        '<a href="#model">Model</a><a href="#relations">Relations</a></nav>',
        '<section id="executive"><h2>Executive summary</h2><div class="cards">',
    ]

    for label, key in (
        ("Active interpretations", "active_findings"), ("Retained findings", "findings"),
        ("Failed execution records", "failed_execution_records"),
    ):
        lines.append(f'<div class="card"><span class="count">{Html(summary[key])}</span>'
                     f"<p>{label}</p></div>")

    lines.extend([
        "</div><p>Scan completeness was not assessed. Counts describe this retained snapshot.</p>",
        '<details><summary>Technical summary</summary>'
        + JsonBlock(summary) + "</details></section>",
        '<section id="findings"><h2>Finding details</h2>',
    ])

    for entity in report.state.Objects(ObjectKind.FINDING):
        finding = Finding.FromObject(entity)
        reference = entity.Reference()
        lines.extend([
            f'<details id="finding-{reference[7:]}"><summary>{finding.severity.value.upper()} · '
            f"{Html(finding.summary)} · {finding.status.value}</summary>",
            f"<p>Subject: {ObjectLink(finding.subject_reference)}</p>",
            f"<p>Check: {Html(finding.check_id)} · location: {Html(finding.location_key)}</p>",
            f"<p>Attributed confidence: {finding.confidence}; "
            f"reason: {Html(finding.status_reason or 'none')}</p>",
            "<h3>Normalized interpretation and remediation</h3>"
            + JsonBlock(finding.ToAttributes()),
            "<h3>Acquisition and disposition provenance</h3>"
            + JsonBlock(JsonValue(entity.provenance)),
            "<h3>Linked evidence</h3><ul>",
        ])

        references = {item for record in entity.provenance for item in record.evidence_references}

        for evidence_reference in sorted(references, key=CanonicalModelJson):
            lines.append(f'<li><a href="#{EvidenceId(evidence_reference)}">'
                         f"{Html(evidence_reference.role)} · {evidence_reference.sha256}</a></li>")

        lines.append("</ul>")
        binding = bindings.get(reference)

        if binding is not None:
            lines.append("<h3>Attributed reference context</h3>"
                         "<p>Context links do not prove classification,")
            lines.append("observed behavior, exploitability, or control fulfillment.</p><ul>")

            for external_reference in binding.references:
                lines.append(f'<li><a href="{Html(external_reference.Url())}" '
                             'rel="noopener noreferrer">'
                             f'{Html(external_reference.external_id)}</a>'
                             f" · catalog {Html(external_reference.catalog_version)}"
                             f" · {Html(external_reference.ToDict()['link_revision'])}</li>")

            lines.append("</ul>" + JsonBlock(binding.ToDict()))

        observations = [JsonValue(item) for item in report.state.observations
                        if item.subject_reference == reference]
        lines.append("<details><summary>Retained observation history</summary>" +
                     JsonBlock(observations) + "</details></details>")

    lines.extend([
        '</section><section id="evidence"><h2>Artifact integrity</h2>',
        "<p>Byte verification is separate from provenance, scan success, and completeness.</p>",
        '<div class="table"><table><thead><tr><th>Role / digest</th><th>Size</th>'
        '<th>Integrity</th><th>Reference metadata</th></tr></thead><tbody>',
    ])
    integrity_metadata = cast(dict[str, object], document["evidence_integrity"])
    checked = {CanonicalModelJson(item) for item in cast(
        list[object], integrity_metadata["checked_references"],
    )}

    for evidence_reference in report.EvidenceReferences():
        integrity = (
            "verified bytes" if CanonicalModelJson(evidence_reference) in checked
            else "not verified"
        )
        lines.append(f'<tr id="{EvidenceId(evidence_reference)}">'
                     f"<td>{Html(evidence_reference.role)}<br>{evidence_reference.sha256}</td>"
                     f"<td>{evidence_reference.size_bytes}</td><td>{integrity}</td>"
                     f"<td>{JsonBlock(JsonValue(evidence_reference))}</td></tr>")

    lines.extend([
        '</tbody></table></div></section><section id="model"><h2>Canonical objects</h2>',
    ])

    for entity in report.state.objects:
        lines.append(f'<details id="object-{entity.Reference()[7:]}"><summary>'
                     f"{entity.identity.kind.value} · {Html(entity.identity.key)}</summary>"
                     + JsonBlock(JsonValue(entity)) + "</details>")

    lines.extend([
        '</section><section id="relations"><h2>Attributed model relations</h2>',
        "<p>Only stored relations appear here. No reachability or attack paths are inferred.</p>",
        '<div class="table"><table><thead><tr><th>Source</th><th>Relation</th>'
        '<th>Target</th><th>Attribution</th></tr></thead><tbody>',
    ])

    for relation in report.state.relations:
        lines.append(f"<tr><td>{ObjectLink(relation.source_reference)}</td>"
                     f"<td>{relation.kind.value}</td><td>{ObjectLink(relation.target_reference)}</td>"
                     f"<td>{JsonBlock(JsonValue(relation))}</td></tr>")

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
