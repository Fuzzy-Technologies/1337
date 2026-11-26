# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic synthetic canonical snapshot for report contracts and golden outputs."""

from dataclasses import replace
from html.parser import HTMLParser

from fuzzy1337.adapters.contracts import AdapterExecution, EvidenceReference, ExecutionState
from fuzzy1337.findings import (
    ApplyFindings,
    Finding,
    FindingSeverity,
    FindingStatus,
    Remediation,
    TransitionFinding,
)
from fuzzy1337.model import (
    ModelProvenance,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    Relation,
    RelationKind,
    SecurityObject,
)
from fuzzy1337.reporting import FindingReferences, ReportReference, ReportSnapshot


class Dom(HTMLParser):
    """Collect exact inert HTML tags, attributes, IDs, and text without executing a browser."""

    def __init__(self):
        """Initialize independent parser collections for one report."""

        super().__init__()
        self.tags = []
        self.attributes = []
        self.ids = []
        self.links = []
        self.text = []
        self.primary_text = []
        self.headingIds = set()
        self.tableLabels = []
        self.tableRegions = []
        self.disclosure_depth = 0
        self.style_depth = 0

    def HandleStartTag(self, tag, attrs):
        """Record parsed attributes and targets, including decoded HTML entities."""

        self.tags.append(tag)

        if tag == "details":
            self.disclosure_depth += 1

        if tag == "style":
            self.style_depth += 1

        self.attributes.extend(attrs)
        fields = dict(attrs)

        if "id" in fields:
            self.ids.append(fields["id"])

            if tag in ("h2", "h3"):
                self.headingIds.add(fields["id"])

        if tag == "div" and fields.get("class") == "table":
            self.tableRegions.append(fields)

        if tag == "table":
            self.tableLabels.append(fields.get("aria-labelledby"))

        if tag == "a":
            self.links.append(fields["href"])

    def HandleData(self, data):
        """Record visible text for independent escaped-payload assertions."""

        self.text.append(data)

        if not self.disclosure_depth and not self.style_depth:
            self.primary_text.append(data)

    def HandleEndTag(self, tag):
        """Track closed disclosures independently of their preserved technical content."""

        if tag == "details":
            self.disclosure_depth -= 1

        if tag == "style":
            self.style_depth -= 1

    handle_starttag = HandleStartTag
    handle_data = HandleData
    handle_endtag = HandleEndTag


def Fixture(summary="Synthetic check interpretation", key="build:synthetic") -> ReportSnapshot:
    """Create attributed synthetic metadata, four dispositions, and one stored relation."""

    evidence = EvidenceReference(
        "stdout", "blobs/sha256/" + "a" * 64, "a" * 64, "application/json", 2,
    )
    provenance = ModelProvenance(
        "synthetic", "run:synthetic", "2026-10-13T00:00:00Z", "scope:fixture", "target:fixture",
        evidence_references=(evidence,), execution=AdapterExecution(ExecutionState.FAILED, 2, 0.1),
    )
    host = SecurityObject(
        ObjectIdentity("synthetic", ObjectKind.HOST, "127.0.0.1"), {"state": "reported"},
        (provenance,),
    )
    asset = SecurityObject(ObjectIdentity("synthetic", ObjectKind.ASSET, key), {}, (provenance,))
    relation = Relation(RelationKind.RELATED_TO, host.Reference(), asset.Reference(),
                        provenance=(provenance,))
    state, _ = ModelState("synthetic").Apply(objects=(host, asset), relations=(relation,))
    detections = tuple(Finding(
        host.Reference(), "synthetic.test-check", f"tcp/{443 + index}", summary, (provenance,),
        severity=severity, confidence=0.75,
        remediation=Remediation("Review the synthetic fixture", ("Inspect local evidence",)),
    ) for index, severity in enumerate((FindingSeverity.HIGH, FindingSeverity.UNKNOWN,
                                       FindingSeverity.LOW, FindingSeverity.INFORMATIONAL)))
    state, _ = ApplyFindings(state, detections)
    operator = replace(provenance, source_id="operator", execution=None, evidence_references=())

    for detection, disposition in zip(detections[1:], (
        FindingStatus.CONFIRMED, FindingStatus.DISMISSED, FindingStatus.RESOLVED,
    ), strict=True):
        state, _ = TransitionFinding(
            state, detection.ToObject("synthetic").Reference(), disposition,
            replace(operator, run_reference="decision:" + disposition.value), "Fixture disposition",
        )

    references = (
        ReportReference("cve", "CVE-2025-12345", "synthetic-1"),
        ReportReference("cwe", "CWE-89", "4.20"),
        ReportReference("capec", "CAPEC-66", "3.9"),
        ReportReference("attack", "T1190", "19"),
        ReportReference("atlas", "AML.T0001", "synthetic-1"),
        ReportReference("owasp-top10", "A03:2021", "2021"),
    )
    context = FindingReferences(
        detections[0].ToObject("synthetic").Reference(), references,
        "Synthetic display context; identifier syntax does not prove membership or a match",
        provenance,
    )

    return ReportSnapshot(state, (context,))
