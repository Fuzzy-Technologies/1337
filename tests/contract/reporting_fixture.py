# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic synthetic canonical snapshot for report contracts and golden outputs."""

from dataclasses import replace

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
