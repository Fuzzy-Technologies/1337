# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent criterion truth tables and exact typed CI input refusal."""

from __future__ import annotations

from dataclasses import replace

import pytest

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.ci_gate import (
    CiFindingCriterion,
    CiPredicateResult,
    EvaluateConfigurationCriterion,
    EvaluateImageCriterion,
    EvaluatePredicate,
    RequireModelContracts,
)
from fuzzy1337.findings import Finding, FindingSeverity, FindingStatus
from fuzzy1337.model import ModelProvenance, ModelState, ObjectIdentity, ObjectKind, SecurityObject


def Specimens():
    """Create literal synthetic findings without deriving criterion expectations from gate code."""

    evidence = EvidenceReference("stdout", "blobs/sha256/" + "a" * 64, "a" * 64,
                                 "application/json", 2)
    provenance = ModelProvenance("synthetic.test", "run:test", "2026-10-14T10:00:00Z",
        "scope:test", "target:test", evidence_references=(evidence,))
    subject = SecurityObject(ObjectIdentity("ci-test", ObjectKind.ASSET, "owned:test"), {},
                             (provenance,))
    high = Finding(subject.Reference(), "ci.test", "position:one", "Owned high finding",
                   (provenance,), severity=FindingSeverity.HIGH)
    low = replace(high, location_key="position:two", severity=FindingSeverity.LOW)
    dismissed = replace(high, location_key="position:three", status=FindingStatus.DISMISSED,
                        status_reason="Owned prior operator dismissal")
    unknown = replace(high, location_key="position:four", severity=FindingSeverity.UNKNOWN)
    model = ModelState("ci-test", objects=(subject, *(item.ToObject("ci-test")
                                                   for item in (high, low, dismissed, unknown))))

    return model, (high, low, dismissed, unknown)


@pytest.mark.parametrize("changes", [
    {"severities": ()}, {"statuses": ()}, {"severities": [FindingSeverity.HIGH]},
    {"severities": ("high",)}, {"statuses": ("open",)},
    {"severities": (FindingSeverity.HIGH, FindingSeverity.HIGH)},
    {"statuses": (FindingStatus.OPEN, FindingStatus.OPEN)},
    {"max_matches": True}, {"max_matches": -1}, {"max_matches": 1025},
    {"max_matches": 0.0}, {"acknowledge_unassessed_completeness": False},
    {"acknowledge_unassessed_completeness": 1},
])
def test_ExplicitCriterionRejectsImplicitOrCoercedSelections(changes):
    """Unknown defaults, duplicate labels, bool counts and absent acknowledgement fail closed."""

    values = {"severities": (FindingSeverity.HIGH,), "statuses": (FindingStatus.OPEN,),
              "max_matches": 0, "acknowledge_unassessed_completeness": True}
    values.update(changes)

    with pytest.raises(ValueError):
        CiFindingCriterion(**values)


@pytest.mark.parametrize("severities,statuses,limit,matches,satisfied", [
    ((FindingSeverity.HIGH,), (FindingStatus.OPEN,), 0, 1, False),
    ((FindingSeverity.HIGH,), (FindingStatus.OPEN,), 1, 1, True),
    ((FindingSeverity.LOW,), (FindingStatus.OPEN,), 0, 1, False),
    ((FindingSeverity.MEDIUM,), (FindingStatus.OPEN,), 0, 0, True),
    ((FindingSeverity.HIGH,), (FindingStatus.DISMISSED,), 0, 1, False),
    ((FindingSeverity.HIGH, FindingSeverity.LOW), (FindingStatus.OPEN,), 1, 2, False),
])
def test_HandwrittenPredicateTruthTable(severities, statuses, limit, matches, satisfied):
    """Exact set conjunction and explicit count limit follow independent declared outcomes."""

    model, findings = Specimens()
    criterion = CiFindingCriterion(severities, statuses, limit, True)
    result = EvaluatePredicate(model, findings[:3], criterion, "a" * 64, "artifact-run:" + "a" * 32)
    document = result.ToDict()
    assert result.satisfied is satisfied and document["matched_count"] == matches, (
        "Explicit conjunction/count truth must match the handwritten criterion oracle"
    )
    assert document["selected_count"] == 3 and document["scan_completeness"] == "not-assessed", (
        "A subset predicate must retain independent selected count and unknown completeness"
    )
    assert criterion.ToDict()["acknowledge_unassessed_completeness"] is True, (
        "The required acknowledgement must remain visible in machine output"
    )


def test_UnknownSeverityRequiresExplicitCallerSelection():
    """Unassessed severity cannot disappear into a no-match satisfied result."""

    model, findings = Specimens()
    criterion = CiFindingCriterion((FindingSeverity.HIGH,), (FindingStatus.OPEN,), 0, True)

    with pytest.raises(ValueError):
        EvaluatePredicate(model, findings, criterion, "a" * 64, "artifact-run:" + "a" * 32)

    explicit = replace(criterion, severities=(FindingSeverity.UNKNOWN,))
    result = EvaluatePredicate(model, findings, explicit, "a" * 64, "artifact-run:" + "a" * 32)
    assert not result.satisfied and len(result.matched_finding_references) == 1, (
        "Explicit unknown severity must enter the caller-selected count rather than imply clean"
    )


@pytest.mark.parametrize("value", [None, (), [], (None,)])
def test_PredicateRejectsForeignFindingCollections(value):
    """Missing or mutable selections cannot become an empty successful result."""

    model, _ = Specimens()
    criterion = CiFindingCriterion((FindingSeverity.HIGH,), (FindingStatus.OPEN,), 0, True)

    if value == ():
        result = EvaluatePredicate(model, (), criterion, "a" * 64, "artifact-run:" + "a" * 32)
        assert result.satisfied, "Proven empty selection may satisfy an explicit predicate"

    else:
        with pytest.raises(ValueError):
            EvaluatePredicate(model, value, criterion, "a" * 64, "artifact-run:" + "a" * 32)


def test_ModifiedCriterionCannotBypassReconstruction():
    """Frozen dataclass mutation does not bypass exact criterion validation at use time."""

    model, findings = Specimens()
    criterion = CiFindingCriterion((FindingSeverity.HIGH,), (FindingStatus.OPEN,), 0, True)
    object.__setattr__(criterion, "max_matches", True)

    with pytest.raises(ValueError):
        criterion.ToDict()

    with pytest.raises(ValueError):
        EvaluatePredicate(model, findings[:1], criterion, "a" * 64, "artifact-run:" + "a" * 32)


def test_PublicGateRejectsForeignWrappersBeforeStorage(tmp_path):
    """Exact type rejection occurs before unavailable workspace or callback access."""

    model, _ = Specimens()
    criterion = CiFindingCriterion((FindingSeverity.HIGH,), (FindingStatus.OPEN,), 0, True)

    def Forbidden():
        """Trip any authority lookup for an invalid public input contract."""

        raise AssertionError("Foreign input reached current authority")

    with pytest.raises(ValueError):
        EvaluateConfigurationCriterion(model, None, (), tmp_path,
            expected_snapshot_sha256="a" * 64, criterion=criterion, context_provider=Forbidden)

    with pytest.raises(ValueError):
        EvaluateImageCriterion(model, (), (), tmp_path,
            expected_snapshot_sha256="a" * 64, criterion=criterion, context_provider=Forbidden)


def test_ForeignNestedModelImplementationsAreRefused():
    """Foreign entity types cannot override serializer/equality behavior at a public boundary."""

    model, _ = Specimens()

    class ForeignObject(SecurityObject):
        """Represent an unauthorized alternative implementation of a canonical record."""

    altered = replace(model, objects=tuple(ForeignObject(item.identity, item.attributes,
                                                       item.provenance) for item in model.objects))

    with pytest.raises(ValueError):
        RequireModelContracts(altered)


@pytest.mark.parametrize("changes", [
    {"satisfied": 1}, {"snapshot_sha256": "invalid"}, {"run_reference": "run:foreign"},
    {"selected_finding_references": []}, {"matched_finding_references": ("object:" + "b" * 64,)},
    {"selected_finding_references": ("object:" + "a" * 64, "object:" + "a" * 64)},
    {"selected_finding_references": ("relation:" + "a" * 64,)},
])
def test_ResultReconstructionRejectsForeignOrInconsistentFields(changes):
    """Returned records validate exact grammar and selection without claiming source authority."""

    values = {"satisfied": True, "snapshot_sha256": "a" * 64,
        "run_reference": "artifact-run:" + "a" * 32,
        "selected_finding_references": ("object:" + "a" * 64,), "matched_finding_references": ()}
    values.update(changes)

    with pytest.raises(ValueError):
        CiPredicateResult(**values)

    valid = CiPredicateResult(True, "a" * 64, "artifact-run:" + "a" * 32, (), ())
    object.__setattr__(valid, "satisfied", 1)

    with pytest.raises(ValueError):
        valid.ToDict()


@pytest.mark.parametrize("reference", ["artifact-run:" + "a" * 32, "native-scan:" + "b" * 64])
def test_OriginalArtifactAndNativeRunGrammarsPreserveCriterionShape(reference):
    """Only the two explicit original source identities enter unchanged result serialization."""

    document = CiPredicateResult(True, "a" * 64, reference, (), ()).ToDict()
    assert document["run_reference"] == reference and document["selected_count"] == 0 and (
        document["scan_completeness"] == "not-assessed"
    ), "Native source identity is additive and cannot change predicate or completeness semantics"


@pytest.mark.parametrize("reference", ["native-scan:" + "a" * 63, "native-scan:" + "A" * 64,
    "native-scan:" + "a" * 65, "native-scan:" + "z" * 64, "artifact-run:" + "a" * 64,
    "native-scan:" + "a" * 64 + "\n", "run:" + "a" * 64])
def test_NativeRunGrammarRejectsAmbiguousOrCoercedIdentities(reference):
    """No generic prefix, alternate width, uppercase digest or trailing data is accepted."""

    with pytest.raises(ValueError):
        CiPredicateResult(True, "a" * 64, reference, (), ())
