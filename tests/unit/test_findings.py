# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure finding identity, deduplication, immutable fields, and disposition boundaries."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.findings import (
    ApplyFindings,
    Finding,
    Findings,
    FindingSeverity,
    FindingStatus,
    Remediation,
    TransitionFinding,
    ValidateFindingTransition,
)
from fuzzy1337.model import (
    ModelProvenance,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)


def Provenance(source_id="native", run_reference="run:one", evidence=True):
    """Supply typed synthetic acquisition or operator context without accessing storage."""

    references = (EvidenceReference(
        "stdout", "blobs/sha256/" + "a" * 64, "a" * 64, "application/json", 2,
    ),) if evidence else ()

    return ModelProvenance(
        source_id, run_reference, "2026-10-11T10:00:00Z", "scope:local", "target:local",
        evidence_references=references,
    )


def Host(workspace_id="synthetic"):
    """Create a canonical subject already attributable to the synthetic workspace."""

    return SecurityObject(
        ObjectIdentity(workspace_id, ObjectKind.HOST, "127.0.0.1"), {}, (Provenance(),),
    )


def Detection(**fields):
    """Build one normalized first-party finding and replace only requested test fields."""

    finding = Finding(
        Host().Reference(), "transport.test-policy", "tcp/443", "Synthetic TLS policy",
        (Provenance(),), severity=FindingSeverity.MEDIUM, confidence=0.75,
        remediation=Remediation("Update the local test policy", ("Change the fixture",)),
    )

    return replace(finding, **fields)


def State():
    """Prepare one canonical model subject through its real immutable update boundary."""

    state, _ = ModelState("synthetic").Apply(objects=(Host(),))

    return state


def test_FingerprintExcludesProviderAndMutableInterpretation():
    """Different acquisitions and metadata converge on the same first-party finding identity."""

    first = Detection()
    second = Detection(
        summary="Alternative interpretation", severity=FindingSeverity.LOW, confidence=0.25,
        provenance=(Provenance("other-provider", "run:two"),), remediation=Remediation(),
    )

    assert first.Fingerprint() == second.Fingerprint(), "Mutable/provider fields changed identity"
    assert first.ToObject("synthetic").Reference() == second.ToObject("synthetic").Reference(), (
        "Equivalent findings did not converge on the same canonical model reference"
    )


@pytest.mark.parametrize("fields", [
    {"check_id": "another-check"}, {"location_key": "tcp/8443"},
    {"subject_reference": Host("other").Reference()},
])
def test_FingerprintDistinguishesCheckLocationAndWorkspace(fields):
    """Dedupe never merges distinct checks, locations, or workspace-bound subjects."""

    assert Detection(**fields).Fingerprint() != Detection().Fingerprint(), (
        "Distinct first-party identity fields collapsed into one fingerprint"
    )


def test_RemediationAndFindingAreImmutableAndCanonical():
    """Caller-owned sequences cannot mutate advisory fields or attribution after construction."""

    steps = ["Review", "Update"]
    references = ["policy:b", "policy:a", "policy:a"]
    remediation = Remediation("Local advice", steps, references)
    finding = Detection(remediation=remediation, confidence=1)
    steps.append("Unexpected")
    references.clear()

    assert remediation.steps == ("Review", "Update"), "Caller mutation changed ordered steps"
    assert remediation.references == ("policy:a", "policy:b"), "References were not canonicalized"
    assert finding.confidence == 1.0 and isinstance(finding.confidence, float), (
        "Confidence did not preserve its normalized finite numeric contract"
    )

    with pytest.raises(FrozenInstanceError):
        finding.summary = "Changed"


@pytest.mark.parametrize("fields", [
    {"subject_reference": "relation:" + "a" * 64}, {"subject_reference": "bad"},
    {"check_id": "Provider Uppercase"}, {"location_key": ""}, {"location_key": "bad\nkey"},
    {"summary": ""}, {"summary": "\x00"}, {"summary": 1},
    {"severity": "medium"}, {"status": "open"}, {"status": FindingStatus.CONFIRMED},
    {"confidence": True}, {"confidence": "0.5"}, {"confidence": -0.1},
    {"confidence": 1.1}, {"confidence": float("nan")}, {"confidence": float("inf")},
    {"confidence": 10 ** 1000}, {"confidence": -(10 ** 1000)},
    {"remediation": {}}, {"status_reason": ""}, {"provenance": ()},
    {"provenance": "all"}, {"provenance": ({},)}, {"summary": "a" * 65536},
])
def test_FindingRejectsMalformedUntypedOrUnboundedFields(fields):
    """Unsupported fields cannot become a persisted canonical finding by coercion."""

    with pytest.raises(ValueError):
        Detection(**fields)


@pytest.mark.parametrize("fields", [
    {"summary": ""}, {"summary": 1}, {"steps": "all"}, {"steps": ("",)},
    {"references": ({},)}, {"references": ("line\nbreak",)}, {"summary": "a" * 65536},
])
def test_RemediationRejectsMalformedAdvisoryFields(fields):
    """Advisory content follows the same strict size/text boundary as the shared model."""

    with pytest.raises(ValueError):
        Remediation(**fields)


def test_DetectorDedupeUsesOneObjectAndRetainsAcquisitionHistory():
    """Same-check acquisitions update one object and preserve attributable interpretations."""

    first = Detection()
    initial, _ = ApplyFindings(State(), (first,))
    second = Detection(
        summary="Second acquisition", confidence=0.8,
        provenance=(Provenance("second-provider", "run:two"),),
    )
    updated, delta = ApplyFindings(initial, (second,))
    entity = updated.Objects(ObjectKind.FINDING)[0]
    replayed, replay_delta = ApplyFindings(updated, (second,))
    observations = [item for item in updated.observations if item.kind == "finding-detection"]

    assert len(Findings(updated)) == 1, "Repeated detection created a second canonical finding"
    assert Findings(updated)[0].summary == second.summary, "Ordered metadata update was lost"
    assert len(entity.provenance) == 2, "Dedupe lost provider acquisition provenance"
    assert {item.attributes["summary"] for item in observations} == {
        first.summary, second.summary,
    }, "Dedupe erased earlier normalized interpretations"
    assert entity.Reference() in delta.updated, "Finding metadata change did not enter the delta"
    assert replayed == updated and replay_delta.revision == updated.revision, (
        "Exact replay changed canonical state or created another revision"
    )


def test_BatchOrderingAndEmptyReplayAreExplicit():
    """Identical keys dedupe in one batch and its ordered last interpretation is current."""

    first = Detection()
    second = Detection(summary="Later in batch")
    state, delta = ApplyFindings(State(), (first, second))
    unchanged, empty_delta = ApplyFindings(state, ())

    assert len(Findings(state)) == 1 and Findings(state)[0].summary == second.summary, (
        "Ordered duplicate detections created a second finding or ignored the latest metadata"
    )
    assert delta.revision == delta.previous_revision + 1, "One batch advanced multiple revisions"
    assert unchanged == state and empty_delta.created == empty_delta.updated == (), (
        "An empty batch changed canonical state"
    )


@pytest.mark.parametrize("status", [FindingStatus.CONFIRMED, FindingStatus.DISMISSED,
                                    FindingStatus.RESOLVED])
def test_DetectorRediscoveryPreservesOperatorDisposition(status):
    """New acquisitions retain explicit triage and their actual incoming open detection fact."""

    state, _ = ApplyFindings(State(), (Detection(),))
    reference = state.Objects(ObjectKind.FINDING)[0].Reference()
    triage = Provenance("operator", "decision:one", evidence=False)
    triaged, _ = TransitionFinding(state, reference, status, triage, "Reviewed local evidence")
    detected = Detection(provenance=(Provenance("another-provider", "run:two"),))
    updated, _ = ApplyFindings(triaged, (detected,))
    finding = Findings(updated)[0]
    incoming = [item for item in updated.observations if (
        item.kind == "finding-detection" and item.provenance.run_reference == "run:two"
    )]

    assert finding.status is status and finding.status_reason == "Reviewed local evidence", (
        "Detector output silently changed an operator disposition"
    )
    assert finding.provenance == updated.Objects(ObjectKind.FINDING)[0].provenance, (
        "Finding projection established a separate attribution source"
    )
    assert incoming and incoming[0].attributes["status"] == "open", (
        "Triage preservation erased the actual incoming detector interpretation"
    )
    assert not any(item.provenance == triage and item.attributes["status"] == "open"
                   for item in updated.observations if item.subject_reference == reference), (
        "Rediscovery falsely attributed a new disposition to the prior operator decision"
    )
    assert Findings(updated, status) == (finding,), "Typed status query missed its canonical object"
    assert Findings(updated, FindingStatus.OPEN) == (), "Status filter ignored triage"


@pytest.mark.parametrize("following", [FindingStatus.OPEN, FindingStatus.DISMISSED,
                                       FindingStatus.RESOLVED])
def test_OperatorDecisionReplayPreservesNewerDispositionAndMetadata(following):
    """Retrying an old decision cannot overwrite a later operator or detector interpretation."""

    state, _ = ApplyFindings(State(), (Detection(),))
    reference = state.Objects(ObjectKind.FINDING)[0].Reference()
    first = Provenance("operator", "decision:one", evidence=False)
    second = Provenance("operator", "decision:two", evidence=False)
    state, _ = TransitionFinding(
        state, reference, FindingStatus.CONFIRMED, first, "Initial review",
    )
    state, _ = TransitionFinding(state, reference, following, second, "Later review")
    acquisition = Detection(
        summary="Later detector interpretation", provenance=(Provenance("native", "run:two"),),
    )
    state, _ = ApplyFindings(state, (acquisition,))
    replayed, delta = TransitionFinding(
        state, reference, FindingStatus.CONFIRMED, first, "Initial review",
    )

    assert replayed == state and delta.created == delta.updated == (), (
        "An exact old operator decision replay overwrote newer canonical state"
    )
    assert Findings(replayed)[0].summary == acquisition.summary, (
        "Decision retry restored detector metadata captured by the earlier decision"
    )


def test_DeliberateRepeatedDispositionRequiresNewDecisionAttribution():
    """A fresh decision can return to a prior status without being mistaken for a retry."""

    state, _ = ApplyFindings(State(), (Detection(),))
    reference = state.Objects(ObjectKind.FINDING)[0].Reference()

    for decision, status in (("decision:one", FindingStatus.CONFIRMED),
                             ("decision:two", FindingStatus.OPEN),
                             ("decision:three", FindingStatus.CONFIRMED)):
        state, delta = TransitionFinding(
            state, reference, status, Provenance("operator", decision, evidence=False), "Reviewed",
        )
        assert delta.revision == delta.previous_revision + 1, "A fresh decision was discarded"

    assert Findings(state)[0].status is FindingStatus.CONFIRMED, (
        "A deliberate repeated disposition was treated as an old decision retry"
    )


@pytest.mark.parametrize("previous,following,allowed", [
    (None, FindingStatus.OPEN, True), (None, FindingStatus.CONFIRMED, False),
    (FindingStatus.OPEN, FindingStatus.CONFIRMED, True),
    (FindingStatus.CONFIRMED, FindingStatus.DISMISSED, True),
    (FindingStatus.CONFIRMED, FindingStatus.OPEN, True),
    (FindingStatus.OPEN, FindingStatus.RESOLVED, True),
    (FindingStatus.DISMISSED, FindingStatus.DISMISSED, True),
    (FindingStatus.RESOLVED, FindingStatus.RESOLVED, True),
    (FindingStatus.DISMISSED, FindingStatus.OPEN, True),
    (FindingStatus.RESOLVED, FindingStatus.OPEN, True),
    (FindingStatus.RESOLVED, FindingStatus.CONFIRMED, False),
    (FindingStatus.DISMISSED, FindingStatus.RESOLVED, False),
])
def test_DispositionLifecycleRequiresExplicitReopening(previous, following, allowed):
    """Closed dispositions cannot silently become another closed or confirmed outcome."""

    if allowed:
        ValidateFindingTransition(previous, following)

    else:
        with pytest.raises(ValueError):
            ValidateFindingTransition(previous, following)


@pytest.mark.parametrize("state,findings", [
    ({}, ()), (State(), "all"), (State(), ({},)),
    (State(), (Detection(provenance=(Provenance(evidence=False),)),)),
    (State(), (Detection(status=FindingStatus.CONFIRMED, status_reason="Reviewed"),)),
    (State(), (Detection(status_reason="Reviewed"),)),
])
def test_DetectorIngestionRejectsImplicitEvidenceAndTriage(state, findings):
    """Detector ingestion cannot masquerade as an operator decision or omit evidence linkage."""

    with pytest.raises(ValueError):
        ApplyFindings(state, findings)


@pytest.mark.parametrize("state,status", [({}, None), (State(), "open")])
def test_QueriesRejectUntypedInputs(state, status):
    """A query does not silently accept another authoritative store or untyped status."""

    with pytest.raises(ValueError):
        Findings(state, status)


@pytest.mark.parametrize("fields", [
    {"state": {}}, {"reference": "bad"}, {"reference": "object:" + "f" * 64},
    {"status": "confirmed"}, {"reason": ""}, {"provenance": {}},
])
def test_TransitionsRejectMalformedDecisionContext(fields):
    """Explicit triage still requires an existing subject, typed status, reason, and attribution."""

    state, _ = ApplyFindings(State(), (Detection(),))
    arguments = {
        "state": state, "reference": state.Objects(ObjectKind.FINDING)[0].Reference(),
        "status": FindingStatus.CONFIRMED, "provenance": Provenance("operator", evidence=False),
        "reason": "Verified fixture",
    }
    arguments.update(fields)

    with pytest.raises(ValueError):
        TransitionFinding(**arguments)
