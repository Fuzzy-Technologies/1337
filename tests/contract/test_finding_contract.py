# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Versioned finding attributes, canonical identity, and shared-model persistence contracts."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from fuzzy1337 import model
from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.findings import ApplyFindings, Finding, Findings, FindingStatus, TransitionFinding
from fuzzy1337.model import (
    ModelProvenance,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)

ROOT = Path(__file__).resolve().parents[2]


def Provenance():
    """Provide typed synthetic evidence linkage without claiming raw bytes were verified."""

    return ModelProvenance(
        "native", "run:fixture", "2026-10-11T10:00:00Z", "scope:local", "target:local",
        evidence_references=(EvidenceReference(
            "stdout", "blobs/sha256/" + "a" * 64, "a" * 64, "application/json", 2,
        ),),
    )


def Document():
    """Load the tracked known-answer attribute fixture as detached strict JSON."""

    return json.loads((ROOT / "contracts" / "examples" / "finding.json").read_text("utf-8"))


def Validator():
    """Load the declared Draft 2020-12 attribute schema without external references."""

    schema = json.loads((ROOT / "contracts" / "finding.schema.json").read_text("utf-8"))
    Draft202012Validator.check_schema(schema)

    return Draft202012Validator(schema)


def State():
    """Bind the fixture to its first-party subject in the existing canonical snapshot."""

    host = SecurityObject(
        ObjectIdentity("synthetic", ObjectKind.HOST, "127.0.0.1"), {}, (Provenance(),),
    )
    state, _ = ModelState("synthetic").Apply(objects=(host,))
    finding = Finding.FromAttributes(Document(), (Provenance(),))
    state, _ = ApplyFindings(state, (finding,))

    return state


def test_KnownAnswerFingerprintAndStrictSchemaRoundTrip():
    """The tracked fixture fixes identity serialization and structural field semantics."""

    document = Document()
    Validator().validate(document)
    finding = Finding.FromAttributes(document, (Provenance(),))

    assert finding.Fingerprint() == (
        "eaeff2c4e47d84fe2eef972fbe0d73456edde88aa3626be97b6c4375a1383f6b"
    ), "Finding identity serialization changed without a contract decision"
    assert finding.ToAttributes() == document, "Normalized fields changed during strict round trip"
    assert Finding.FromObject(finding.ToObject("synthetic")) == finding, (
        "The SOM projection introduced a competing normalized record"
    )


@pytest.mark.parametrize("field,value", [
    ("schema_version", 2), ("schema_version", True), ("fingerprint", "bad"),
    ("fingerprint", "a" * 64 + "\n"), ("subject_reference", "relation:" + "a" * 64),
    ("subject_reference", "object:" + "a" * 64 + "\n"), ("check_id", "UPPER"),
    ("check_id", "rule\n"), ("location_key", ""), ("summary", "line\nbreak"),
    ("severity", "provider-critical"), ("confidence", True), ("confidence", -1),
    ("confidence", 1.1), ("status", "unknown"), ("status", "confirmed"),
    ("status_reason", ""), ("remediation", {}),
    ("remediation", {"summary": None, "steps": [], "references": ["policy:a", "policy:a"]}),
])
def test_RuntimeAndPublishedSchemaRejectStructuralViolations(field, value):
    """Schema consumers and runtime producers agree on typed version-1 fields."""

    document = Document()
    document[field] = value

    assert not Validator().is_valid(document), "Published schema accepted an invalid field"

    with pytest.raises(ValueError):
        Finding.FromAttributes(document, (Provenance(),))


@pytest.mark.parametrize("mutation", ["missing", "extra", "remediation-extra"])
def test_UnknownAndAbsentFieldsFailClosed(mutation):
    """Future required fields cannot be discarded by older normalized readers."""

    document = Document()

    if mutation == "missing":
        document.pop("severity")

    elif mutation == "extra":
        document["provider_payload"] = {}

    else:
        document["remediation"]["execute"] = "unsupported"

    assert not Validator().is_valid(document), "Attribute schema ignored unknown/missing fields"

    with pytest.raises(ValueError):
        Finding.FromAttributes(document, (Provenance(),))


def test_RuntimeRecomputesFingerprintAndObjectNaturalKey():
    """Syntactically valid hashes are not sufficient proof of first-party identity."""

    document = Document()
    document["fingerprint"] = "a" * 64

    assert Validator().is_valid(document), "Structural schema unexpectedly hashes identity"

    with pytest.raises(ValueError, match="fingerprint"):
        Finding.FromAttributes(document, (Provenance(),))

    finding = Finding.FromAttributes(Document(), (Provenance(),))

    with pytest.raises(ValueError, match="key"):
        SecurityObject(
            ObjectIdentity("synthetic", ObjectKind.FINDING, "wrong-key"),
            finding.ToAttributes(), finding.provenance,
        )


@pytest.mark.parametrize("entity", [None, {}, "finding"])
def test_ProjectionRejectsUntypedRecords(entity):
    """Only the existing canonical object type may supply finding projections."""

    with pytest.raises(ValueError):
        Finding.FromObject(entity)


def test_GenericFindingObjectRequiresCanonicalFields():
    """Generic adapters cannot use the new kind to bypass its normalized schema."""

    with pytest.raises(ValueError):
        SecurityObject(ObjectIdentity("synthetic", ObjectKind.FINDING, "provider-key"),
                       {"severity": "whatever"}, (Provenance(),))

    with pytest.raises(ValueError, match="finding"):
        Finding.FromObject(State().Objects(ObjectKind.HOST)[0])


def test_FindingCollisionCannotOverwriteAnotherObjectKind(monkeypatch):
    """Even an injected digest collision fails before treating a host as an existing finding."""

    host = State().Objects(ObjectKind.HOST)[0]
    state = ModelState("synthetic", objects=(host,))
    real_reference = model.ModelReference

    def CollidingReference(namespace, value):
        """Inject a finding identity collision without changing the legitimate subject reference."""

        if namespace == "object" and isinstance(value, ObjectIdentity) and (
            value.kind is ObjectKind.FINDING
        ):
            return host.Reference()

        return real_reference(namespace, value)

    monkeypatch.setattr(model, "ModelReference", CollidingReference)
    finding = Finding.FromAttributes(Document(), (Provenance(),))

    with pytest.raises(ValueError, match="collision"):
        state.Apply(objects=(finding.ToObject("synthetic"),))


def test_PersistedFindingRemainsOneSchemaVersionOneModelObject():
    """The additive kind retains the exact model envelope, evidence, and strict reopen boundary."""

    state = State()
    document = state.ToDict()

    assert document["schema_version"] == 1 and set(document) == {
        "schema_version", "workspace_id", "revision", "objects", "relations", "observations",
    }, "Finding implementation changed the existing model envelope"
    assert ModelState.FromDict(document) == state, "Canonical findings did not reopen losslessly"
    entity = next(item for item in document["objects"] if item["identity"]["kind"] == "finding")
    entity["attributes"]["schema_version"] = 99

    with pytest.raises(ValueError, match="schema"):
        ModelState.FromDict(document)


def test_PersistedFindingCannotPointToMissingOrFindingSubjects():
    """Finding relationships resolve only to non-finding objects in the same workspace."""

    state = State()
    first = Findings(state)[0]

    for subject in ("object:" + "f" * 64, state.Objects(ObjectKind.FINDING)[0].Reference()):
        finding = replace(first, subject_reference=subject)

        with pytest.raises(ValueError, match="subject"):
            ApplyFindings(state, (finding,))


def test_GenericUpdatesEnforceEvidenceAndDispositionLifecycle():
    """Direct SOM writers cannot bypass linkage, open creation, or explicit reopening rules."""

    state = State()
    first = Findings(state)[0]
    no_evidence = replace(first, provenance=(replace(Provenance(), evidence_references=()),))
    subject_only = ModelState("synthetic", objects=state.Objects(ObjectKind.HOST))

    with pytest.raises(ValueError, match="evidence"):
        subject_only.Apply(objects=(no_evidence.ToObject("synthetic"),))

    triaged = replace(first, status=FindingStatus.CONFIRMED, status_reason="Checked")

    with pytest.raises(ValueError, match="open"):
        subject_only.Apply(objects=(triaged.ToObject("synthetic"),))

    reference = state.Objects(ObjectKind.FINDING)[0].Reference()
    resolved, _ = TransitionFinding(
        state, reference, FindingStatus.RESOLVED, Provenance(), "Remediated in fixture",
    )

    with pytest.raises(ValueError, match="reopen"):
        resolved.Apply(objects=(triaged.ToObject("synthetic"),))

    assert ModelState.FromDict(resolved.ToDict()) == resolved, (
        "Valid persisted disposition was rejected as if it were a new detection"
    )
