# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual selected original proof, current model pins, portable analysis and read-only refusals."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
from dataclasses import replace

import pytest

from fuzzy1337 import path_commands as commands
from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import LocalModelStore
from tests.contract.reachability_fixture import Fixture
from tests.path_command_helpers import Arguments, Files, Run, SmallArguments, SmallGraph, Value


def Selected(fixture, records):
    """Select independently produced graph and original assessment pins through the handler."""

    return Arguments(fixture.root, fixture.model, fixture.objects["source"].Reference(),
        fixture.objects["event"].Reference(),
        (item.Reference() for item in fixture.relations.values()),
        assessments=tuple(record.evidence_id for record in records),
        context=fixture.graph["context_reference"], scope=fixture.graph["scope_reference"],
        at=fixture.graph["query_at"])


@pytest.mark.parametrize("phase", ["initial", "potential", "likely", "confirmed", "remediation",
                                  "conflicting-barrier"])
def test_OriginalSixPhaseAttestationsPreservePathOracleAndPortableNoWrites(tmp_path, phase):
    """Every original hop state/barrier remains explicit after actual acquisition and relocation."""

    fixture = Fixture.Create(tmp_path / "workspace")
    records = fixture.Phase(phase)
    before = Files(fixture.root)
    status, result = Run(Selected(fixture, records))
    assert status == 0, "Actual original proof consumer failed its supported phase"
    oracle = json.loads((commands.Path(__file__).parents[1] /
                         "contract/fixtures/reachability.oracle.v1.json").read_text())
    expected = next(item for item in oracle["phase_expectations"] if item["phase"] == phase)
    actual = {tuple(path["hops"]): path["state"] for path in result["analysis"]["search"]["paths"]}
    assert actual == {tuple(fixture.relations[alias].Reference() for alias in path): state
        for path, state in zip(oracle["event_paths"], expected["event_states"], strict=True)}, (
        "Actual command changed original attestation phase or independent path oracle"
    )
    assert "synthetic-private-source-value" not in json.dumps(result) and "_seal" not in str(
        result
    ), (
        "Path DTO copied original raw witnesses, observation attributes or private sealed objects"
    )
    moved = tmp_path / "moved workspace"
    shutil.move(fixture.root, moved)
    fixture.root = moved
    status, replayed = Run(Selected(fixture, records))
    assert status == 0 and replayed == result and Files(moved) == before, (
        "Source-backed path analysis changed after relocation or wrote saved state"
    )


@pytest.mark.parametrize("field,value", [("role", "stdout"), ("media_type", "text/plain"),
    ("source_version", "2"), ("workspace_id", "foreign"), ("scope_reference", "scope:foreign"),
    ("invocation_sha256", "a" * 64)])
def test_SelectedWrongManifestProfileRefusesBeforeAnyRawBlobRead(
    tmp_path, monkeypatch, field, value,
):
    """Selected assessment profile/context rejection cannot reach eager owner Get raw reads."""

    fixture = Fixture.Create(tmp_path / "workspace")
    original = fixture.Assessment()
    store = LocalEvidenceStore(fixture.root / "evidence")
    provenance = original.provenance
    role, media = original.reference.role, original.reference.media_type

    if field == "role":
        role = value

    elif field == "media_type":
        media = value

    else:
        provenance = replace(provenance, **{field: value})

    forged = store.Put(store.Read(original.reference), role, media, provenance)

    def NoRead(*args, **kwargs):
        """Expose an eager raw read before original selected manifest admission."""

        raise AssertionError("Rejected path manifest reached raw bytes")

    monkeypatch.setattr(LocalEvidenceStore, "Read", NoRead)
    status, result = Run(Selected(fixture, (forged,)))
    assert status == 4 and result["analysis"] is None, "Wrong path manifest profile was accepted"


def test_AllSelectedManifestsPreflightBeforeEvenFirstValidRawRead(tmp_path, monkeypatch):
    """A later invalid selected assessment must block raw reads of an earlier valid one."""

    fixture = Fixture.Create(tmp_path / "workspace")
    valid = fixture.Assessment()
    invalid = fixture.Assessment(role="wrong-profile")

    def NoRead(*args, **kwargs):
        """Expose any first selected raw read before the whole manifest selection is checked."""

        raise AssertionError("Path manifest selection was not preflighted completely")

    monkeypatch.setattr(LocalEvidenceStore, "Read", NoRead)
    status, result = Run(Selected(fixture, (valid, invalid)))
    assert status == 4 and result["analysis"] is None, (
        "Later invalid selected assessment was ignored"
    )


@pytest.mark.parametrize("kind", ["support", "assessment"])
def test_PhysicalBlobOversizeRefusesBeforeReadingItsActualBytes(tmp_path, monkeypatch, kind):
    """A small declared manifest cannot bypass physical same-blob allocation preflight."""

    fixture = Fixture.Create(tmp_path / "workspace")
    records = fixture.Phase("confirmed")
    selected = fixture.records["source-portal"] if kind == "support" else records[0]
    ceiling = commands.SUPPORT_BYTES if kind == "support" else commands.ASSESSMENT_BYTES
    (fixture.root / "evidence" / selected.reference.locator).write_bytes(b"x" * (ceiling + 1))
    original = LocalEvidenceStore.Read

    def Read(store, reference):
        """Permit assessment metadata parsing but refuse the oversized selected raw blob."""

        if reference.sha256 == selected.reference.sha256:
            raise AssertionError("Oversized path source reached raw reading")

        return original(store, reference)

    monkeypatch.setattr(LocalEvidenceStore, "Read", Read)
    status, result = Run(Selected(fixture, records))
    assert status == 4 and result["analysis"] is None, "Physical blob size preflight was skipped"


def test_PinnedModelTamperFailsBeforeProofAccess(tmp_path, monkeypatch):
    """An equal-revision different model cannot reuse a selected complete snapshot digest."""

    context = SmallGraph(tmp_path)
    arguments = SmallArguments(context)
    root, basis, objects, _ = context
    changed = replace(objects["pivot"], attributes={"owned": "changed"})
    forged = replace(basis, objects=tuple(changed if item.Reference() == changed.Reference()
        else item for item in basis.objects))
    (root / "state/model/model.json").write_bytes(commands.CanonicalModelJson(forged.ToDict()))

    def NoProof(*args, **kwargs):
        """Expose original proof access after a failed exact saved-model pin."""

        raise AssertionError("Changed saved model reached path proof reading")

    monkeypatch.setattr(commands, "PreflightAssessments", NoProof)
    status, result = Run(arguments)
    assert status == 4 and result["failure"] == "basis", "Equal-revision model tamper was accepted"


def test_OutputAndAnalysisRunWithoutAcquisitionNetworkOrGenericReportReaders(tmp_path, monkeypatch):
    """Read-only analysis does not contact hosts or verify unrelated raw aliases through reports."""

    context = SmallGraph(tmp_path)

    def Refuse(*args, **kwargs):
        """Fail any undesired side effect or hidden generic source enumeration."""

        raise AssertionError("Read-only path command attempted an unrelated side effect")

    monkeypatch.setattr(socket, "socket", Refuse)
    monkeypatch.setattr(socket, "getaddrinfo", Refuse)
    monkeypatch.setattr(subprocess, "Popen", Refuse)
    monkeypatch.setattr(LocalEvidenceStore, "Put", Refuse)
    monkeypatch.setattr(LocalModelStore, "Save", Refuse)
    status, result = Run(SmallArguments(context))
    assert status == 0 and result["authority"] == "none", (
        "Read-only command attempted new authority"
    )


def test_OriginalSupportCorruptionFailsWithoutChangingAnyOwner(tmp_path):
    """Actual original byte integrity remains mandatory after successful physical size preflight."""

    fixture = Fixture.Create(tmp_path / "workspace")
    records = fixture.Phase("confirmed")
    support = fixture.records["source-portal"]
    (fixture.root / "evidence" / support.reference.locator).write_bytes(
        b"x" * support.reference.size_bytes)
    before = Files(fixture.root)
    status, result = Run(Selected(fixture, records))
    assert status == 4 and result["analysis"] is None and Files(fixture.root) == before, (
        "Corrupt original support bytes became a path proof or were overwritten"
    )


@pytest.mark.parametrize("case,reason", [("stale-model", "stale-model"),
    ("expired", "stale-support"), ("future", "future-support"),
    ("failed", "failed-support"), ("missing-observation", "missing-basis"),
    ("missing-evidence", "missing-evidence")])
def test_UnusableOriginalProofRetainsDeclaredConfidenceAndUnknownReason(tmp_path, case, reason):
    """Original unusability stays attributed UNKNOWN through the actual product DTO."""

    options = {}

    if case == "future":
        options["support_time"] = "2026-10-13T00:00:04Z"

    elif case == "failed":
        options["execution"] = AdapterExecution(ExecutionState.FAILED, 1, 0.0)

    fixture = Fixture.Create(tmp_path / "workspace", **options)
    declaration = fixture.Declaration("source-portal")
    envelope = fixture.Envelope([declaration])

    if case == "stale-model":
        envelope["model_version"]["snapshot_sha256"] = "0" * 64

    elif case == "missing-observation":
        declaration["basis"][0]["observation_reference"] = "observation:" + "0" * 64

    elif case == "missing-evidence":
        declaration["basis"][0]["evidence_manifest_ids"] = []

    record = fixture.Assessment(envelope)
    arguments = Selected(fixture, (record,))

    if case == "expired":
        arguments = Value(arguments, "--as-of", "2026-10-13T01:00:04Z")

    before = Files(fixture.root)
    status, result = Run(arguments)
    assert status == 0, "Original unusability was changed into uninformative product refusal"
    edge = next(item for item in result["analysis"]["transitions"]
        if item["relation_reference"] == fixture.relations["source-portal"].Reference())
    assert edge["state"] == "UNKNOWN" and reason in edge["reasons"] and (
        edge["claims"][0]["confidence"] == 0.99
    ), "Product erased the original declared estimate or admitted unusable support"
    estimates = [estimate for path in result["analysis"]["search"]["paths"]
        for estimate in path["confidence_estimates"]
        if estimate["relation_reference"] == edge["relation_reference"]]
    assert estimates and all(item["effective_confidence"] is None for item in estimates), (
        "Original unusable confidence was promoted to an effective path estimate"
    )
    assert Files(fixture.root) == before, "Unusable proof analysis wrote original owner state"


@pytest.mark.parametrize("kind", ["assessment", "support", "manifest"])
@pytest.mark.parametrize("alias", ["hardlink", "symlink"])
def test_SelectedPhysicalAliasesRefuseBeforeReadingTheirOriginalBytes(
    tmp_path, monkeypatch, kind, alias,
):
    """Selected physical aliases cannot bypass the actual retained-source admission boundary."""

    fixture = Fixture.Create(tmp_path / "workspace")
    records = fixture.Phase("confirmed")
    selected = fixture.records["source-portal"] if kind == "support" else records[0]
    path = fixture.root / "evidence" / selected.reference.locator

    if kind == "manifest":
        path = fixture.root / "evidence/records" / (selected.evidence_id[7:] + ".json")

    backup = tmp_path / "physical original"

    try:
        if alias == "hardlink":
            os.link(path, backup)

        else:
            path.rename(backup)
            path.symlink_to(backup)

    except OSError:
        pytest.skip("Host does not support creating the selected physical alias")

    original = LocalEvidenceStore.Read

    def Read(store, reference):
        """Expose selected aliased raw access while allowing earlier assessment parsing."""

        if reference.sha256 == selected.reference.sha256:
            raise AssertionError("Aliased path proof reached raw reading")

        return original(store, reference)

    monkeypatch.setattr(LocalEvidenceStore, "Read", Read)
    status, result = Run(Selected(fixture, records))
    assert status == 4 and result["analysis"] is None, "Selected physical alias was accepted"


@pytest.mark.parametrize("field,value", [("workspace_id", "foreign"),
    ("scope_reference", "scope:foreign"), ("source_id", "foreign-source"),
    ("tool_version", "foreign-provider")])
def test_SubstitutedSupportMetadataRefusesBeforeItsRawRead(tmp_path, monkeypatch, field, value):
    """Original support context and exact observation joins precede support byte admission."""

    fixture = Fixture.Create(tmp_path / "workspace")
    original = fixture.records["source-portal"]
    store = LocalEvidenceStore(fixture.root / "evidence")
    substituted = store.Put(store.Read(original.reference), original.reference.role,
        original.reference.media_type, replace(original.provenance, **{field: value}))
    declaration = fixture.Declaration("source-portal")
    declaration["basis"][0]["evidence_manifest_ids"] = [substituted.evidence_id]
    record = fixture.Assessment(fixture.Envelope([declaration]))
    owning_read = LocalEvidenceStore.Read

    def Read(owner, reference):
        """Permit original assessment parsing but expose a premature substituted support read."""

        if reference.sha256 == substituted.reference.sha256:
            raise AssertionError("Substituted path support reached raw reading")

        return owning_read(owner, reference)

    monkeypatch.setattr(LocalEvidenceStore, "Read", Read)
    status, result = Run(Selected(fixture, (record,)))
    assert status == 4 and result["analysis"] is None, "Substituted support join was accepted"


def test_UnselectedSameBlobAliasCannotAcquireAuthorityOrForceGenericRawReads(tmp_path, monkeypatch):
    """Only explicit original pins participate even when unrelated manifests alias their bytes."""

    from fuzzy1337 import report_commands

    fixture = Fixture.Create(tmp_path / "workspace")
    records = fixture.Phase("confirmed")
    status, original = Run(Selected(fixture, records))
    assert status == 0, "Independent original path source did not produce a baseline"
    store = LocalEvidenceStore(fixture.root / "evidence")
    support = fixture.records["source-portal"]
    unrelated = store.Put(store.Read(support.reference), "unrelated-role", "text/plain",
        replace(support.provenance, workspace_id="foreign", scope_reference="scope:foreign"))
    manifest = fixture.root / "evidence/records" / (unrelated.evidence_id[7:] + ".json")
    manifest.write_bytes(b"unread malformed unrelated manifest")

    def Refuse(*args, **kwargs):
        """Expose unrelated generic model/evidence discovery while replaying explicit pins."""

        raise AssertionError("Path consumer attempted generic report source discovery")

    monkeypatch.setattr(report_commands, "OpenReportInput", Refuse)
    before = Files(fixture.root)
    status, replayed = Run(Selected(fixture, records))
    assert status == 0 and replayed == original and Files(fixture.root) == before, (
        "Unselected same-blob alias supplied authority, caused reads or changed original facts"
    )
