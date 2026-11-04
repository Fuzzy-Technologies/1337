# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Original CycloneDX custody, alias isolation, quotas and read-only portable policy evaluation."""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
import subprocess
from copy import deepcopy
from dataclasses import replace

import pytest

from fuzzy1337 import cyclonedx_license_policy as projection
from fuzzy1337.cyclonedx_license_policy import EvaluateVerifiedCycloneDxLicenses
from fuzzy1337.evidence import EvidenceError, EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.images import ApplyVerifiedCycloneDx, ImageIdentity, PackageIdentity
from fuzzy1337.license_policy import LicensePolicy
from fuzzy1337.model import CanonicalModelJson, LocalModelStore, ModelProvenance
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

IMAGE = "sha256:" + "a" * 64


def Component(alias="source-one", licenses=None):
    """Describe one exact source occurrence; aliases can independently share its canonical PURL."""

    value = {"type": "library", "bom-ref": alias, "name": "Owned_Lib", "version": "1.0",
             "purl": "pkg:pypi/owned-lib@1.0"}

    if licenses is not None:
        value["licenses"] = licenses

    return value


def Payload(components=None):
    """Build a handwritten supported container document with ignored root-license bait."""

    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "container", "name": "owned",
            "hashes": [{"alg": "SHA-256", "content": IMAGE[7:]}],
            "licenses": [{"expression": "IGNORED-ROOT-LICENSE"}]}},
        "components": [Component(licenses=[{"expression": "MIT"}])]
                      if components is None else components}


def Owned(tmp_path, payload=None):
    """Retain original independent SBOM evidence under real existing model/workspace owners."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned CycloneDX policy"), "owned")
    state = LocalModelStore(root).Create()
    source = EvidenceProvenance("owned", "scope:owned", "inventory.cyclonedx", "1", None,
                               "2026-10-13T00:00:00Z", "2026-10-13T00:00:01Z")
    selected = tmp_path / "selected.json"
    raw = CanonicalModelJson(Payload() if payload is None else payload)
    selected.write_bytes(raw)
    record = LocalEvidenceStore(root / "evidence").Put(raw, "sbom", "application/json", source)
    provenance = ModelProvenance(source.source_id, "run:owned", source.finished_at,
        source.scope_reference, "target:owned", evidence_references=(record.reference,))

    return root, state, record, provenance, selected


def Policy():
    """Select synthetic caller preferences without any implicit project or legal policy."""

    return LicensePolicy("owned-review", ("MIT",), ("Apache-2.0",))


def Evaluate(context, *, image=None, policy=None):
    """Enter the actual read-only SDK boundary with exact original manifests and attribution."""

    root, state, record, provenance, _ = context

    return EvaluateVerifiedCycloneDxLicenses(
        state, record, provenance, ImageIdentity(IMAGE) if image is None else image, root,
        Policy() if policy is None else policy,
    )


def Files(root):
    """Snapshot original owning bytes to detect every attempted persistence change."""

    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*") if path.is_file()}


def Refuse(*args, **kwargs):
    """Trip on any process, network or saved-owner write from this read-only projection."""

    raise AssertionError("Read-only CycloneDX projection attempted an unauthorized side effect.")


@pytest.fixture(name="owned_context")
def OwnedContext(tmp_path):
    """Prepare independently retained original source bytes for each SDK integration case."""

    return Owned(tmp_path)


def test_OriginalChoicesAndAliasesRemainIndependentWithoutInventedRoles(tmp_path, monkeypatch):
    """Allow/deny expressions and aliases sharing a PURL remain separate original source facts."""

    payload = Payload([
        Component("source-one", [{"expression": "MIT OR Apache-2.0"},
                                 {"license": {"id": "Apache-2.0"}},
                                 {"expression": "MIT"}, {"expression": "MIT"}]),
        Component("source-two", [{"license": {"id": "MIT OR Apache-2.0"}}]),
        Component("source-three", []), Component("source-four"),
        Component("source-five", [{"expression": "MIT", "acknowledgement": "concluded"}]),
    ])
    context = Owned(tmp_path, payload)
    root, state, record, provenance, _ = context
    before = Files(root)
    monkeypatch.setattr(LocalModelStore, "Save", Refuse)
    monkeypatch.setattr(LocalEvidenceStore, "Put", Refuse)
    monkeypatch.setattr(LocalWorkspaceStore, "Save", Refuse)
    monkeypatch.setattr(socket, "socket", Refuse)
    monkeypatch.setattr(subprocess, "Popen", Refuse)
    result = Evaluate(context)
    assert result["policy"] == Policy().Description() and result[
        "evidence_id"
    ] == record.evidence_id, (
        "Projection lost exact caller policy digest or original acquisition-manifest identity."
    )
    assert result["source_sha256"] == record.reference.sha256 == hashlib.sha256(
        CanonicalModelJson(payload),
    ).hexdigest() and result["provenance"] == json.loads(CanonicalModelJson(provenance)), (
        "Source digest or complete source/scope/time/run attribution changed."
    )
    components = result["components"]
    assert [item["source_bom_ref"] for item in components] == [
        "source-one", "source-two", "source-three", "source-four", "source-five",
    ] and [item["component_index"] for item in components] == list(range(5)), (
        "Original component aliases or stable source-order coordinates were collapsed."
    )
    package = PackageIdentity.FromPurl("pkg:pypi/owned-lib@1.0").Object("owned").Reference()
    assert all(item["package_reference"] == package for item in components), (
        "Repeated source aliases did not share the unchanged canonical package identity."
    )
    assertions = components[0]["assertions"]
    assert [item["evaluation"]["status"] for item in assertions] == [
        "allow", "deny", "allow", "allow",
    ] and [item["license_index"] for item in assertions] == [0, 1, 2, 3], (
        "Sibling or duplicate license entries were aggregated, deduplicated or reordered."
    )
    assert components[1]["assertions"][0]["evaluation"] == {
        "status": "unknown", "reason": "unsupported-license-identifier", "atoms": [],
    }, "A compound license.id became an allowed expression."
    assert components[2]["assertions"][0]["information_state"] == "empty" and components[3][
        "assertions"
    ][0]["information_state"] == "omitted", "Omitted and empty information states were conflated."
    assert components[4]["assertions"][0]["evaluation"] == {
        "status": "unknown", "reason": "unsupported-license-choice", "atoms": [],
    }, "An ignored source field became an approved source role or policy assertion."
    serialized = CanonicalModelJson(result)
    assert b"IGNORED-ROOT-LICENSE" not in serialized and b"compliance" not in serialized, (
        "Ignored root declarations supplied package truth or a compliance verdict appeared."
    )
    assert all(item["source_role"] == "not-classified" for component in components
               for item in component["assertions"]), "A source occurrence gained an invented role."
    assert Files(root) == before and LocalModelStore(root).Open() == state, (
        "Read-only policy evaluation changed original evidence or saved model/workspace bytes."
    )


@pytest.mark.parametrize("field", ["state", "record", "provenance", "image_identity", "policy"])
def test_ExactTypedInputRefusalPrecedesSourceReads(owned_context, monkeypatch, field):
    """Each direct input type refuses implicit substitutions before evidence reads."""

    root, state, record, provenance, _ = owned_context
    arguments = {"state": state, "record": record, "provenance": provenance,
                 "image_identity": ImageIdentity(IMAGE), "policy": Policy(), "workspace_root": root}
    arguments[field] = {"implicit": "untrusted"}
    monkeypatch.setattr(projection, "VerifyRecords", Refuse)

    with pytest.raises(ValueError, match="invalid-cyclonedx-license-policy-input"):
        EvaluateVerifiedCycloneDxLicenses(**arguments)


@pytest.mark.parametrize("case", ["version", "root", "duplicate-alias", "package", "nested",
                                  "name-only", "both-choice", "null-licenses", "empty-text"])
def test_UnchangedCompleteOwnerRejectsMalformedOrUnsupportedInventory(tmp_path, case):
    """Original bytes cannot be sanitized to hide inventory or source-choice admission errors."""

    payload = Payload()
    component = payload["components"][0]

    if case == "version":
        payload["specVersion"] = "1.5"

    elif case == "root":
        payload["metadata"]["component"]["hashes"][0]["content"] = "b" * 64

    elif case == "duplicate-alias":
        payload["components"].append(deepcopy(component))

    elif case == "package":
        component["version"] = "2.0"

    elif case == "nested":
        component["components"] = [Component("nested")]

    else:
        component["licenses"] = {
            "name-only": [{"license": {"name": "Owned license"}}],
            "both-choice": [{"license": {"id": "MIT"}, "expression": "MIT"}],
            "null-licenses": None, "empty-text": [{"expression": ""}],
        }[case]

    context = Owned(tmp_path, payload)
    root, state, record, provenance, _ = context
    before = Files(root)

    with pytest.raises(ValueError):
        ApplyVerifiedCycloneDx(state, record, provenance, ImageIdentity(IMAGE), root)

    with pytest.raises(ValueError):
        Evaluate(context)

    assert Files(root) == before, "Whole-operation source refusal modified retained owners."


@pytest.mark.parametrize("field,value", [("source_id", "inventory.other"),
    ("scope_reference", "scope:other"), ("provider_version", "other"),
    ("observed_at", "2026-10-13T00:00:02Z"), ("evidence_references", ())])
def test_ExistingProvenanceOwnerRejectsSourceScopeVersionTimeAndManifestSubstitution(
    owned_context, field, value,
):
    """Source attribution cannot be replaced while borrowing the original acquisition manifest."""

    root, state, record, provenance, _ = owned_context
    altered = replace(provenance, **{field: value})
    before = Files(root)

    with pytest.raises(ValueError):
        EvaluateVerifiedCycloneDxLicenses(state, record, altered, ImageIdentity(IMAGE), root,
                                         Policy())

    assert Files(root) == before, "Provenance refusal rewrote saved owner state."


def test_ConfigManifestDomainsStayExplicitAndDoNotBorrowSavedAliases(owned_context):
    """Equal root bytes keep distinct explicitly selected config and manifest identities."""

    config = Evaluate(owned_context)
    manifest = Evaluate(owned_context, image=ImageIdentity(IMAGE, "manifest"))
    assert config["image_reference"] != manifest["image_reference"] and config[
        "image_digest_kind"
    ] == "config" and manifest["image_digest_kind"] == "manifest", (
        "Equal hash bytes collapsed explicitly selected config and manifest digest domains."
    )
    assert config["components"] == manifest["components"], (
        "Explicit source interpretation changed independent component coordinates."
    )


def test_CorruptionAndForeignAcquisitionManifestCannotSupplyPolicyTruth(owned_context):
    """A normalized/cached license cannot replace exact original-byte and acquisition integrity."""

    root, state, record, provenance, _ = owned_context
    altered = replace(record, provenance=replace(record.provenance, source_version="2"))

    with pytest.raises(EvidenceError):
        EvaluateVerifiedCycloneDxLicenses(state, altered, provenance, ImageIdentity(IMAGE), root,
                                         Policy())

    blob = root / "evidence" / record.reference.locator
    blob.write_bytes(b"x" * record.reference.size_bytes)
    before = Files(root)

    with pytest.raises(EvidenceError):
        Evaluate(owned_context)

    assert Files(root) == before, "Corrupt-source refusal repaired or rewrote original evidence."


def test_OriginalSourceReopensAfterRelocationAndSelectedInputDeletion(owned_context, tmp_path):
    """Portable replay uses retained original bytes without the initial input path or writes."""

    root, state, record, provenance, selected = owned_context
    original = Evaluate(owned_context)
    selected.unlink()
    moved = tmp_path / "relocated"
    shutil.move(root, moved)
    before = Files(moved)
    reopened = LocalModelStore(moved).Open()
    result = EvaluateVerifiedCycloneDxLicenses(reopened, record, provenance, ImageIdentity(IMAGE),
                                             moved, Policy())
    assert result == original and reopened == state and Files(moved) == before, (
        "Relocated evaluation required the deleted input or changed source/owner bytes."
    )


def test_GlobalOccurrenceBudgetRefuses4097RowsAcrossIndividuallyValidArrays(tmp_path):
    """Every source occurrence counts globally, including duplicate atoms and empty components."""

    payload = Payload([Component("first", [{"expression": "MIT"}] * 4096),
                       Component("second", [])])
    context = Owned(tmp_path, payload)
    root, state, record, provenance, _ = context
    ApplyVerifiedCycloneDx(state, record, provenance, ImageIdentity(IMAGE), root)
    before = Files(root)

    with pytest.raises(ValueError, match="cyclonedx-license-policy-limit"):
        Evaluate(context)

    assert Files(root) == before, "Global quota refusal wrote partial projection or model state."


def test_WholeCanonicalOutputBudgetRefusesValidRepeatedLongSourceOccurrences(tmp_path):
    """Actual one-MiB output expansion refuses the whole operation without a shortened result."""

    expression = "X" * 2048
    payload = Payload([Component("source", [{"expression": expression}] * 600)])
    context = Owned(tmp_path, payload)
    root, state, record, provenance, _ = context
    ApplyVerifiedCycloneDx(state, record, provenance, ImageIdentity(IMAGE), root)
    before = Files(root)

    with pytest.raises(ValueError, match="cyclonedx-license-policy-limit"):
        Evaluate(context)

    assert Files(root) == before, "Output quota refusal leaked a partial result into saved owners."


def test_EmptyComponentInventoryDoesNotBorrowIgnoredRootLicenses(tmp_path):
    """Empty package inventory produces no source assertions or synthetic license verdict."""

    result = Evaluate(Owned(tmp_path, Payload([])))
    assert result["components"] == [] and "status" not in result, (
        "Empty inventory became a package assertion or overall policy/compliance status."
    )


def test_AnotherOriginalImageAndAcquisitionCannotSupplySharedPackageLicenseFacts(
    owned_context,
):
    """Saved package/license deduplication cannot replace selected original source occurrences."""

    root, state, selectedRecord, selectedProvenance, _ = owned_context
    otherPayload = Payload([Component("other-alias", [{"expression": "Apache-2.0"}])])
    otherPayload["metadata"]["component"]["hashes"][0]["content"] = "b" * 64
    otherSource = replace(selectedRecord.provenance, source_id="inventory.other")
    otherRecord = LocalEvidenceStore(root / "evidence").Put(
        CanonicalModelJson(otherPayload), "sbom", "application/json", otherSource,
    )
    otherProvenance = replace(selectedProvenance, source_id=otherSource.source_id,
                               evidence_references=(otherRecord.reference,))
    state, _ = ApplyVerifiedCycloneDx(state, otherRecord, otherProvenance,
                                     ImageIdentity("sha256:" + "b" * 64), root)
    LocalModelStore(root).Save(state, expected_revision=0)
    before = Files(root)
    selected = EvaluateVerifiedCycloneDxLicenses(state, selectedRecord, selectedProvenance,
                                               ImageIdentity(IMAGE), root, Policy())
    assert len(selected["components"]) == 1 and selected["components"][0]["source_bom_ref"] == (
        "source-one"
    ) and selected["components"][0]["assertions"][0]["evaluation"]["status"] == "allow", (
        "Another image's shared package license replaced the selected original source assertion."
    )
    assert selected["evidence_id"] == selectedRecord.evidence_id and "other-alias" not in (
        CanonicalModelJson(selected).decode("utf-8")
    ), "A different original acquisition supplied the selected policy result or source alias."
    assert Files(root) == before, "Cross-source projection modified saved original owners."


def test_ActualForeignOwningWorkspaceRejectsCopiedOriginalEvidence(owned_context, tmp_path):
    """Copied immutable evidence cannot transfer its original owning workspace identity."""

    root, _, record, provenance, _ = owned_context
    foreign = tmp_path / "foreign"
    LocalWorkspaceStore(foreign).Create(WorkspaceConfiguration("Foreign fixture"), "foreign")
    state = LocalModelStore(foreign).Create()
    shutil.copytree(root / "evidence", foreign / "evidence", dirs_exist_ok=True)
    before = Files(foreign)

    with pytest.raises(ValueError, match="workspace/scope/source/version"):
        EvaluateVerifiedCycloneDxLicenses(state, record, provenance, ImageIdentity(IMAGE), foreign,
                                         Policy())

    assert Files(foreign) == before, "Foreign ownership refusal rewrote copied source custody."


def test_Exact4096OccurrenceBudgetKeepsEveryOriginalIndex(tmp_path):
    """The maximum supported count returns complete duplicate occurrences rather than truncating."""

    result = Evaluate(Owned(tmp_path, Payload([
        Component("source", [{"expression": "MIT"}] * 4096),
    ])))
    assertions = result["components"][0]["assertions"]
    assert len(assertions) == 4096 and assertions[0]["license_index"] == 0 and assertions[-1][
        "license_index"
    ] == 4095, "The exact supported occurrence limit was rejected or silently shortened."
