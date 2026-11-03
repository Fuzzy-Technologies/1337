# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exact identity selection and bounded read-only failure paths for image inventory views."""

from __future__ import annotations

from dataclasses import replace

import pytest

import fuzzy1337.image_sbom_view as views
from fuzzy1337.model import LocalModelStore, Relation, RelationKind
from fuzzy1337.report_commands import ReportFailure
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.sbom_helpers import IMAGE_DIGEST, Arguments, Context, Run, ViewArguments


def PolicyArguments(owned):
    """Select explicit synthetic caller preferences on the unchanged actual image view."""

    return ViewArguments(owned) + ["--license-policy", "owned-v1", "--allow-license", "MIT",
                                  "--deny-license", "Apache-2.0"]


@pytest.mark.parametrize("mode", ["missing-kind", "tag", "extra-source", "missing-image"])
def test_ExplicitImageViewRefusesInvalidSelectionsWithoutReflectingInputs(tmp_path, mode):
    """No tag, implicit digest kind or write option can select an image view."""

    owned = Context(tmp_path)
    arguments = ViewArguments(owned)

    if mode == "missing-kind":
        arguments = arguments[:-2]

    elif mode == "tag":
        arguments[arguments.index("--image-digest") + 1] = "PRIVATE_MARKER:latest"

    elif mode == "extra-source":
        arguments.extend(["--file", "PRIVATE_MARKER"])

    status, outcome = Run(arguments)
    assert status == (4 if mode == "missing-image" else 2), (
        "The read-only view must require explicit valid image semantics and an existing identity"
    )
    assert outcome["status"] == "failed" and "PRIVATE_MARKER" not in str(outcome), (
        "Refused image selection must use fixed diagnostics without reflecting rejected values"
    )

@pytest.mark.parametrize("mode", ["before-verification", "after-projection"])
def test_ChangedSavedModelCannotReturnAViewOfAnUnverifiedBasis(tmp_path, monkeypatch, mode):
    """A concurrent model update before or after verification refuses the whole projection."""

    owned = Context(tmp_path)
    assert Run(Arguments(owned))[0] == 0, "Owned input must first create real image inventory"
    original = views.OpenReportInput if mode == "before-verification" else views.ImageSbomView

    def Changed(*args):
        """Advance the actual canonical owner while the query is between its snapshot checks."""

        state = LocalModelStore(owned.root).Open()
        LocalModelStore(owned.root).Save(replace(state, revision=state.revision + 1),
                                         expected_revision=state.revision)

        return original(*args)

    name = "OpenReportInput" if mode == "before-verification" else "ImageSbomView"
    monkeypatch.setattr(views, name, Changed)
    status, outcome = Run(ViewArguments(owned))
    assert status == 4 and outcome["failure"] == "basis-changed" and (
        "package_references" not in outcome
    ), "Changed canonical snapshots must fail without returning partially verified inventory"

@pytest.mark.parametrize("mode", ["report-limit", "output-limit", "interrupt",
                                  "storage", "internal"])
def test_VerificationAndOutputFailuresStayNonzeroAndSafe(tmp_path, monkeypatch, mode):
    """Existing report quotas, interruption and unknown failures retain truthful terminal status."""

    owned = Context(tmp_path)
    assert Run(Arguments(owned))[0] == 0, "Owned original acquisition must first succeed"

    def Refuse(*_args):
        """Simulate one actual consumer boundary failure without sensitive terminal values."""

        error = {"report-limit": ReportFailure("limit"), "interrupt": KeyboardInterrupt(),
                 "storage": OSError("PRIVATE_MARKER"), "internal": RuntimeError("PRIVATE_MARKER")}

        raise error[mode]

    if mode == "output-limit":
        monkeypatch.setattr(views, "MAX_IMAGE_SBOM_VIEW_BYTES", 1)

    else:
        monkeypatch.setattr(views, "OpenReportInput", Refuse)

    status, outcome = Run(ViewArguments(owned), json_output=mode != "storage")
    assert status == (130 if mode == "interrupt" else 4), "Refused views cannot exit successfully"
    assert "PRIVATE_MARKER" not in str(outcome) and "failed" in str(outcome), (
        "Consumer failures must have safe diagnostics and never leave a success acknowledgement"
    )


def test_ContradictoryIdentityAndContainmentCycleNeverInventAnotherImageInventory(tmp_path):
    """Only package containment is traversed, once per node, even in an arbitrary saved cycle."""

    owned = Context(tmp_path)
    assert Run(Arguments(owned))[0] == 0, "Owned source graph must first import"
    model = LocalModelStore(owned.root).Open()
    image = views.ImageIdentity(IMAGE_DIGEST)
    entity = next(item for item in model.objects if item.Reference() == image.Object(
        model.workspace_id).Reference())
    contradictory, _ = model.Apply(objects=(replace(entity, attributes={
        **entity.attributes, "digest_kind": "manifest"}),))

    with pytest.raises(views.SbomFailure, match="image-identity"):
        views.ImageSbomView(contradictory, image)

    packages = [item for item in model.objects if item.attributes.get("asset_type") == "package"]
    cycle = Relation(RelationKind.CONTAINS, packages[-1].Reference(), packages[0].Reference(),
                     provenance=entity.provenance)
    unrelated = Relation(RelationKind.CONTAINS, entity.Reference(), entity.Reference(),
                         provenance=entity.provenance)
    cyclic, _ = model.Apply(relations=(cycle, unrelated))
    result = views.ImageSbomView(cyclic, image)
    assert len(result["package_references"]) == 3 and cycle.Reference() in (
        result["containment_relation_references"]
    ) and unrelated.Reference() not in result["containment_relation_references"], (
        "Traversal must be finite and report original package edges without borrowing image nodes"
    )


def test_ViewDoesNotWriteSavedOwnersAndEmptyInventoryRemainsUnknown(tmp_path):
    """An observed image without supplied package facts never becomes a clean inventory verdict."""

    owned = Context(tmp_path)
    assert Run(Arguments(owned))[0] == 0, "Owned original graph import must first succeed"
    model_store = LocalModelStore(owned.root)
    original = model_store.Open()
    # Remove relation-subject observations while preserving real image/package attribution.
    objects = {item.Reference() for item in original.objects}
    empty = replace(original, relations=(), observations=tuple(
        item for item in original.observations if item.subject_reference in objects))
    result = views.ImageSbomView(empty, views.ImageIdentity(IMAGE_DIGEST))
    assert result["inventory_status"] == "unknown" and not result["package_references"], (
        "Absent package containment must remain unknown rather than imply complete empty inventory"
    )
    before = {path.relative_to(owned.root): path.read_bytes()
              for path in owned.root.rglob("*") if path.is_file()}
    status, text = Run(ViewArguments(owned), json_output=False)
    after = {path.relative_to(owned.root): path.read_bytes()
             for path in owned.root.rglob("*") if path.is_file()}
    assert status == 0 and "sbom.image: succeeded" in text and before == after, (
        "A successful human-readable image query must leave every saved owner byte unchanged"
    )
    assert model_store.Open() == original and (
        LocalWorkspaceStore(owned.root).Open().revision == 1
    ), (
        "Read-only projection cannot create a canonical model or workspace transition"
    )


def test_OversizedKnownOriginalRefusesBeforeGenericEvidenceVerification(tmp_path, monkeypatch):
    """Saved original SBOM size guards remain active in the read-only consumer path."""

    owned = Context(tmp_path)
    status, outcome = Run(Arguments(owned))
    assert status == 0, "Original acquisition must first establish actual known product custody"
    evidence = views.SbomEvidenceStore(owned.root / "evidence")
    record = evidence.Manifest(outcome["evidence_id"])
    blob = evidence.StoragePath(("blobs", "sha256", record.reference.sha256))

    with blob.open("ab") as stream:
        stream.truncate(4 * 1024 * 1024 + 1)

    def Forbidden(*_args):
        """Trip an attempted generic report read after the original source preflight must fail."""

        raise AssertionError("Known oversized original reached the generic report evidence reader")

    monkeypatch.setattr(views, "OpenReportInput", Forbidden)
    status, outcome = Run(ViewArguments(owned))
    assert status == 4 and outcome["failure"] == "selected-source", (
        "Saved-source view must retain original SBOM ceilings before any generic owning byte read"
    )


@pytest.mark.parametrize("extra", [
    ["--allow-license", "MIT"], ["--deny-license", "MIT"],
    ["--license-policy", "owned"],
    ["--license-policy", "owned", "--allow-license", "MIT", "--deny-license", "mit"],
    ["--license-policy", "PRIVATE MARKER", "--allow-license", "MIT"],
    ["--license-policy", "owned", "--allow-license", "PRIVATE MARKER"],
])
def test_ExplicitPolicyConfigurationIsValidatedBeforeReadingSavedOwners(tmp_path, extra):
    """Missing, ambiguous or unsupported policy declarations never start a source projection."""

    owned = Context(tmp_path)
    status, outcome = Run(ViewArguments(owned) + extra)
    assert status == 2 and outcome["failure"] == "configuration" and (
        "PRIVATE" not in str(outcome)
    ), "Policy configuration must fail safely before source and image lookup"


@pytest.mark.parametrize("mode", ["expression", "source-sha", "source-spdx", "source-id",
                                  "unknown-manifest", "manifest-type", "missing-alias"])
def test_PolicyProjectionRequiresExactOriginalSourceInterpretation(tmp_path, mode):
    """Saved assertions cannot borrow another source/alias or replace original expressions."""

    owned = Context(tmp_path)
    assert Run(Arguments(owned))[0] == 0, "Actual original SPDX import must first succeed"
    store = LocalModelStore(owned.root)
    model = store.Open()
    assertion = next(item for item in model.observations if item.kind == "spdx-package-license"
        and item.attributes["declared"].get("expression") == "MIT")
    fields = dict(assertion.attributes)

    if mode == "expression":
        fields["declared"] = {"state": "expression", "expression": "Apache-2.0"}

    elif mode == "source-sha":
        fields["document_sha256"] = "b" * 64

    elif mode == "source-spdx":
        fields["spdx_id"] = "SPDXRef-Helper"

    elif mode == "source-id":
        assertion = replace(assertion, provenance=replace(assertion.provenance,
                                                         source_id="inventory.other"))

    elif mode == "unknown-manifest":
        fields["evidence_id"] = "sha256:" + "b" * 64

    elif mode == "manifest-type":
        fields["evidence_id"] = 1

    forged = replace(assertion, attributes=fields)
    observations = tuple(item for item in model.observations if not (
        item.kind == "spdx-package-license" and item.attributes.get("spdx_id") == "SPDXRef-Lib"
    ) and not (mode == "missing-alias" and item.kind == "spdx-source-alias"
               and item.attributes.get("spdx_id") == "SPDXRef-Lib")) + (forged,)
    store.Save(replace(model, observations=observations, revision=model.revision + 1),
               expected_revision=model.revision)
    status, outcome = Run(PolicyArguments(owned))
    assert status == 4 and outcome["status"] == "failed" and "license_policy" not in outcome, (
        "Exact original reparse and custody joins must refuse changed interpretations atomically"
    )


@pytest.mark.parametrize("limit", ["MAX_IMAGE_LICENSE_SOURCES", "MAX_IMAGE_LICENSE_ASSERTIONS"])
def test_PolicySourceAndAssertionQuotasWithholdEveryPartialDecision(tmp_path, monkeypatch, limit):
    """Extra interpretation work has its own finite ceilings below the unchanged output ceiling."""

    owned = Context(tmp_path)
    assert Run(Arguments(owned))[0] == 0, "Actual source import must precede read-only projection"
    monkeypatch.setattr(views, limit, 0)
    status, outcome = Run(PolicyArguments(owned))
    assert status == 4 and outcome["failure"] == "limit" and "license_policy" not in outcome, (
        "A source/assertion quota cannot return a partial policy match as a successful image view"
    )


def test_UnsupportedAndAbsentSourceProfilesRemainUnknownWithoutBorrowingLicenseAssets(tmp_path):
    """Opaque older declarations and unrelated current license assets are never silently trusted."""

    owned = Context(tmp_path)
    assert Run(Arguments(owned))[0] == 0, "Original source must first create canonical packages"
    store = LocalModelStore(owned.root)
    model = store.Open()
    packages = {item.Reference() for item in model.objects
                if item.attributes.get("asset_type") == "package"}
    one = next(item for item in model.observations if item.kind == "spdx-package-license"
               and item.subject_reference in packages)
    old_fields = {key: value for key, value in one.attributes.items() if key != "evidence_id"}
    older = replace(one, attributes=old_fields)
    observations = tuple(item for item in model.observations if item.kind != (
        "spdx-package-license"
    )) + (older,)
    store.Save(replace(model, observations=observations, revision=model.revision + 1),
               expected_revision=model.revision)
    status, outcome = Run(PolicyArguments(owned))
    assert status == 0, "An explicit unsupported/absent result is a valid read-only projection"
    rows = outcome["license_policy"]["packages"]
    actual = next(row for row in rows if row["package_reference"] == older.subject_reference)
    assert actual["assertions"] == [{"observation_reference": older.Reference(),
        "status": "unknown", "reason": "unsupported-source-profile"}], (
        "An older unsupported assertion cannot be upgraded to a trusted policy result"
    )
    assert all(row["status"] == "unknown" and row["reason"] == "no-selected-source-assertion"
        for row in rows if row is not actual), (
        "Remaining license assets or declarations from other profiles cannot fill missing facts"
    )
