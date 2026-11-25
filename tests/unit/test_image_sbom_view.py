# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exact identity selection and bounded read-only failure paths for image inventory views."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

import fuzzy1337.image_sbom_view as views
from fuzzy1337.evidence import EvidenceProvenance
from fuzzy1337.images import ApplyVerifiedCycloneDx, PackageIdentity
from fuzzy1337.model import (
    CanonicalModelJson,
    LocalModelStore,
    ModelProvenance,
    Relation,
    RelationKind,
)
from fuzzy1337.report_commands import ReportFailure
from fuzzy1337.sbom_spdx import ApplyVerifiedSpdx
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.sbom_helpers import FIXTURES, IMAGE_DIGEST, Arguments, Context, Run, ViewArguments
from tests.unit.test_images import SBOM


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


def test_TextImageViewRefusesAnOverLimitSummaryBeforeWriting(tmp_path, monkeypatch):
    """Measure the complete text result before printing any verified snapshot identity."""

    owned = Context(tmp_path)
    assert Run(Arguments(owned))[0] == 0, "Owned source must be saved before inspection"
    arguments = ViewArguments(owned)
    status, original = Run(arguments)
    assert status == 0, "The saved view must fit the normal output bound"
    monkeypatch.setattr(views, "MAX_IMAGE_SBOM_VIEW_BYTES", len(CanonicalModelJson(original)))
    assert Run(arguments) == (0, original), "The JSON result must still fit its existing bound"
    assert Run(arguments, json_output=False) == (4, "sbom.image: failed\nfailure: limit\n"), (
        "The longer text result must refuse atomically without exposing the digest or inventory"
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


def test_SharedPackageDoesNotBorrowNestedContainmentFromAnotherImage(tmp_path):
    """Keep nested SPDX membership scoped to the image whose source declared it."""

    owned = Context(tmp_path)
    document = json.loads((FIXTURES / "spdx.graph.v2.3.json").read_bytes())
    originalPackages = document["packages"]
    originalRelationships = document["relationships"]
    document["packages"] = [originalPackages[index] for index in (0, 3)]
    document["relationships"] = [originalRelationships[index] for index in (0, 3)]
    owned.source.write_text(json.dumps(document), encoding="utf-8")
    assert Run(Arguments(owned, digest_kind="config"))[0] == 0, (
        "The independently retained config graph must import before correlation"
    )

    document["packages"] = [originalPackages[index] for index in (0, 3, 4)]
    document["relationships"] = [originalRelationships[index] for index in (0, 3, 5)]
    owned.source.write_text(json.dumps(document), encoding="utf-8")
    assert Run(Arguments(owned, digest_kind="manifest"))[0] == 0, (
        "The manifest source must retain its own direct and nested relationships"
    )
    model = LocalModelStore(owned.root).Open()
    config = views.ImageSbomView(model, views.ImageIdentity(IMAGE_DIGEST))
    manifest = views.ImageSbomView(model, views.ImageIdentity(IMAGE_DIGEST, "manifest"))
    aliases = {(item.attributes["image_reference"], item.attributes["spdx_id"]):
               item.subject_reference for item in model.observations
               if item.kind == "spdx-source-alias"}
    expectedConfig = {aliases[(config["image_reference"], "SPDXRef-Lib-Alias")]}
    expectedManifest = {aliases[(manifest["image_reference"], identifier)]
                        for identifier in ("SPDXRef-Lib-Alias", "SPDXRef-Helper")}
    claims: dict[str, set[str]] = {}

    for item in model.observations:
        if item.kind == "spdx-relationship-claim" and (
            item.attributes["relationship_type"] == "CONTAINS"
        ):
            claims.setdefault(item.attributes["image_reference"], set()).add(
                item.subject_reference)

    assert set(config["package_references"]) == expectedConfig and set(
        config["containment_relation_references"]
    ) == claims[config["image_reference"]], (
        "The config source cannot borrow the manifest-only nested package claim."
    )
    assert set(manifest["package_references"]) == expectedManifest and set(
        manifest["containment_relation_references"]
    ) == claims[manifest["image_reference"]], (
        "The manifest source must retain its direct and nested package claims."
    )


@pytest.mark.parametrize("attribution", ["foreign", "selected", "both", "other-run"])
def test_UnclaimedContainmentRequiresTheSelectedImageSourceContext(tmp_path, attribution):
    """Canonical nested edges retain their own image attribution without needing SPDX claims."""

    owned = Context(tmp_path)
    document = json.loads(owned.source.read_bytes())
    packages, relationships = document["packages"], document["relationships"]
    document["packages"] = [packages[index] for index in (0, 3)]
    document["relationships"] = [relationships[index] for index in (0, 3)]
    owned.source.write_text(json.dumps(document), encoding="utf-8")
    assert Run(Arguments(owned))[0] == 0, "The config source must contain only its own library"
    owned.source.write_bytes((FIXTURES / "spdx.graph.v2.3.json").read_bytes())
    assert Run(Arguments(owned, digest_kind="manifest"))[0] == 0, (
        "The foreign source must establish real image and package provenance"
    )
    model = LocalModelStore(owned.root).Open()
    images = {item.attributes["digest_kind"]: item for item in model.objects
              if item.attributes.get("asset_type") == "image"}
    aliases = {item.attributes["spdx_id"]: item.subject_reference for item in model.observations
               if item.kind == "spdx-source-alias"}
    provenance = images["manifest"].provenance

    if attribution == "selected":
        provenance = images["config"].provenance

    elif attribution == "both":
        provenance = (*provenance, *images["config"].provenance)

    elif attribution == "other-run":
        provenance = (replace(images["config"].provenance[0], run_reference="run:other"),)

    edge = Relation(RelationKind.CONTAINS, aliases["SPDXRef-Lib-Alias"],
                    aliases["SPDXRef-App"], provenance=provenance)
    proposed, _ = model.Apply(relations=(edge,))
    result = views.ImageSbomView(proposed, views.ImageIdentity(IMAGE_DIGEST))
    expected = {aliases["SPDXRef-Lib-Alias"]}

    if attribution in ("selected", "both"):
        expected.add(aliases["SPDXRef-App"])

    assert set(result["package_references"]) == expected and (
        edge.Reference() in result["containment_relation_references"]
    ) == (attribution in ("selected", "both")), (
        "An unclaimed edge requires exact selected-image provenance, beyond a shared package"
    )


@pytest.mark.parametrize("selectedClaim", ["absent", "missing-image", "non-string", "foreign"])
def test_ForeignSpdxClaimCannotOverrideIndependentSelectedContainment(
    tmp_path, selectedClaim,
):
    """Scope SPDX restrictions to their original attribution and reject invalid scoped claims."""

    owned = Context(tmp_path)
    document = json.loads(owned.source.read_bytes())
    packages, relationships = document["packages"], document["relationships"]
    document["packages"] = [packages[index] for index in (0, 3)]
    document["relationships"] = [relationships[index] for index in (0, 3)]
    owned.source.write_text(json.dumps(document), encoding="utf-8")
    assert Run(Arguments(owned))[0] == 0, "The selected source must retain its direct package"
    owned.source.write_bytes((FIXTURES / "spdx.graph.v2.3.json").read_bytes())
    assert Run(Arguments(owned, digest_kind="manifest"))[0] == 0, (
        "The foreign SPDX source must independently retain the nested edge"
    )
    model = LocalModelStore(owned.root).Open()
    images = {item.attributes["digest_kind"]: item for item in model.objects
              if item.attributes.get("asset_type") == "image"}
    aliases = {item.attributes["spdx_id"]: item.subject_reference for item in model.observations
               if item.kind == "spdx-source-alias"}
    edge = next(item for item in model.relations if item.kind is RelationKind.CONTAINS
                and item.source_reference == aliases["SPDXRef-Lib-Alias"]
                and item.target_reference == aliases["SPDXRef-Helper"])
    attributed = replace(edge, provenance=(*edge.provenance, *images["config"].provenance))
    observations = ()

    if selectedClaim != "absent":
        foreign = next(item for item in model.observations
                       if item.kind == "spdx-relationship-claim"
                       and item.subject_reference == edge.Reference())
        attributes = dict(foreign.attributes)

        if selectedClaim == "missing-image":
            del attributes["image_reference"]

        elif selectedClaim == "non-string":
            attributes["image_reference"] = 1

        observations = (replace(foreign, attributes=attributes,
                                provenance=images["config"].provenance[0]),)

    proposed, _ = model.Apply(relations=(attributed,), observations=observations)
    result = views.ImageSbomView(proposed, views.ImageIdentity(IMAGE_DIGEST))
    expected = {aliases["SPDXRef-Lib-Alias"]}

    if selectedClaim == "absent":
        expected.add(aliases["SPDXRef-Helper"])

    assert set(result["package_references"]) == expected and (
        edge.Reference() in result["containment_relation_references"]
    ) == (selectedClaim == "absent"), (
        "Foreign claims cannot suppress a separate selected context, and invalid local claims "
        "cannot authorize that context"
    )


@pytest.mark.parametrize("profile", ["cyclonedx", "flat-spdx"])
@pytest.mark.parametrize("kind", ["config", "manifest"])
def test_OriginalFlatInventoriesRetainDirectUnclaimedContainment(tmp_path, profile, kind):
    """Existing verified flat import owners do not need graph-specific relationship observations."""

    owned = Context(tmp_path)
    basis = LocalModelStore(owned.root).Open()
    evidence = views.SbomEvidenceStore(owned.root / "evidence")
    raw = CanonicalModelJson(SBOM) if profile == "cyclonedx" else (
        FIXTURES / "spdx.image.v2.3.json").read_bytes()
    source = EvidenceProvenance(basis.workspace_id, "scope:owned", "inventory.owned-sbom", "1",
                               None, "2026-10-13T00:00:00Z", "2026-10-13T00:00:01Z")
    record = evidence.Put(raw, "sbom", "application/json", source)
    provenance = ModelProvenance(source.source_id, "run:flat", source.finished_at,
        source.scope_reference, "target:owned", evidence_references=(record.reference,))
    image = views.ImageIdentity(IMAGE_DIGEST, kind)
    importer = ApplyVerifiedCycloneDx if profile == "cyclonedx" else ApplyVerifiedSpdx
    model, _ = importer(basis, record, provenance, image, owned.root)
    package = PackageIdentity.FromPurl("pkg:pypi/owned-lib@1.0").Object(basis.workspace_id)
    result = views.ImageSbomView(model, image)
    expected = Relation(RelationKind.CONTAINS, image.Object(basis.workspace_id).Reference(),
                        package.Reference(), provenance=(provenance,))
    assert not any(item.kind == "spdx-relationship-claim" for item in model.observations), (
        "This compatibility case must exercise actual flat owners without graph-specific claims"
    )
    assert result["package_references"] == [package.Reference()] and (
        result["containment_relation_references"] == [expected.Reference()]
    ), "Both original flat profiles must retain their exact package and original direct relation"


def test_ViewDoesNotWriteSavedOwnersAndEmptyInventoryRemainsUnknown(tmp_path):
    """An observed image without supplied package facts never becomes a clean inventory verdict."""

    owned = Context(tmp_path)
    assert Run(Arguments(owned))[0] == 0, "Owned original graph import must first succeed"
    modelStore = LocalModelStore(owned.root)
    original = modelStore.Open()
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
    assert modelStore.Open() == original and (
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
    oldFields = {key: value for key, value in one.attributes.items() if key != "evidence_id"}
    older = replace(one, attributes=oldFields)
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
