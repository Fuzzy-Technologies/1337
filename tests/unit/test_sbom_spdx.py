# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent SPDX document interpretation, graph fidelity, licensing and trust-boundary tests."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from traceback import format_exception

import pytest

from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.evidence import (
    EvidenceError,
    EvidenceIntegrityError,
    EvidenceProvenance,
    LocalEvidenceStore,
)
from fuzzy1337.findings import Findings
from fuzzy1337.images import ImageIdentity, PackageIdentity
from fuzzy1337.model import CanonicalModelJson, LocalModelStore, ModelProvenance
from fuzzy1337.sbom_spdx import ApplyVerifiedSpdx
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

ROOT = Path(__file__).resolve().parents[2]
IMAGE = ImageIdentity("sha256:" + "a" * 64)
MANIFEST = ImageIdentity("sha256:" + "b" * 64, "manifest")
PACKAGE = PackageIdentity.FromPurl("pkg:pypi/owned-lib@1.0")


def Document(name="spdx.image.v2.3.json"):
    """Load an independently authored source fixture, not an importer-generated document."""

    return json.loads((ROOT / "tests/contract/fixtures" / name).read_text())


@pytest.fixture
def context(tmp_path):
    """Create real owned workspace/model/evidence state without invoking a scanner."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned SPDX fixture"), "spdx-test")

    return root, LocalModelStore(root).Create(), LocalEvidenceStore(root / "evidence")


def Acquired(context, payload, *, source_overrides=None):
    """Record independent source acquisition, preserving its bytes before interpretation."""

    _, state, store = context
    source = EvidenceProvenance(state.workspace_id, "scope:owned", "inventory.spdx", "1", None,
                               "2026-10-13T00:00:00Z", "2026-10-13T00:00:01Z")

    if source_overrides:
        source = replace(source, **source_overrides)

    raw = payload if isinstance(payload, bytes) else CanonicalModelJson(payload)
    record = store.Put(raw, "sbom", "application/json", source)
    provenance = ModelProvenance(source.source_id, "run:spdx", source.finished_at,
        source.scope_reference, "target:owned", source.tool_version, (record.reference,))

    return record, provenance


def Import(context, document=None, *, image=IMAGE):
    """Exercise only the public verified-document boundary for synthetic source fixtures."""

    root, state, _ = context
    record, provenance = Acquired(context, Document() if document is None else document)

    return ApplyVerifiedSpdx(state, record, provenance, image, root)


def test_InventoryRetainsCanonicalIdentitiesRawBytesAndSeparateLicenseRoles(context):
    """The source's concluded license does not rewrite an author's declared license."""

    root, initial, store = context
    source = Document()
    record, provenance = Acquired(context, source)
    state, delta = ApplyVerifiedSpdx(initial, record, provenance, IMAGE, root)
    assert delta.revision == initial.revision + 1, "Inventory must apply one complete transition"
    images = {item.identity.key for item in state.objects
              if item.attributes["asset_type"] == "image"}
    assert images == {
        IMAGE.Object(initial.workspace_id).key,
    }, "SPDX created a competing image identity"
    package = next(item for item in state.objects if item.attributes["asset_type"] == "package")
    assert package.identity == PACKAGE.Object(initial.workspace_id), "PURL package identity changed"
    licenses = {item.attributes["expression"] for item in state.objects
                if item.attributes["asset_type"] == "license"}
    assert licenses == {"MIT"}, "A concluded license became an author declaration"
    facts = [item.attributes for item in state.observations
             if item.kind == "spdx-package-license"
             and item.subject_reference == package.Reference()]
    assert len(facts) == 1 and facts[0]["declared"]["expression"] == "MIT", (
        "Declared license source role was lost"
    )
    assert facts[0]["concluded"]["expression"] == "Apache-2.0", "Concluded license fact was lost"
    assert not Findings(state), "Inventory or external references invented a vulnerability verdict"
    assert store.Read(record.reference) == CanonicalModelJson(source), "Raw evidence was rewritten"
    assert b"SYNTHETIC_PRIVATE_MARKER" not in CanonicalModelJson(state.ToDict()), (
        "Private source details escaped the raw evidence boundary"
    )
    replayed, replay_delta = ApplyVerifiedSpdx(state, record, provenance, IMAGE, root)
    assert replayed == state and not replay_delta.created and not replay_delta.updated, (
        "Exact verified source replay changed state"
    )


def test_InformationStatesRemainDistinctFromLicenseEntities(context):
    """Absent/no-information/no-license fields do not manufacture named licenses."""

    state, _ = Import(context, Document("spdx.license-status.v2.3.json"))
    licenses = {item.attributes["expression"] for item in state.objects
                if item.attributes["asset_type"] == "license"}
    assert licenses == {"MIT OR Apache-2.0"}, "A licensing information state became a license asset"
    facts = {item.attributes["spdx_id"]: item.attributes for item in state.observations
             if item.kind == "spdx-package-license"}
    assert facts["SPDXRef-Package-0"]["declared"]["state"] == "absent", "Absent value was invented"
    assert facts["SPDXRef-Package-1"]["declared"]["state"] == "none", "NONE lost its meaning"
    assert facts["SPDXRef-Package-1"]["concluded"]["state"] == "noassertion", (
        "Concluded unknown value was conflated with NONE"
    )


def test_NamespacedPurlsAndInverseContainmentUseExistingPackageKeys(context):
    """Native-style names and inverse source relations resolve without losing namespace identity."""

    source = Document("spdx.namespaces.v2.3.json")
    state, _ = Import(context, source)
    expected = {PackageIdentity.FromPurl(item["externalRefs"][0]["referenceLocator"]).Object(
        state.workspace_id
    ).Reference() for item in source["packages"][1:]}
    actual = {item.Reference() for item in state.objects
              if item.attributes["asset_type"] == "package"}
    assert actual == expected, "Namespace or version disappeared from package identities"


@pytest.mark.parametrize("change", [
    {"spdxVersion": "SPDX-2.2"}, {"spdxVersion": "SPDX-3.0"}, {"dataLicense": "MIT"},
    {"SPDXID": "SPDXRef-Other"}, {"documentNamespace": "relative"},
    {"documentNamespace": "urn:owned:namespace#fragment"}, {"name": ""},
    {"documentNamespace": "https:///owned"}, {"documentNamespace": "https://owned.invalid:bad"},
    {"documentNamespace": "urn:owned:with space"},
    {"creationInfo": {}}, {"creationInfo": {"created": "private", "creators": ["Tool: owned"]}},
    {"creationInfo": {"created": "2026-02-30T00:00:00Z", "creators": ["Tool: owned"]}},
    {"creationInfo": {"created": "2026-10-01T00:00:00Z", "creators": []}},
    {"creationInfo": {"created": "2026-10-01T00:00:00Z", "creators": ["Unknown: owned"]}},
    {"packages": []}, {"packages": False}, {"documentDescribes": ["SPDXRef-Missing"]},
    {"documentDescribes": ["SPDXRef-Image", "SPDXRef-Image"]},
    {"documentDescribes": ["SPDXRef-Image", "SPDXRef-Owned-Lib"]},
])
def test_UnsupportedOrAmbiguousEnvelopeFailsAtomically(context, change):
    """Malformed document-level claims cannot return partial inventory or change saved state."""

    root, initial, _ = context
    source = Document()
    source.update(deepcopy(change))

    with pytest.raises(ValueError):
        Import(context, source)

    assert LocalModelStore(root).Open() == initial, "Rejected envelope wrote canonical state"


@pytest.mark.parametrize("field", [
    "files", "snippets", "annotations", "externalDocumentRefs", "hasExtractedLicensingInfos",
    "signatures", "vulnerabilities", "vex",
])
@pytest.mark.parametrize("location", ["document", "package"])
def test_UnsupportedGraphsAreNotSilentlyFlattened(context, field, location):
    """Nonempty semantic graphs require their own accepted interpretation owner."""

    source = Document()
    record = source if location == "document" else source["packages"][1]
    record[field] = [{"private": "synthetic-private-source-value"}]

    with pytest.raises(ValueError):
        Import(context, source)


@pytest.mark.parametrize("change", [
    {"SPDXID": "SPDXRef-DOCUMENT"}, {"SPDXID": "DocumentRef-other:SPDXRef-Package"},
    {"filesAnalyzed": True}, {"filesAnalyzed": 0}, {"hasFiles": []},
    {"packageVerificationCode": {}}, {"licenseInfoFromFiles": []},
    {"versionInfo": "1.1"}, {"name": "different-package"}, {"downloadLocation": None},
    {"externalRefs": []}, {"externalRefs": False},
    {"externalRefs": [{"referenceCategory": "SECURITY", "referenceType": "purl",
                       "referenceLocator": "pkg:pypi/owned-lib@1.0"}]},
    {"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                       "referenceLocator": "pkg:pypi/owned-lib"}]},
    {"licenseDeclared": "LicenseRef-Local"},
    {"licenseConcluded": "DocumentRef-other:LicenseRef-Local"}, {"licenseDeclared": None},
])
def test_MalformedOrUnscopedPackageClaimsFailClosed(context, change):
    """Package bindings and license scopes cannot be repaired by guessing missing identities."""

    source = Document()
    source["packages"][1].update(deepcopy(change))

    with pytest.raises(ValueError):
        Import(context, source)


@pytest.mark.parametrize("field", ["licenseDeclared", "licenseConcluded"])
@pytest.mark.parametrize("expression", [
    "licenseref-owned", "MIT OR licenseref-owned", "LiCeNsErEf-Owned",
    "documentref-other:licenseref-owned", "MIT AND DoCuMeNtReF-Other:LiCeNsErEf-Owned",
])
def test_CaseVariantScopedLicenseReferencesCannotBecomeGlobalAssets(context, field, expression):
    """Scoped license references retain their guard independently of expression prefix case."""

    root, initial, _ = context
    source = Document()
    source["packages"][1][field] = expression

    with pytest.raises(ValueError, match="scoped license"):
        Import(context, source)

    assert LocalModelStore(root).Open() == initial, "Scoped license failure wrote partial state"


@pytest.mark.parametrize("kind,source,target", [
    ("DEPENDS_ON", "SPDXRef-Image", "SPDXRef-Owned-Lib"),
    ("CONTAINS", "SPDXRef-Owned-Lib", "SPDXRef-Image"),
    ("CONTAINS", "SPDXRef-Image", "SPDXRef-Image"),
    ("CONTAINS", "SPDXRef-Image", "SPDXRef-Missing"),
    ("CONTAINS", "DocumentRef-other:SPDXRef-Image", "SPDXRef-Owned-Lib"),
    ("DESCRIBES", "SPDXRef-Owned-Lib", "SPDXRef-Image"),
])
def test_RelationshipClaimsCannotInventContainment(context, kind, source, target):
    """Dependencies, unresolved endpoints and reversed containment never become image contents."""

    document = Document()
    document["relationships"][1] = {
        "relationshipType": kind, "spdxElementId": source, "relatedSpdxElement": target,
    }

    with pytest.raises(ValueError):
        Import(context, document)


@pytest.mark.parametrize("mutate", [
    lambda value: value["packages"].append(deepcopy(value["packages"][1])),
    lambda value: value["relationships"].append(deepcopy(value["relationships"][1])),
    lambda value: value["relationships"].pop(),
    lambda value: value["packages"][0].update(primaryPackagePurpose="APPLICATION"),
    lambda value: value["packages"][1].update(primaryPackagePurpose="CONTAINER"),
    lambda value: value["packages"][0].update(checksums=[]),
    lambda value: value["packages"][0]["checksums"][0].update(algorithm="SHA1"),
    lambda value: value["packages"][0]["checksums"][0].update(checksumValue="b" * 64),
    lambda value: value["packages"][0]["checksums"].append(
        deepcopy(value["packages"][0]["checksums"][0])),
    lambda value: value["packages"][0].update(externalRefs=deepcopy(
        value["packages"][1]["externalRefs"])),
    lambda value: value["packages"][1]["externalRefs"].append(
        deepcopy(value["packages"][1]["externalRefs"][0])),
])
def test_AmbiguousIdentityGraphAndRootDigestAreRejected(context, mutate):
    """Duplicated aliases/PURLs and mismatched image roots cannot manufacture canonical bindings."""

    source = Document()
    mutate(source)

    with pytest.raises(ValueError):
        Import(context, source)


def test_DescriptionRelationMayUseInverseAndMustAgreeWithExplicitRoot(context):
    """One normative local description relation can select the root without a producer shortcut."""

    source = Document()
    del source["documentDescribes"]
    source["relationships"][0] = {"spdxElementId": "SPDXRef-Image",
        "relationshipType": "DESCRIBED_BY", "relatedSpdxElement": "SPDXRef-DOCUMENT"}
    state, _ = Import(context, source)
    references = {item.Reference() for item in state.objects}
    assert PACKAGE.Object(state.workspace_id).Reference() in references, (
        "Inverse document description failed to bind the package catalog"
    )


@pytest.mark.parametrize("changes", [
    {"observed_at": "2030-01-01T00:00:00Z"}, {"source_id": "inventory.other"},
    {"scope_reference": "scope:other"}, {"provider_version": "invented"},
    {"evidence_references": ()},
    {"execution": AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.01)},
])
def test_ModelAcquisitionClaimsMustMatchVerifiedSource(context, changes):
    """Document creation claims cannot substitute for verified acquisition provenance."""

    root, state, _ = context
    record, provenance = Acquired(context, Document())

    with pytest.raises(ValueError):
        ApplyVerifiedSpdx(state, record, replace(provenance, **changes), IMAGE, root)


@pytest.mark.parametrize("changes", [
    {"workspace_id": "other"}, {"invocation_sha256": "a" * 64},
    {"execution": AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.01)},
])
def test_OfflineEvidenceCannotForgeWorkspaceOrExecution(context, changes):
    """Manifest integrity cannot convert fabricated execution into offline document truth."""

    root, state, _ = context
    record, provenance = Acquired(context, Document(), source_overrides=changes)

    with pytest.raises(ValueError):
        ApplyVerifiedSpdx(state, record, provenance, IMAGE, root)


def test_SourceAliasesAreScopedToDocumentContentAndImageKindStaysExplicit(context):
    """Repeated local SPDX IDs retain independent document/image attribution."""

    root, state, _ = context
    for name, image in [
        ("spdx.image.v2.3.json", IMAGE), ("spdx.image.manifest.v2.3.json", MANIFEST),
    ]:
        record, provenance = Acquired(context, Document(name))
        state, _ = ApplyVerifiedSpdx(state, record, provenance, image, root)
    packages = [item for item in state.objects if item.attributes["asset_type"] == "package"]
    aliases = [item.attributes for item in state.observations if item.kind == "spdx-source-alias"
               and item.subject_reference == packages[0].Reference()]
    assert len(packages) == 1 and len(aliases) == 2, "Source aliases became competing package IDs"
    assert len({item["document_sha256"] for item in aliases}) == 2, (
        "Local SPDX IDs lost document scope"
    )
    assert len({item["image_reference"] for item in aliases}) == 2, (
        "Image hash-kind contexts collapsed"
    )


def test_ExplicitKindIsPreservedEvenWhenChecksumBytesAreIdentical(context):
    """A generic SPDX checksum cannot choose between caller-declared OCI digest meanings."""

    root, state, _ = context
    record, provenance = Acquired(context, Document())
    for kind in ("config", "manifest"):
        state, _ = ApplyVerifiedSpdx(state, record, provenance,
                                     ImageIdentity(IMAGE.digest, kind), root)
    images = [item for item in state.objects if item.attributes["asset_type"] == "image"]
    assert len(images) == 2, "Equal checksum bytes incorrectly collapsed OCI digest meanings"
    assert {item.attributes["digest_kind"] for item in images} == {"config", "manifest"}, (
        "SPDX invented a digest kind from a generic checksum"
    )


def test_ExternalSecurityReferencesStayRawAndDuplicateSourcePackagesCorrelate(context):
    """Multiple scoped source IDs may describe one PURL without creating vulnerabilities."""

    marker = "synthetic-private-source-value"
    source = Document()
    package = deepcopy(source["packages"][1])
    package["SPDXID"] = "SPDXRef-Second-Alias"
    package["externalRefs"].append({"referenceCategory": "SECURITY", "referenceType": "advisory",
                                    "referenceLocator": "https://owned.invalid/" + marker})
    source["packages"].append(package)
    source["relationships"].append({"spdxElementId": "SPDXRef-Image",
        "relationshipType": "CONTAINS", "relatedSpdxElement": package["SPDXID"]})
    state, _ = Import(context, source)
    packages = [item for item in state.objects if item.attributes["asset_type"] == "package"]
    aliases = [item for item in state.observations if item.kind == "spdx-source-alias"
               and item.subject_reference == packages[0].Reference()]
    assert len(packages) == 1 and len(aliases) == 2, "Local aliases created duplicate PURL assets"
    assert not Findings(state), "A security reference created a detection verdict"
    assert marker.encode() not in CanonicalModelJson(state.ToDict()), (
        "An unconsumed security locator escaped raw evidence"
    )


@pytest.mark.parametrize("field", ["record", "provenance", "image"])
def test_PublicBoundaryRejectsUnstructuredAcquisitionClaims(context, field):
    """Plain objects cannot stand in for typed verified evidence or explicit image identity."""

    root, state, _ = context
    record, provenance = Acquired(context, Document())
    claims = {"record": record, "provenance": provenance, "image": IMAGE}
    claims[field] = object()
    with pytest.raises(ValueError, match="typed offline"):
        ApplyVerifiedSpdx(state, claims["record"], claims["provenance"], claims["image"], root)


@pytest.mark.parametrize("raw", [b"{", b"[]", b'{"private":1,"private":2}', b'{"x":NaN}',
    b'{"x":1e999}', b"[" * 2000, b'\xff', b" " * (4 * 1024 * 1024 + 1)],
    ids=["incomplete-object", "wrong-top-level", "duplicate-key", "nonfinite-constant",
        "numeric-overflow", "excessive-nesting", "invalid-utf8", "excessive-bytes"])
def test_StrictBoundedJsonFailsWithoutPartialInventory(context, raw):
    """Malformed syntax, numeric constants, UTF-8 and excessive bytes remain validation failures."""

    with pytest.raises(ValueError):
        Import(context, raw)


@pytest.mark.parametrize("key", [False, True])
def test_UnpairedUnicodeInIgnoredSourceFieldsIsRejected(context, key):
    """Ignored vendor metadata cannot evade the strict source Unicode boundary."""

    text = json.dumps(Document())
    padding = '"\\ud800":0' if key else '"x-padding":"\\ud800"'
    raw = (text[:-1] + ',' + padding + '}').encode()

    with pytest.raises(ValueError, match="UTF-8"):
        Import(context, raw)


def test_NodeDepthAndCollectionBudgetsBoundIgnoredAndConsumedData(context):
    """Ignored source padding and consumed graphs obey the accepted resource limits."""

    source = Document()
    source["x-padding"] = [0] * 65537

    with pytest.raises(ValueError):
        Import(context, source)

    source = Document()
    nested = []
    for _ in range(40):
        nested = [nested]
    source["x-padding"] = nested

    with pytest.raises(ValueError):
        Import(context, source)

    source = Document()
    source["relationships"] = [source["relationships"][0]] * 4097

    with pytest.raises(ValueError):
        Import(context, source)


def test_CorruptOrSubstitutedManifestDoesNotUpdateState(context):
    """Content-compatible bytes cannot substitute for an explicit immutable evidence manifest."""

    root, state, store = context
    record, provenance = Acquired(context, Document())
    altered = replace(record, provenance=replace(record.provenance, scope_reference="scope:other"))

    with pytest.raises((ValueError, EvidenceError)):
        ApplyVerifiedSpdx(state, altered, provenance, IMAGE, root)

    raw_path = store.root / record.reference.locator
    raw_path.write_bytes(b"corrupted")

    with pytest.raises(EvidenceIntegrityError):
        ApplyVerifiedSpdx(state, record, provenance, IMAGE, root)

    assert LocalModelStore(root).Open() == state, "Rejected evidence persisted a partial inventory"


@pytest.mark.parametrize("field", ["namespace", "created", "purl", "identifier"])
def test_PrivateMalformedFieldsDoNotEscapeThroughTracebacks(context, field):
    """Validation categories and exception chaining never echo arbitrary invalid source values."""

    marker = "synthetic-private-source-value"
    source = Document()
    if field == "namespace":
        source["documentNamespace"] = "https://[" + marker + "]/"
    elif field == "created":
        source["creationInfo"]["created"] = marker
    elif field == "purl":
        source["packages"][1]["externalRefs"][0]["referenceLocator"] = marker
    else:
        source["packages"][1]["SPDXID"] = "DocumentRef-" + marker

    with pytest.raises(ValueError) as caught:
        Import(context, source)

    assert marker not in str(caught.value), "Validation error copied a private source value"
    assert marker not in "".join(format_exception(caught.value)), "Traceback exposed private data"
