# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verified offline image identity, version correlation, raw provenance and persistence tests."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from shutil import copytree
from traceback import format_exception

import pytest

from fuzzy1337.adapters import (
    AdapterExecution,
    AdapterInvocation,
    AdapterReport,
    AdapterRequest,
    ExecutionState,
    ImpactLevel,
)
from fuzzy1337.evidence import EvidenceIntegrityError, EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.executors import InvocationDigest
from fuzzy1337.findings import Findings, FindingStatus, TransitionFinding
from fuzzy1337.images import (
    ApplyVerifiedCycloneDx,
    ApplyVerifiedTrivyImages,
    ImageIdentity,
    PackageIdentity,
)
from fuzzy1337.model import CanonicalModelJson, LocalModelStore, ModelProvenance
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

IMAGE = "sha256:" + "a" * 64
MANIFEST = "sha256:" + "b" * 64
PURL = "pkg:pypi/owned-lib@1.0"
NATIVE = {
    "SchemaVersion": 2, "ArtifactType": "container_image",
    "Metadata": {"ImageID": IMAGE, "RepoDigests": ["owned.invalid/fixture@" + MANIFEST],
                 "DiffIDs": ["sha256:" + "c" * 64], "OS": {"Family": "alpine", "Name": "3.20"},
                 "Env": ["SYNTHETIC_PRIVATE_MARKER"]},
    "Results": [{"Target": "private/path/SYNTHETIC_PRIVATE_MARKER", "Type": "python-pkg",
        "Packages": [{"ID": "owned-1", "Name": "Owned_Lib", "Version": "1.0",
                      "Identifier": {"PURL": PURL}, "Licenses": ["MIT"],
                      "Description": "SYNTHETIC_PRIVATE_MARKER"}],
        "Vulnerabilities": [{"VulnerabilityID": "CVE-2099-0001", "PkgID": "owned-1",
            "PkgName": "Owned_Lib", "InstalledVersion": "1.0", "FixedVersion": "2.0",
            "Severity": "HIGH", "Description": "SYNTHETIC_PRIVATE_MARKER"}]}],
}
SBOM = {
    "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
    "metadata": {"component": {"type": "container", "name": "owned",
        "hashes": [{"alg": "SHA-256", "content": IMAGE[7:]}]}},
    "components": [{"type": "library", "bom-ref": "owned-1", "name": "Owned_Lib",
        "version": "1.0", "purl": PURL, "licenses": [{"license": {"id": "MIT"}}],
        "properties": [{"name": "private", "value": "SYNTHETIC_PRIVATE_MARKER"}]}],
}


@pytest.fixture
def context(tmp_path):
    """Create an owned canonical workspace and evidence store, without running a scanner."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned image fixture"), "image-test")

    return root, LocalModelStore(root).Create(), LocalEvidenceStore(root / "evidence")


def Native(context, payload=NATIVE, source_overrides=None, provider_version="0.75.0-synthetic",
           version_fields=None):
    """Store attributed synthetic Trivy-format bytes; the fixture never claims a real scan."""

    root, state, store = context
    execution = AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.01)
    invocation = AdapterInvocation("native.trivy",
        AdapterRequest("image.archive-vulnerabilities", "target:owned", ImpactLevel.SAFE,
                       {"archive": "owned.tar", "timeout_seconds": 1}),
        ("synthetic-trivy", "--input", "owned.tar"), 1, provider_version)
    source = EvidenceProvenance(state.workspace_id, "scope:owned", "native.trivy", "1",
        invocation.provider_version, "2026-10-13T00:00:00Z", "2026-10-13T00:00:01Z",
        InvocationDigest(invocation), execution)

    if source_overrides:
        source = replace(source, **source_overrides)

    raw = payload if isinstance(payload, bytes) else CanonicalModelJson(payload)
    records = [store.Put(raw, "stdout", "application/json", source),
               store.Put(b"owned synthetic evidence fixture", "stderr", "text/plain", source)]
    version = {"Version": invocation.provider_version,
               "VulnerabilityDB": {"Version": 2, "UpdatedAt": "2026-10-01T00:00:00Z"}}

    if version_fields:
        version.update(version_fields)

    records.append(store.Put(CanonicalModelJson(version),
        "provider-version", "application/json", replace(source, invocation_sha256=None,
            execution=None, started_at="2026-10-12T23:59:59Z",
            finished_at="2026-10-13T00:00:00Z")))
    report = AdapterReport(invocation, execution, tuple(item.reference for item in records))
    provenance = ModelProvenance("native.trivy", "run:fixture", source.finished_at,
        "scope:owned", "target:owned", invocation.provider_version, report.evidence, execution)

    return report, provenance, tuple(records)


def Sbom(context, payload=SBOM):
    """Preserve independently collected SBOM bytes without inventing a terminal scan outcome."""

    _, state, store = context
    source = EvidenceProvenance(state.workspace_id, "scope:owned", "inventory.cyclonedx", "1",
                               None, "2026-10-13T00:00:00Z", "2026-10-13T00:00:01Z")
    raw = payload if isinstance(payload, bytes) else CanonicalModelJson(payload)
    record = store.Put(raw, "sbom", "application/json", source)
    provenance = ModelProvenance(source.source_id, "run:sbom", source.finished_at,
        source.scope_reference, "target:owned", evidence_references=(record.reference,))

    return record, provenance


def Import(context, payload=NATIVE):
    """Interpret verified owned native fixture evidence through the public import boundary."""

    root, state, _ = context
    report, provenance, records = Native(context, payload)

    return ApplyVerifiedTrivyImages(state, report, provenance, records, root)


def test_ImagePackageIdentityDedupAndPersistence(context):
    """Repeated native and SBOM imports share package identities and retain raw provenance."""

    root, initial, store = context
    report, provenance, records = Native(context)
    state, delta = ApplyVerifiedTrivyImages(initial, report, provenance, records, root)
    replay, no_change = ApplyVerifiedTrivyImages(state, report, provenance, records, root)

    assert replay == state and not no_change.created and not no_change.updated, (
        "Exact evidence replay must preserve state, revisions and observation history."
    )
    assert delta.revision == initial.revision + 1, "One import must produce one transition."
    assert len(Findings(state)) == 1, "The exact-version vulnerability must correlate once."
    assert Findings(state)[0].severity.value == "high", "Native severity must retain its value."
    assert Findings(state)[0].remediation.summary == "Upgrade to 2.0", (
        "The advisory must preserve the provider's fixed version."
    )
    assert store.Read(records[0].reference) == CanonicalModelJson(NATIVE), (
        "Normalized interpretation must leave original raw tool output unchanged."
    )
    assert b"SYNTHETIC_PRIVATE_MARKER" not in CanonicalModelJson(state.ToDict()), (
        "Arbitrary private metadata must remain outside normalized durable state."
    )
    assert ImageIdentity(IMAGE).Object(state.workspace_id).Reference() != (
        ImageIdentity(IMAGE, "manifest").Object(state.workspace_id).Reference()
    ), "Config and manifest hash semantics must identify distinct image assets."
    model = LocalModelStore(root)
    model.Save(state, expected_revision=initial.revision)
    previous_revision = state.revision
    record, sbom_context = Sbom(context)
    state, _ = ApplyVerifiedCycloneDx(state, record, sbom_context, ImageIdentity(IMAGE), root)
    package = PackageIdentity.FromPurl(PURL).Object(state.workspace_id).Reference()
    entities = [item for item in state.objects if item.Reference() == package]

    assert len(entities) == 1 and len(entities[0].provenance) == 2, (
        "Native and SBOM inventory must share identity while retaining both source origins."
    )
    model.Save(state, expected_revision=previous_revision)

    assert LocalModelStore(root).Open() == state, "Canonical state must survive durable reopening."


def test_MultipleImageOriginsPreserveFindingTriage(context):
    """The same package/version finding deduplicates across images and never auto-reopens triage."""

    root, _, _ = context
    state, _ = Import(context)
    finding = Findings(state)[0]
    operator = ModelProvenance("operator", "decision:owned", "2026-10-13T01:00:00Z",
                               "scope:owned", "target:owned")
    state, _ = TransitionFinding(state, finding.ToObject(state.workspace_id).Reference(),
        FindingStatus.RESOLVED, operator, "Synthetic owner disposition")
    other = deepcopy(NATIVE)
    other["Metadata"]["ImageID"] = "sha256:" + "d" * 64
    report, provenance, records = Native(context, other)
    state, _ = ApplyVerifiedTrivyImages(state, report, provenance, records, root)

    assert len(Findings(state)) == 1 and Findings(state)[0].status is FindingStatus.RESOLVED, (
        "Additional image origins must not duplicate or reopen an operator-resolved finding."
    )
    containing = [item for item in state.relations
                  if item.target_reference == finding.subject_reference]

    assert len(containing) == 2, "The package must retain both containing image origins."
    state, _ = TransitionFinding(state, finding.ToObject(state.workspace_id).Reference(),
        FindingStatus.OPEN, replace(operator, run_reference="decision:reopen"),
        "Explicit reopening")

    assert Findings(state)[0].status is FindingStatus.OPEN, "Operator reopening must apply."


@pytest.mark.parametrize("overrides", [
    {"workspace_id": "different"}, {"scope_reference": "scope:other"},
    {"source_id": "native.other"}, {"tool_version": "different"},
    {"invocation_sha256": "0" * 64},
    {"execution": AdapterExecution(ExecutionState.FAILED, 7, 0.01)},
])
def test_ManifestProvenanceMustMatchReport(context, overrides):
    """Valid content hashes cannot attach another workspace/source/run's bytes to an import."""

    root, state, _ = context
    report, provenance, records = Native(context, source_overrides=overrides)

    with pytest.raises(ValueError):
        ApplyVerifiedTrivyImages(state, report, provenance, records, root)


@pytest.mark.parametrize("mutate", [
    lambda value: value.update(SchemaVersion=True),
    lambda value: value.update(ArtifactType="filesystem"),
    lambda value: value.update(Trivy={"Version": "contradictory"}),
    lambda value: value.update(Metadata={"ImageID": "latest"}),
    lambda value: value["Metadata"].update(RepoDigests=["mutable-tag"]),
    lambda value: value["Metadata"].update(DiffIDs=["bad"]),
    lambda value: value["Results"][0].update(Packages={}),
    lambda value: value["Results"][0].update(Vulnerabilities=False),
    lambda value: value["Results"][0]["Packages"][0].update(Licenses=False),
    lambda value: value["Results"][0]["Packages"][0].update(Version="1.1"),
    lambda value: value["Results"][0]["Packages"][0].update(Epoch=True),
    lambda value: value["Results"][0]["Vulnerabilities"][0].update(InstalledVersion="1.1"),
    lambda value: value["Results"][0]["Vulnerabilities"][0].update(PkgID="other"),
    lambda value: value["Results"][0]["Vulnerabilities"][0].update(Severity="FAKE"),
])
def test_MalformedNativeIdentityAndVersionBindingFailClosed(context, mutate):
    """Malformed structures and wrong installed versions cannot manufacture correlated findings."""

    payload = deepcopy(NATIVE)
    mutate(payload)

    with pytest.raises(ValueError):
        Import(context, payload)


@pytest.mark.parametrize("value", [
    "pkg:pypi/name", "pkg:pypi/name@", "pkg:PyPi/name@1", "pkg:pypi/%gg@1",
    "pkg:pypi/%ff@1", "pkg:pypi/%2f@1", "pkg:pypi/..@1", "pkg:pypi/name@1#file",
    "pkg:pypi/name@1?token=private", "pkg:pypi/name@1?arch=x&arch=y",
    "pkg:pypi/name@1?arch", "pkg:pypi/name@1?arch=%00", "bad",
])
def test_UnsupportedPurlProfileFails(value):
    """Identity parsing rejects unknown qualifiers, invalid encoding and missing versions."""

    with pytest.raises(ValueError):
        PackageIdentity.FromPurl(value)


def test_NativeEpochReleaseFallbackAndVersionSeparation(context):
    """Epoch/release complete installed versions and fallback preserves OS/architecture context."""

    payload = deepcopy(NATIVE)
    package = payload["Results"][0]["Packages"][0]
    package.update(Name="owned-lib", Version="1.0", Release="r1", Epoch=2, Arch="x86_64",
                   Identifier={})
    vulnerability = payload["Results"][0]["Vulnerabilities"][0]
    vulnerability.update(PkgName="owned-lib", InstalledVersion="2:1.0-r1")
    state, _ = Import(context, payload)
    identity = PackageIdentity("python-pkg", "owned-lib", "2:1.0-r1",
        qualifiers=(("arch", "x86_64"), ("os", "alpine"), ("os_version", "3.20")))

    assert Findings(state)[0].subject_reference == identity.Object(
        state.workspace_id
    ).Reference(), (
        "Epoch, release and OS/architecture context must bind the installed package version."
    )
    assert identity.Object(state.workspace_id) != replace(identity, version="2:1.0-r2").Object(
        state.workspace_id
    ), "Different installed release versions must retain distinct package identities."


@pytest.mark.parametrize("mutate", [
    lambda value: value.update(specVersion="1.5"),
    lambda value: value.update(version=True),
    lambda value: value["metadata"]["component"].update(type="library"),
    lambda value: value["metadata"]["component"].update(hashes=[]),
    lambda value: value["components"].append(value["components"][0]),
    lambda value: value["components"][0].update(version="2.0"),
    lambda value: value["components"][0].update(name="other"),
    lambda value: value["components"][0].update(type="container"),
    lambda value: value["components"][0].update(licenses=[None]),
    lambda value: value["components"][0].update(licenses=[
        {"license": {"id": "MIT"}, "expression": "Apache-2.0"}]),
    lambda value: value["components"][0].update(components=[{}]),
    lambda value: value["metadata"]["component"].update(components=[{}]),
])
def test_SbomFormatRootAndComponentBinding(context, mutate):
    """Wrong format/container hash and ambiguous components fail before any model update."""

    root, state, _ = context
    payload = deepcopy(SBOM)
    mutate(payload)
    record, provenance = Sbom(context, payload)

    with pytest.raises(ValueError):
        ApplyVerifiedCycloneDx(state, record, provenance, ImageIdentity(IMAGE), root)


def test_SbomExpressionAndExplicitManifestBinding(context):
    """Inventory retains license expressions and honors caller-declared manifest hash semantics."""

    root, state, _ = context
    payload = deepcopy(SBOM)
    payload["components"][0]["licenses"] = [{"expression": "MIT OR Apache-2.0"}]
    record, provenance = Sbom(context, payload)
    imported, _ = ApplyVerifiedCycloneDx(
        state, record, provenance, ImageIdentity(IMAGE, "manifest"), root,
    )
    replay, delta = ApplyVerifiedCycloneDx(imported, record, provenance,
                                          ImageIdentity(IMAGE, "manifest"), root)

    assert replay == imported and not delta.created and not delta.updated, (
        "SBOM replay must deduplicate its inventory and acquisition observations."
    )
    assert not Findings(imported), "Inventory alone must not invent vulnerability verdicts."
    assert any(item.attributes.get("expression") == "MIT OR Apache-2.0"
               for item in imported.objects), "Declared license expressions must survive import."


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'\xff',
    b'{"a":' + b'9' * 5000 + b'}', b'{"a":' + b'[' * 40 + b'0' + b']' * 40 + b'}'])
def test_RawParserFailuresPreserveOriginalState(context, raw):
    """Ambiguous/non-finite/truncated raw evidence never yields a partially accepted inventory."""

    root, state, _ = context
    record, provenance = Sbom(context, raw)

    with pytest.raises(ValueError):
        ApplyVerifiedCycloneDx(state, record, provenance, ImageIdentity(IMAGE), root)

    assert LocalModelStore(root).Open() == state, "Failed interpretation must leave state intact."


def test_EvidenceAndCollectionBudgets(context, monkeypatch):
    """Integrity and independent item/byte budgets fail before durable state is changed."""

    from fuzzy1337 import images

    root, state, store = context
    report, provenance, records = Native(context)
    monkeypatch.setattr(images, "IMAGE_IMPORT_MAX_BYTES", 1)

    with pytest.raises(ValueError, match="byte budget"):
        ApplyVerifiedTrivyImages(state, report, provenance, records, root)

    monkeypatch.setattr(images, "IMAGE_IMPORT_MAX_BYTES", 4 * 1024 * 1024)
    monkeypatch.setattr(images, "IMAGE_IMPORT_MAX_ITEMS", 0)

    with pytest.raises(ValueError, match="bounded array"):
        ApplyVerifiedTrivyImages(state, report, provenance, records, root)

    monkeypatch.setattr(images, "IMAGE_IMPORT_MAX_ITEMS", 4096)
    (store.root / records[0].reference.locator).write_bytes(b"corrupted owned fixture")

    with pytest.raises(EvidenceIntegrityError, match="digest|length"):
        ApplyVerifiedTrivyImages(state, report, provenance, records, root)


def test_SourceFailureAndModelContextCannotBeSubstituted(context):
    """A failed report or mismatched model context cannot inherit successful native evidence."""

    root, state, _ = context
    report, provenance, records = Native(context)

    with pytest.raises(ValueError):
        ApplyVerifiedTrivyImages(state, replace(report,
            execution=AdapterExecution(ExecutionState.FAILED, 7, 0.01)), provenance, records, root)

    with pytest.raises(ValueError):
        ApplyVerifiedTrivyImages(state, report, replace(provenance, target_reference="other"),
                                 records, root)

    with pytest.raises(ValueError):
        ImageIdentity(IMAGE, "tag")

    with pytest.raises(ValueError):
        PackageIdentity("pypi", "x\x00", "1")


@pytest.mark.parametrize("version_fields", [
    {"Version": "different"}, {"VulnerabilityDB": {"Version": True}},
    {"VulnerabilityDB": {"Version": 0, "UpdatedAt": "2026-10-01T00:00:00Z"}},
    {"VulnerabilityDB": {"Version": 2, "UpdatedAt": ""}},
])
def test_ObservedDatabaseAndToolMetadataCannotBeInvented(context, version_fields):
    """Accepted image identities require matching observed tool and valid database metadata."""

    root, state, _ = context
    report, provenance, records = Native(context, version_fields=version_fields)

    with pytest.raises(ValueError):
        ApplyVerifiedTrivyImages(state, report, provenance, records, root)


def test_ScanObservationTimeAndProbeChronology(context):
    """Observation time matches scan collection; future probes cannot attest an earlier scan."""

    root, state, store = context
    report, provenance, records = Native(context)

    with pytest.raises(ValueError):
        ApplyVerifiedTrivyImages(state, report,
            replace(provenance, observed_at="2026-10-13T01:00:00Z"), records, root)

    original = records[-1]
    future = store.Put(store.Read(original.reference), original.reference.role, "application/json",
        replace(original.provenance, started_at="2026-10-13T02:00:00Z",
                finished_at="2026-10-13T02:00:01Z"))

    with pytest.raises(ValueError, match="precede"):
        ApplyVerifiedTrivyImages(state, report, provenance, (*records[:-1], future), root)


def test_UnsupportedNativeVersionAndMissingEvidence(context):
    """Compatible bytes and empty roles cannot substitute for the supported provider envelope."""

    root, state, _ = context
    report, provenance, records = Native(context, provider_version="0.74.0-synthetic")

    with pytest.raises(ValueError, match="supported"):
        ApplyVerifiedTrivyImages(state, report, provenance, records, root)

    report, provenance, records = Native(context)

    with pytest.raises(ValueError):
        ApplyVerifiedTrivyImages(state, report, provenance, (), root)

    with pytest.raises(ValueError):
        ApplyVerifiedTrivyImages(state, report, provenance, (*records, records[0]), root)


def test_SbomScopeOwnershipAndNoScanClaim(context):
    """Offline inventory attribution cannot invent scan execution or replace its evidence role."""

    root, state, store = context
    record, provenance = Sbom(context)

    with pytest.raises(ValueError):
        ApplyVerifiedCycloneDx(state, record,
            replace(provenance, execution=AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.01)),
            ImageIdentity(IMAGE), root)

    claimed = store.Put(store.Read(record.reference), "sbom", "application/json",
        replace(record.provenance, invocation_sha256="a" * 64))

    with pytest.raises(ValueError, match="invent"):
        ApplyVerifiedCycloneDx(state, claimed, provenance, ImageIdentity(IMAGE), root)

    with pytest.raises(ValueError):
        ApplyVerifiedCycloneDx(state, record, provenance, ImageIdentity(MANIFEST), root)


def test_PurlCanonicalizationAndQualifierOrdering():
    """Equivalent percent-encoded qualifiers and PyPI names retain the same package/version key."""

    first = PackageIdentity.FromPurl("pkg:pypi/Owned_Lib@1.0?arch=x86_64&distro=owned")
    second = PackageIdentity.FromPurl("pkg:pypi/owned-lib@1.0?distro=%6Fwned&arch=x86_64")

    assert first == second, "Encoding and qualifier order must not split package identities."

    with pytest.raises(ValueError):
        PackageIdentity("pypi", "_invalid", "1")

    with pytest.raises(ValueError):
        PackageIdentity("pypi", "name\ud800", "1")


@pytest.mark.parametrize(("result_type", "name", "purl"), [
    ("node-pkg", "@owned/lib", "pkg:npm/%40owned/lib@1.0"),
    ("jar", "org.owned:lib", "pkg:maven/org.owned/lib@1.0"),
    ("gobinary", "owned.invalid/lib", "pkg:golang/owned.invalid/lib@1.0"),
])
def test_NamespacedPackagesRetainExactNativeCorrelation(context, result_type, name, purl):
    """Native npm/Maven/Go names bind their PURL namespace rather than losing package identity."""

    payload = deepcopy(NATIVE)
    payload["Results"][0]["Type"] = result_type
    payload["Results"][0]["Packages"][0].update(Name=name, Identifier={"PURL": purl})
    payload["Results"][0]["Vulnerabilities"][0].update(PkgName=name)
    state, _ = Import(context, payload)

    assert Findings(state)[0].subject_reference == PackageIdentity.FromPurl(purl).Object(
        state.workspace_id
    ).Reference(), "Qualified names must retain their namespaced installed-version key."


@pytest.mark.parametrize("observed_at", [
    "2026-10-12T23:59:59Z", "2030-01-01T00:00:00Z",
])
def test_SbomObservationTimeMustMatchVerifiedCollection(context, observed_at):
    """The public document ingestion boundary cannot invent earlier or later acquisition facts."""

    root, state, store = context
    record, provenance = Sbom(context)
    raw = store.Read(record.reference)

    with pytest.raises(ValueError, match="observation time"):
        ApplyVerifiedCycloneDx(state, record, replace(provenance, observed_at=observed_at),
                              ImageIdentity(IMAGE), root)

    assert LocalModelStore(root).Open() == state, "Rejected attribution wrote canonical state."
    assert store.Read(record.reference) == raw, "Rejected attribution altered immutable evidence."


@pytest.mark.parametrize(("architecture", "purl"), [
    (None, "pkg:npm/owned-lib@1.0"),
    ("x86_64", "pkg:pypi/owned-lib@1.0?arch=arm64"),
    ("x86_64", "pkg:pypi/owned-lib@1.0"),
    (True, "pkg:pypi/owned-lib@1.0?arch=x86_64"),
])
def test_ContradictoryNativePurlClassificationCannotCorrelateFindings(context, architecture, purl):
    """A catalog cannot relabel Python packages or collapse observed incompatible architectures."""

    root, initial, store = context
    payload = deepcopy(NATIVE)
    payload["Results"][0]["Packages"][0].update(Name="owned-lib", Arch=architecture,
                                               Identifier={"PURL": purl})
    payload["Results"][0]["Vulnerabilities"][0]["PkgName"] = "owned-lib"
    report, provenance, records = Native(context, payload)

    with pytest.raises(ValueError):
        ApplyVerifiedTrivyImages(initial, report, provenance, records, root)

    assert LocalModelStore(root).Open() == initial, "Contradictory package fields changed state."
    assert store.Read(records[0].reference) == CanonicalModelJson(payload), (
        "Contradictory raw package evidence must remain available for inspection."
    )


def test_MatchingNativeArchitectureKeepsPackageVersionsDistinct(context):
    """Different observed architectures retain separate installed-package identities."""

    root, state, _ = context

    for architecture in ("x86_64", "arm64"):
        payload = deepcopy(NATIVE)
        payload["Results"][0]["Packages"][0].update(Arch=architecture,
            Identifier={"PURL": PURL + "?arch=" + architecture})
        report, provenance, records = Native(context, payload)
        state, _ = ApplyVerifiedTrivyImages(state, report, provenance, records, root)

    expected = {PackageIdentity.FromPurl(PURL + "?arch=" + architecture).Object(
        state.workspace_id
    ).Reference() for architecture in ("x86_64", "arm64")}
    assert {finding.subject_reference for finding in Findings(state)} == expected, (
        "Architecture-specific package findings collapsed into one package version."
    )


@pytest.mark.parametrize("field", ["severity", "database_updated_at"])
def test_UntrustedNativeDiagnosticFieldsDoNotLeakThroughTracebacks(context, field):
    """Malformed provider fields remain confined to raw evidence when validation fails."""

    root, state, _ = context
    marker = "synthetic-private-source-value"
    payload = deepcopy(NATIVE)
    version_fields = None

    if field == "severity":
        payload["Results"][0]["Vulnerabilities"][0]["Severity"] = marker

    else:
        version_fields = {"VulnerabilityDB": {"Version": 2, "UpdatedAt": marker}}

    report, provenance, records = Native(context, payload, version_fields=version_fields)

    with pytest.raises(ValueError) as caught:
        ApplyVerifiedTrivyImages(state, report, provenance, records, root)

    assert marker not in str(caught.value), "Validation diagnostic exposed private source data."
    assert marker not in "".join(format_exception(caught.value)), (
        "Validation exception chaining exposed private source data."
    )


def test_VerifiedInventoryReplaySurvivesWorkspaceRelocation(context):
    """Relative evidence/manifests and canonical IDs remain valid after an owned workspace move."""

    root, original, _ = context
    report, provenance, records = Native(context)
    imported, _ = ApplyVerifiedTrivyImages(original, report, provenance, records, root)
    LocalModelStore(root).Save(imported, expected_revision=original.revision)
    relocated = root.with_name("relocated-owned-workspace")
    copytree(root, relocated)
    reopened = LocalModelStore(relocated).Open()
    store = LocalEvidenceStore(relocated / "evidence")
    retained = tuple(store.Get(item.evidence_id) for item in records)
    replay, delta = ApplyVerifiedTrivyImages(reopened, report, provenance, retained, relocated)

    assert replay == imported and not delta.created and not delta.updated, (
        "Relocation must preserve immutable attribution, package identities and exact replay."
    )
