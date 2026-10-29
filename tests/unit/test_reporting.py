# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure report projections, strict display references, and hostile serialization boundaries."""

import json
from dataclasses import FrozenInstanceError, replace
from html.parser import HTMLParser
from xml.etree import ElementTree

import pytest

from fuzzy1337 import report_formats, reporting
from fuzzy1337.adapters.contracts import ExecutionState
from fuzzy1337.model import (
    CanonicalModelJson,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from fuzzy1337.report_formats import RenderHtml, SerializeJson, SerializeJunit, SerializeSarif
from fuzzy1337.reporting import ReportReference, ReportSnapshot
from tests.contract.reporting_fixture import Fixture

EXPORTERS = (RenderHtml, SerializeJson, SerializeSarif, SerializeJunit)


class Dom(HTMLParser):
    """Collect exact inert HTML tags, attributes, IDs, and text without executing a browser."""

    def __init__(self):
        """Initialize independent parser collections for one report."""

        super().__init__()
        self.tags = []
        self.attributes = []
        self.ids = []
        self.links = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        """Record parsed attributes and targets, including decoded HTML entities."""

        self.tags.append(tag)
        self.attributes.extend(attrs)
        fields = dict(attrs)

        if "id" in fields:
            self.ids.append(fields["id"])

        if tag == "a":
            self.links.append(fields["href"])

    def HandleData(self, data):
        """Record visible text for independent escaped-payload assertions."""

        self.text.append(data)

    handle_data = HandleData


def test_ProjectionRetainsExactCanonicalStateAndHonestInterpretations():
    """Export never invents observed edges, successful execution, verified bytes, or compliance."""

    report = Fixture()
    original = CanonicalModelJson(report.state.ToDict())
    document = json.loads(SerializeJson(report))

    assert document["model"] == report.state.ToDict(), "Report replaced canonical model content"
    assert document["scan_completeness"] == "not-assessed", "Snapshot claimed scan completeness"
    assert document["summary"]["finding_statuses"] == {
        "open": 1, "confirmed": 1, "dismissed": 1, "resolved": 1,
    }, "Finding dispositions were lost during projection"
    assert document["summary"]["active_findings"] == 2, "Closed dispositions counted as active"
    assert document["summary"]["failed_execution_records"] == 1, "Failure records were lost"
    assert document["evidence_integrity"]["checked_references"] == [], (
        "Pure report invented raw artifact integrity verification"
    )
    assert document["evidence_integrity"]["unverified_count"] == 1, "Integrity references changed"
    assert {item["reference"] for item in document["model"]["relations"]} == {
        report.state.relations[0].Reference(),
    }, (
        "Report added attack/reachability relations absent from the canonical model"
    )
    assert CanonicalModelJson(report.state.ToDict()) == original, "Export mutated source state"


def test_FailedExecutionCountRetainsDistinctTargetAttributionWithoutInferringJobs():
    """The summary counts exact outcome provenance, not guessed acquisition or run identities."""

    provenance = Fixture().state.Objects(ObjectKind.HOST)[0].provenance[0]
    succeeded = replace(
        provenance,
        execution=replace(provenance.execution, state=ExecutionState.SUCCEEDED, exit_code=0),
    )
    first = SecurityObject(
        ObjectIdentity("synthetic", ObjectKind.ASSET, "first"), {}, (provenance,),
    )
    second = SecurityObject(
        ObjectIdentity("synthetic", ObjectKind.ASSET, "second"), {},
        (provenance, replace(provenance, target_reference="target:other"), succeeded),
    )
    state, _ = ModelState("synthetic").Apply(objects=(first, second))
    document = ReportSnapshot(state).ToDict()

    assert document["summary"]["failed_execution_records"] == 2, (
        "Distinct target attribution was merged or shared exact provenance counted twice"
    )
    assert len(document["execution_outcomes"]) == 3, "Projection lost conflicting source outcomes"
    assert "failed_acquisitions" not in document["summary"], "Count claimed inferred acquisitions"


@pytest.mark.parametrize("exporter", EXPORTERS, ids=lambda function: function.__name__)
def test_ExportsAreDeterministicAndRejectUntypedState(exporter):
    """The same snapshot yields identical artifacts; dictionaries cannot pretend to be reports."""

    report = Fixture()

    assert exporter(report) == exporter(Fixture()), "Identical snapshots exported differently"

    with pytest.raises(ValueError, match="ReportSnapshot"):
        exporter({})


def test_SarifRetainsActiveResultsAndClosedDispositionMetadataWithoutPassedChecks():
    """SARIF retains canonical findings without guessed source coordinates or invocation success."""

    report = Fixture()
    document = json.loads(SerializeSarif(report))
    run = document["runs"][0]

    assert document["version"] == "2.1.0", "SARIF version changed"
    assert len(run["results"]) == 2 and len(run["properties"]["closedFindings"]) == 2, (
        "SARIF changed the retained active/closed disposition boundary"
    )
    assert {item["level"] for item in run["results"]} == {"error", "warning"}, (
        "SARIF severity adapter lost unknown/high normalized severity"
    )
    assert all(item["kind"] == "fail" for item in run["results"]), "SARIF invented passed checks"
    assert "invocations" not in run, "Report claimed an overall scanner execution outcome"
    assert all("physicalLocation" not in location for item in run["results"]
               for location in item["locations"]), "Report invented source-code coordinates"
    assert run["properties"]["canonicalSnapshotSha256"] == report.SnapshotDigest(), (
        "SARIF detached results from the exact canonical snapshot"
    )


def test_JunitAdaptersUseFailuresAndSkipsWithoutInventingSecurityPasses():
    """JUnit findings retain terminal dispositions and execution provenance in valid XML."""

    root = ElementTree.fromstring(SerializeJunit(Fixture()))

    assert root.attrib == {
        "name": "1337 retained findings", "tests": "4", "failures": "2",
        "errors": "0", "skipped": "2",
    }, "JUnit counts did not match canonical disposition semantics"
    assert len(root.findall("testcase/failure")) == len(root.findall("testcase/skipped")) == 2, (
        "A retained finding was silently converted into a passed check"
    )
    assert all(case.find("failure") is not None or case.find("skipped") is not None
               for case in root.findall("testcase")), "JUnit invented a security pass"
    assert '"state":"failed"' in root.find("testcase/failure").text, (
        "JUnit discarded failed acquisition provenance"
    )


def test_EmptySnapshotDoesNotClaimACompletedCleanScan():
    """Zero retained findings are explicit empty projections with no successful scan inference."""

    report = ReportSnapshot(ModelState("synthetic"))
    sarif = json.loads(SerializeSarif(report))["runs"][0]
    junit = ElementTree.fromstring(SerializeJunit(report))

    assert sarif["results"] == [] and sarif["properties"]["scanCompleteness"] == "not-assessed", (
        "Empty report claimed successful scanner coverage"
    )
    assert junit.attrib["tests"] == "0" and junit.findall("testcase") == [], (
        "Empty report invented passed security checks"
    )


def test_HtmlIsDarkOfflineInertAndEveryCanonicalFragmentResolves():
    """Exact DOM/fragment assertions establish safe offline details without launching a browser."""

    report = Fixture()
    dom = Dom()
    dom.feed(RenderHtml(report).decode("utf-8"))

    assert not {"script", "iframe", "img", "form", "object", "embed"} & set(dom.tags), (
        "Report introduced executable or externally acquired content"
    )
    assert not any(name.lower().startswith("on") for name, _ in dom.attributes), (
        "Report introduced executable event handlers"
    )
    assert ("content", "dark") in dom.attributes, "Report lost its explicit dark default"
    assert len(dom.ids) == len(set(dom.ids)), "Canonical report fragments were duplicated"
    assert all(link[1:] in dom.ids for link in dom.links if link.startswith("#")), (
        "A canonical report reference points to a missing fragment"
    )
    links = {item.Url() for binding in report.reference_bindings for item in binding.references}
    assert {link for link in dom.links if not link.startswith("#")} == links, (
        "Report accepted an arbitrary clickable URL instead of a fixed publisher locator"
    )
    assert dom.tags.count("details") >= len(report.state.objects) + 4, (
        "Report did not expose interactive canonical/finding detail layers"
    )


def test_HostileHtmlXmlControlsAndBidiRemainVisibleInertText():
    """Stored hostile strings cannot escape text contexts or poison XML/control rendering."""

    hostile = '<script src=x>alert(1)</script><img src=x onerror="alert(1)">\x01\x1b\u202e'
    report = Fixture(summary=hostile, key='build:<svg onload="alert(1)">\u202e')
    dom = Dom()
    dom.feed(RenderHtml(report).decode("utf-8"))
    displayed = "".join(dom.text)
    junit = ElementTree.fromstring(SerializeJunit(report))

    assert "script" not in dom.tags and "img" not in dom.tags and "svg" not in dom.tags, (
        "HTML payload escaped inert report text"
    )
    assert "\\u0001" in displayed and "\\u001b" in displayed and "\\u202e" in displayed, (
        "Report emitted hidden terminal or bidirectional controls"
    )
    assert "\\u0001" in junit.find("testcase/failure").attrib["message"], (
        "XML-invalid controls were emitted rather than displayed safely"
    )
    summaries = {item["normalized"]["summary"] for item in json.loads(
        SerializeJson(report),
    )["findings"]}

    assert hostile in summaries, (
        "Safe presentation changed the canonical machine-readable finding interpretation"
    )


@pytest.mark.parametrize("family,identifier,version,url", [
    ("cve", "CVE-2025-12345", "synthetic", "https://www.cve.org/CVERecord?id=CVE-2025-12345"),
    ("cwe", "CWE-89", "4.20", "https://cwe.mitre.org/data/definitions/89.html"),
    ("capec", "CAPEC-66", "3.9", "https://capec.mitre.org/data/definitions/66.html"),
    ("attack", "T1059.001", "19", "https://attack.mitre.org/techniques/T1059/001/"),
    ("atlas", "AML.T0001", "synthetic", "https://atlas.mitre.org/techniques/AML.T0001"),
    ("owasp-top10", "A03:2021", "2021", "https://top10.owasp.org/2021/A03_2021-Injection/"),
])
def test_CanonicalReferencePublisherUrlsAreFixedAndVersionMetadataIsRetained(
    family, identifier, version, url,
):
    """Canonical navigation never accepts caller URL syntax or claims historical page pinning."""

    reference = ReportReference(family, identifier, version)

    assert reference.Url() == url, "Fixed canonical publisher URL changed"
    assert reference.ToDict()["catalog_version"] == version, "Catalog version was discarded"


@pytest.mark.parametrize("fields", [
    ("javascript", "CWE-89", "1"), ("cwe", "javascript:alert(1)", "1"),
    ("cwe", "CWE-89/../../x", "1"), ("cwe", "CWE-89?token=x", "1"),
    ("cwe", "CWE-89\n", "1"), ("cwe", "CWE-89\u202e", "1"),
    ("cwe", "CWE-0", "1"), ("cwe", "CWE-89", "\ud800"),
    ("cwe", "CWE-89", "\x01"), ("cwe", "CWE-89", "x" * 129),
    ("owasp-top10", "A03:2021", "2025"), ("owasp-top10", "A11:2021", "2021"),
])
def test_InvalidReferenceUrlControlAndUnicodeMetadataFailsClosed(fields):
    """Unsupported link identities cannot become credentials, traversal, or injected hyperlinks."""

    with pytest.raises(ValueError):
        ReportReference(*fields)


def test_ReferenceBindingsRequireActualFindingOwnershipAndLinkedEvidence():
    """A citation to another object or unrelated artifact cannot pretend to support a finding."""

    report = Fixture()
    binding = report.reference_bindings[0]
    host = report.state.Objects(ObjectKind.HOST)[0].Reference()
    evidence = replace(binding.provenance.evidence_references[0], sha256="b" * 64,
                       locator="blobs/sha256/" + "b" * 64)

    for context in (
        replace(binding, finding_reference=host),
        replace(binding, provenance=replace(binding.provenance, evidence_references=(evidence,))),
    ):
        with pytest.raises(ValueError, match="finding"):
            ReportSnapshot(report.state, (context,))

    with pytest.raises(ValueError, match="unique"):
        ReportSnapshot(report.state, (binding, binding))


@pytest.mark.parametrize("mutation", [
    "empty", "untyped", "duplicate", "relation", "no-evidence", "text",
])
def test_ReferenceContextRejectsMalformedOrUnattributedClaims(mutation):
    """Generic sequences, untyped values, and absent evidence cannot bypass context ownership."""

    binding = Fixture().reference_bindings[0]
    arguments = {}

    if mutation == "empty":
        arguments["references"] = ()

    elif mutation == "untyped":
        arguments["references"] = ({},)

    elif mutation == "duplicate":
        arguments["references"] = (binding.references[0],) * 2

    elif mutation == "relation":
        arguments["finding_reference"] = "relation:" + "a" * 64

    elif mutation == "no-evidence":
        arguments["provenance"] = replace(binding.provenance, evidence_references=())

    else:
        arguments["rationale"] = "\ud800"

    with pytest.raises(ValueError):
        replace(binding, **arguments)


def test_ReportIsImmutableAndByteVerificationCannotBeSuppliedByItsConstructor():
    """The pure constructor accepts neither a verified flag nor mutable context ownership."""

    report = Fixture()
    bindings = list(report.reference_bindings)
    frozen = ReportSnapshot(report.state, bindings)
    bindings.clear()

    assert frozen.reference_bindings == report.reference_bindings, "Caller mutation changed context"

    with pytest.raises(FrozenInstanceError):
        frozen.state = ModelState("other")

    with pytest.raises(TypeError):
        ReportSnapshot(report.state, _checked_evidence=report.EvidenceReferences())


def test_ReportContextAndCanonicalModelSizeLimitsFailBeforePublishing(monkeypatch):
    """Oversized model/context inputs cannot create an unbounded report projection."""

    report = Fixture()

    with pytest.raises(ValueError):
        ReportSnapshot(None)

    with pytest.raises(ValueError):
        ReportSnapshot(report.state, "all")

    with pytest.raises(ValueError):
        ReportSnapshot(report.state, ({},))

    with pytest.raises(ValueError):
        ReportSnapshot(report.state, report.reference_bindings * 1025)

    monkeypatch.setattr(reporting, "MAX_MODEL_BYTES", 1)

    with pytest.raises(ValueError, match="byte limit"):
        ReportSnapshot(report.state)


@pytest.mark.parametrize("exporter", EXPORTERS, ids=lambda function: function.__name__)
def test_AllFormatsEnforceTheFinalOutputByteLimit(monkeypatch, exporter):
    """Every artifact encoder uses the same finite bound rather than publishing partial output."""

    report = Fixture()
    monkeypatch.setattr(report_formats, "MAX_REPORT_BYTES", 1)

    with pytest.raises(ValueError, match="byte limit"):
        exporter(report)
