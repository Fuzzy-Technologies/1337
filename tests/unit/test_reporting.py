# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure report projections, strict display references, and hostile serialization boundaries."""

import json
from dataclasses import FrozenInstanceError, replace
from html.parser import HTMLParser
from xml.etree import ElementTree

import pytest

from fuzzy1337 import report_formats, reporting
from fuzzy1337.adapters.contracts import AdapterExecution, ExecutionState
from fuzzy1337.findings import ApplyFindings, Finding, FindingSeverity
from fuzzy1337.intelligence import IntelligenceFeed
from fuzzy1337.model import (
    CanonicalModelJson,
    LocalModelStore,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    Observation,
    Relation,
    RelationKind,
    SecurityObject,
)
from fuzzy1337.report_formats import RenderHtml, SerializeJson, SerializeJunit, SerializeSarif
from fuzzy1337.reporting import ReportReference, ReportSnapshot
from tests.contract.report_export_fixture import Context as ReportExportContext
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
        self.primary_text = []
        self.headingIds = set()
        self.tableLabels = []
        self.tableRegions = []
        self.disclosure_depth = 0
        self.style_depth = 0

    def handle_starttag(self, tag, attrs):
        """Record parsed attributes and targets, including decoded HTML entities."""

        self.tags.append(tag)

        if tag == "details":
            self.disclosure_depth += 1

        if tag == "style":
            self.style_depth += 1

        self.attributes.extend(attrs)
        fields = dict(attrs)

        if "id" in fields:
            self.ids.append(fields["id"])

            if tag in ("h2", "h3"):
                self.headingIds.add(fields["id"])

        if tag == "div" and fields.get("class") == "table":
            self.tableRegions.append(fields)

        if tag == "table":
            self.tableLabels.append(fields.get("aria-labelledby"))

        if tag == "a":
            self.links.append(fields["href"])

    def HandleData(self, data):
        """Record visible text for independent escaped-payload assertions."""

        self.text.append(data)

        if not self.disclosure_depth and not self.style_depth:
            self.primary_text.append(data)

    def handle_endtag(self, tag):
        """Track closed disclosures independently of their preserved technical content."""

        if tag == "details":
            self.disclosure_depth -= 1

        if tag == "style":
            self.style_depth -= 1

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


def test_JunitProjectsReportMetadataOnce(monkeypatch):
    """Reuse one canonical report projection for all three JUnit metadata properties."""

    report = Fixture()
    toDict = ReportSnapshot.ToDict
    expected = toDict(report)
    calls = 0

    def CountProjection(snapshot):
        """Count complete report projections while preserving their canonical fields."""

        nonlocal calls
        calls += 1

        return toDict(snapshot)

    monkeypatch.setattr(ReportSnapshot, "ToDict", CountProjection)
    root = ElementTree.fromstring(SerializeJunit(report))
    properties = {item.attrib["name"]: item.attrib["value"]
                  for item in root.findall("properties/property")}

    assert calls == 1, "JUnit repeated the complete report projection"
    assert properties["snapshot_sha256"] == report.SnapshotDigest()
    assert json.loads(properties["evidence_integrity"]) == expected["evidence_integrity"]
    assert json.loads(properties["execution_outcomes"]) == expected["execution_outcomes"]
    assert json.loads(properties["reference_context"]) == expected["reference_bindings"]


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


def test_HtmlTablesExposeNamedKeyboardScrollRegions():
    """Name each native table and its keyboard scroll region with the visible heading."""

    dom = Dom()
    dom.feed(RenderHtml(Fixture()).decode("utf-8"))
    labels = [region["aria-labelledby"] for region in dom.tableRegions]

    assert labels == [
        "operations-table-heading", "model-host-table-heading",
        "findings-severity-table-heading", "evidence-table-heading", "relationships-table-heading",
    ]
    assert dom.tableLabels == labels
    assert set(labels) <= dom.headingIds
    assert all(region.get("role") == "region" and region.get("tabindex") == "0"
               for region in dom.tableRegions)


def test_HtmlFindingsJumpToSavedDispositionGroups():
    """Expose populated dispositions with direct links and visible canonical finding cards."""

    report = Fixture()
    host, = report.state.Objects(ObjectKind.HOST)
    extra = Finding(host.Reference(), "synthetic.second-open", "stored",
                    "Second open finding", host.provenance)
    state, _ = ApplyFindings(report.state, (extra,))
    report = replace(report, state=state)
    rendered = RenderHtml(report).decode("utf-8")
    findingsHtml = rendered.split('<section id="findings">', 1)[1].split("</section>", 1)[0]
    findings = ElementTree.fromstring(f"<section>{findingsHtml}</section>")
    statuses = (("open", "Open (2)"), ("confirmed", "Confirmed (1)"),
                ("dismissed", "Dismissed (1)"), ("resolved", "Resolved (1)"))
    navigation = findings.find('nav[@aria-label="Finding dispositions"]')
    assert navigation is not None
    assert [(link.get("href"), link.text) for link in navigation.findall("a")] == [
        (f"#findings-{status}", label) for status, label in statuses
    ]
    assert [(heading.get("id"), heading.get("tabindex"), heading.text)
            for heading in findings.findall("h3")] == [
        (f"findings-{status}", "-1", label) for status, label in statuses
    ]

    expected = []
    entities = state.Objects(ObjectKind.FINDING)

    for status, _ in statuses:
        expected.append(("h3", f"findings-{status}"))
        expected.extend(("article", f"finding-{entity.Reference()[7:]}")
                        for entity in entities if entity.attributes["status"] == status)

    actual = [(element.tag, element.get("id")) for element in findings
              if element.tag in ("h3", "article")]
    assert actual == expected


def test_HtmlFindingIndexOrdersSavedSeverityAndRetainsSubjects():
    """Compare saved severities across dispositions with canonical ties and exact record links."""

    report = Fixture(summary="Retained interpretation <marker>")
    host, = report.state.Objects(ObjectKind.HOST)
    asset, = report.state.Objects(ObjectKind.ASSET)
    sourceRows = (
        (asset, FindingSeverity.CRITICAL), (asset, FindingSeverity.HIGH),
        (host, FindingSeverity.MEDIUM),
    )
    extra = tuple(Finding(
        subject.Reference(), "synthetic.severity-index", severity.value,
        f"{severity.value.title()} entry", subject.provenance, severity=severity,
    ) for subject, severity in sourceRows)
    state, _ = ApplyFindings(report.state, extra)
    rendered = RenderHtml(replace(report, state=state)).decode("utf-8")
    findingsHtml = rendered.split('<section id="findings">', 1)[1].split("</section>", 1)[0]
    findings = ElementTree.fromstring(f"<section>{findingsHtml}</section>")
    index, = findings.findall('details[@class="findings-severity-index"]')
    assert index.get("open") is None
    heading, = index.findall("summary/h3")
    assert heading.text == "Findings by saved severity"
    region, = index.findall('div[@role="region"]')
    assert (region.get("aria-labelledby"), region.get("tabindex")) == (heading.get("id"), "0")
    table, = region.findall("table")
    assert table.get("aria-labelledby") == heading.get("id")
    assert [(header.get("scope"), header.text) for header in table.findall("thead/tr/th")] == [
        ("col", "Finding"), ("col", "Saved severity"), ("col", "Disposition"), ("col", "Subject"),
    ]
    severityOrder = ("critical", "high", "medium", "low", "informational", "unknown")
    entities = state.Objects(ObjectKind.FINDING)
    ranked = [
        entity for severity in severityOrder for entity in entities
        if entity.attributes["severity"] == severity
    ]
    cardIds = {card.get("id") for card in findings.findall("article")}
    subjectLabels = {
        host.Reference(): "Host: 127.0.0.1", asset.Reference(): "Asset: build:synthetic",
    }

    for entry, entity in zip(table.findall("tbody/tr"), ranked, strict=True):
        title, severity, disposition, subject = entry
        assert (title.tag, title.get("scope")) == ("th", "row")
        findingLink, = title.findall("a")
        fragment = f"finding-{entity.Reference()[7:]}"
        assert (findingLink.get("href"), findingLink.text) == (
            f"#{fragment}", entity.attributes["summary"],
        )
        assert fragment in cardIds
        assert [severity.text, disposition.text] == [
            str(entity.attributes[field]).title() for field in ("severity", "status")
        ]
        reference = str(entity.attributes["subject_reference"])
        subjectLink, = subject.findall("a")
        assert (subjectLink.get("href"), subjectLink.text) == (
            f"#object-{reference[7:]}", subjectLabels[reference],
        )


def test_HtmlFindingIndexPaginatesAboveFiftyWithNativeDisclosures():
    """Keep the full finding cards alongside bounded, independently accessible index pages."""

    report = Fixture()
    host, = report.state.Objects(ObjectKind.HOST)
    detections = tuple(Finding(
        host.Reference(), "synthetic.index-boundary", f"stored-{ordinal}",
        "Retained finding", host.provenance, severity=FindingSeverity.HIGH,
    ) for ordinal in range(47))
    state, _ = ApplyFindings(report.state, detections[:-1])
    atLimit = RenderHtml(replace(report, state=state))
    assert b'name="findings-severity-pages"' not in atLimit
    assert b"data-paginated" not in atLimit

    state, _ = ApplyFindings(state, detections[-1:])
    rendered = RenderHtml(replace(report, state=state)).decode("utf-8")
    findingsHtml = rendered.split('<section id="findings">', 1)[1].split("</section>", 1)[0]
    findings = ElementTree.fromstring(f"<section>{findingsHtml}</section>")
    index, = findings.findall('details[@class="findings-severity-index"]')
    assert index.get("data-paginated") == "true"
    assert index.get("open") is None
    navigation, = index.findall('nav[@aria-label="Finding index row ranges"]')
    links = navigation.findall("a")
    assert [(link.get("href"), link.text) for link in links] == [
        ("#findings-severity-rows-1", "Rows 1–50"), ("#findings-severity-rows-51", "Row 51"),
    ]
    pages = index.findall('details[@name="findings-severity-pages"]')
    assert [page.get("open") for page in pages] == ["open", None]
    tables = []

    for link, page in zip(links, pages, strict=True):
        summary, = page.findall("summary")
        assert (summary.get("id"), summary.text) == (link.attrib["href"][1:], link.text)
        region, = page.findall('div[@role="region"]')
        table, = region.findall("table")
        assert region.get("tabindex") == "0"
        assert region.get("aria-labelledby") == table.get("aria-labelledby") == summary.get("id")
        tables.append(table)

    assert [len(table.findall("tbody/tr")) for table in tables] == [50, 1]
    entities = state.Objects(ObjectKind.FINDING)
    severities = ("high", "low", "informational", "unknown")
    expected = [
        f"#finding-{entity.Reference()[7:]}"
        for severity in severities for entity in entities
        if entity.attributes["severity"] == severity
    ]
    assert [link.get("href") for table in tables for link in table.findall("tbody/tr/th/a")] == (
        expected
    )
    assert tables[-1].findtext("tbody/tr/td") == "Unknown"
    assert {card.get("id") for card in findings.findall("article")} == {
        link[1:] for link in expected
    }
    stylesheet = rendered.split("<style>", 1)[1].split("</style>", 1)[0]
    assert "@media print {.findings-severity-index[data-paginated] {display:none}}" in stylesheet


def test_HtmlFiltersBySavedFindingSeverityIncludingUnknown():
    """Hide nonmatching cards and empty disposition groups through native fragment state."""

    report = Fixture()
    host, = report.state.Objects(ObjectKind.HOST)
    extra = Finding(host.Reference(), "synthetic.unknown", "saved",
                    "Another unknown finding", host.provenance)
    state, _ = ApplyFindings(report.state, (extra,))
    rendered = RenderHtml(replace(report, state=state)).decode("utf-8")
    findingsHtml = rendered.split('<section id="findings">', 1)[1].split("</section>", 1)[0]
    findings = ElementTree.fromstring(f"<section>{findingsHtml}</section>")
    filters, = findings.findall('nav[@aria-labelledby="finding-severity-filter-label"]')
    assert filters.get("hidden") == "hidden"
    assert filters.findtext('span[@id="finding-severity-filter-label"]') == (
        "Filter by saved severity"
    )
    assert [(link.get("href"), link.text) for link in filters.findall("a")] == [
        ("#findings", "All (5)"),
        ("#findings-severity-high", "High (1)"),
        ("#findings-severity-low", "Low (1)"),
        ("#findings-severity-informational", "Informational (1)"),
        ("#findings-severity-unknown", "Unknown (2)"),
    ]
    selected, = findings.findall('p[@id="findings-severity-unknown"]')
    assert (selected.get("tabindex"), selected.get("hidden")) == ("-1", "hidden")
    assert selected.text.startswith("Showing Unknown (2).")
    assert {card.get("id"): card.get("data-finding-severities")
            for card in findings.findall("article")} == {
        f"finding-{entity.Reference()[7:]}": entity.attributes["severity"]
        for entity in state.Objects(ObjectKind.FINDING)
    }
    assert [heading.get("id") for heading in findings.findall("h3")
            if "unknown" in heading.attrib["data-finding-severities"].split()] == [
        "findings-open", "findings-confirmed"
    ]
    stylesheet = rendered.split("<style>", 1)[1].split("</style>", 1)[0]
    unknownSelector = (
        '#findings-severity-unknown:target ~ [data-finding-severities]'
        ':not([data-finding-severities~="unknown"])'
    )
    defaults, guard, conditional = stylesheet.partition(
        f"@media screen {{\n@supports selector({unknownSelector}) {{\n"
    )
    assert guard
    assert ".finding-severity-filter[hidden] {display:none}" in defaults
    assert ".finding-severity-selection[hidden] {display:none}" in defaults
    screenRules, closing, tail = conditional.partition("\n}\n}\n")
    assert closing and not tail
    for rule in (
        ".finding-severity-filter[hidden] {display:flex}",
        ".finding-severity-selection[hidden]:target {display:block}",
        f"{unknownSelector} {{display:none}}",
    ):
        assert rule not in defaults and rule in screenRules


@pytest.mark.parametrize("verify,expectedIntegrity", [
    (False, "not verified"), (True, "verified bytes"),
], ids=["unverified", "verified"])
def test_HtmlFindingLinkResolvesToEvidenceRowWithScopedHeaders(tmp_path, verify, expectedIntegrity):
    """Match a finding's evidence number to its highlighted row and byte-integrity context."""

    workspaceRoot, records = ReportExportContext(tmp_path, findings=False)
    store = LocalModelStore(workspaceRoot)
    state = store.Open()
    host, = state.Objects(ObjectKind.HOST)
    reference = records[1].reference
    provenance = replace(host.provenance[0], run_reference=records[1].evidence_id,
                         evidence_references=(reference,))
    finding = Finding(host.Reference(), "synthetic.evidence-row", "stored",
                      "Retained interpretation", (provenance,))
    state, delta = ApplyFindings(state, (finding,))
    store.Save(state, expected_revision=delta.previous_revision)
    report = ReportSnapshot(store.Open())

    if verify:
        report = reporting.VerifyReportEvidence(report, workspaceRoot)

    rendered = RenderHtml(report).decode("utf-8")
    findingsHtml = rendered.split('<section id="findings">', 1)[1].split("</section>", 1)[0]
    findings = ElementTree.fromstring(f"<section>{findingsHtml}</section>")
    link, = (anchor for anchor in findings.findall("article//a")
             if anchor.attrib["href"].startswith("#evidence-"))
    fragment = link.attrib["href"][1:]
    evidenceHtml = rendered.split('<section id="evidence">', 1)[1].split("</section>", 1)[0]
    tableHtml = evidenceHtml.split('aria-labelledby="evidence-table-heading">', 1)[1]
    table = ElementTree.fromstring(tableHtml.split("</table>", 1)[0] + "</table>")
    columns = ("Evidence", "Role", "Size", "Integrity", "Technical reference")
    assert [(cell.tag, cell.get("scope"), cell.text) for cell in table.findall("thead/tr/*")] == [
        ("th", "col", label) for label in columns
    ]
    assert len(table.findall("tbody/tr")) == 2
    row = table.find(f'tbody/tr[@id="{fragment}"]')
    assert row is not None
    identity, role, size, integrity, details = row
    assert (identity.tag, identity.get("scope"), identity.text) == ("th", "row", "Evidence 2")
    assert link.text == f"{identity.text}: {reference.role}", (
        "The finding link must display the evidence row number and role"
    )
    assert [cell.tag for cell in (role, size, integrity, details)] == ["td"] * 4
    assert (role.text, size.text, integrity.text) == (
        reference.role, f"{reference.size_bytes} bytes", expectedIntegrity,
    )
    assert details.findtext("details/pre") == CanonicalModelJson(reference).decode("utf-8")
    stylesheet = rendered.split("<style>", 1)[1].split("</style>", 1)[0]
    assert (
        '@media screen {#evidence tbody tr:target > * {background:#15212b}\n'
        '#evidence tbody tr:target > th[scope="row"] '
        '{outline:2px solid var(--cyan);outline-offset:-2px}}\n'
        in stylesheet
    ), "The linked evidence row needs a visible screen-only marker"


def test_HtmlCalculatesCanonicalSnapshotDigestOnce(monkeypatch):
    """Display the exact retained snapshot identity with one digest calculation per render."""

    report = Fixture()
    snapshotDigest = ReportSnapshot.SnapshotDigest
    expected = snapshotDigest(report)
    calls = 0

    def CountSnapshotDigest(snapshot):
        """Count digest calculations while using the real canonical model serializer."""

        nonlocal calls
        calls += 1

        return snapshotDigest(snapshot)

    monkeypatch.setattr(ReportSnapshot, "SnapshotDigest", CountSnapshotDigest)

    assert f"<code>{expected}</code>".encode() in RenderHtml(report)
    assert calls == 1, "HTML recalculated the canonical snapshot digest"


def test_HtmlReusesEvidenceFragmentsByCompleteReference(monkeypatch):
    """Share anchors while keeping distinct roles and row labels for the same artifact."""

    report = Fixture()
    reference, = report.EvidenceReferences()
    alternate = replace(reference, role="stderr")
    host, = report.state.Objects(ObjectKind.HOST)
    provenance = replace(
        host.provenance[0], source_id="native.web-check",
        evidence_references=(reference, alternate),
        execution=AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.1),
    )
    endpoint = SecurityObject(
        ObjectIdentity("synthetic", ObjectKind.ENDPOINT, "http://127.0.0.1/"), {}, (provenance,),
    )
    observation = Observation(
        "native.web-response-check", endpoint.Reference(),
        {"check_id": "native.html-reflection", "matched": False}, provenance,
    )
    state, _ = report.state.Apply(objects=(endpoint,), observations=(observation,))
    finding = Finding(endpoint.Reference(), "synthetic.shared-evidence", "stored",
                      "Retained evidence with two roles", (provenance,))
    state, _ = ApplyFindings(state, (finding,))
    report = replace(report, state=state)
    evidenceId = report_formats.EvidenceId
    fragments = {item: evidenceId(item) for item in (reference, alternate)}
    calls = []

    def CountEvidenceId(item):
        """Count calculations while preserving canonical fragment generation."""

        calls.append(item)

        return evidenceId(item)

    monkeypatch.setattr(report_formats, "EvidenceId", CountEvidenceId)
    payload = RenderHtml(report)
    assert RenderHtml(report) == payload
    rendered = payload.decode("utf-8")
    dom = Dom()
    dom.feed(rendered)
    assert len(set(fragments.values())) == 2

    expected = ((1, alternate, 1), (2, reference, len(state.Objects(ObjectKind.FINDING))))

    for index, item, findingLinks in expected:
        fragment = fragments[item]
        assert dom.ids.count(fragment) == 1
        assert f'<a href="#{fragment}">{item.role}</a>' in rendered
        label = f'<a href="#{fragment}">Evidence {index}: {item.role}</a>'
        assert rendered.count(label) == findingLinks, (
            "Each finding link must use the display number for its complete evidence reference"
        )
        assert dom.links.count(f"#{fragment}") == findingLinks + 1, (
            "Finding and operation links must target the evidence row for their retained role"
        )

    assert len(calls) == 4 and all(calls.count(item) == 2 for item in fragments), (
        "Each full evidence reference must have one identity calculation per render"
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



def test_HtmlExplainsFindingsAndRemediationWithoutOpeningTechnicalDisclosures():
    """Human interpretation, subject and next action are readable before viewing raw metadata."""

    report = Fixture()
    dom = Dom()
    dom.feed(RenderHtml(report).decode("utf-8"))
    visible = " ".join(dom.primary_text)

    for expected in (
        "Result at a glance", "Open or confirmed findings need attention",
        "Synthetic check interpretation", "Host: 127.0.0.1", "What to do next",
        "Review the synthetic fixture", "Inspect local evidence", "did not succeed",
        "Marked resolved by an operator", "successful retesting is not established",
        "Scan completeness was not assessed", "Recorded source", "synthetic",
    ):
        assert expected in visible, f"Readable explanation was omitted: {expected}"

    assert "a" * 64 not in visible and report.SnapshotDigest() not in visible, (
        "Raw evidence and snapshot digests must remain inside technical disclosures"
    )
    assert "object:" not in visible and '"schema_version"' not in visible, (
        "Canonical identifiers and JSON must not replace readable report content"
    )
    assert "failed; exit 2" in visible, "Readable outcome must retain the actual failed execution"



def test_EmptyHtmlExplainsUnknownCoverageAndDoesNotSuggestASecureTarget():
    """Empty state distinguishes missing result records from a successful vulnerability check."""

    dom = Dom()
    dom.feed(RenderHtml(ReportSnapshot(ModelState("empty"))).decode("utf-8"))
    visible = " ".join(dom.primary_text)

    assert "Zero findings do not establish that a target is secure" in visible, (
        "An empty report must not imply that any vulnerability checks passed"
    )
    assert "No execution outcomes were retained" in visible, "Missing execution must remain unknown"
    assert "opening this report does not perform one" in visible, "Export cannot imply execution"
    assert "No objects of this kind were retained" in visible, "Missing inventory must be explicit"
    assert [region["aria-labelledby"] for region in dom.tableRegions] == [
        "evidence-table-heading", "relationships-table-heading",
    ]



def test_HtmlInventoryShowsRetainedFieldsAndKeepsUntrustedAddressesInert():
    """Hosts, ports, services and addresses are readable records rather than inferred findings."""

    original = Fixture()
    provenance = original.state.Objects(ObjectKind.HOST)[0].provenance
    objects = (
        SecurityObject(ObjectIdentity("synthetic", ObjectKind.PORT, "127.0.0.1/tcp/8080"),
                       {"protocol": "tcp", "number": 8080, "state": "open"}, provenance),
        SecurityObject(ObjectIdentity("synthetic", ObjectKind.SERVICE, "owned-http"),
                       {"name": "http", "version": {"unparsed": "unknown"}}, provenance),
        SecurityObject(ObjectIdentity("synthetic", ObjectKind.ENDPOINT,
                       "https://untrusted.invalid/<script>inert</script>"),
                       {"method": "GET", "status": 302}, provenance),
    )
    state, _ = original.state.Apply(objects=objects)
    rendered = RenderHtml(replace(original, state=state)).decode("utf-8")
    dom = Dom()
    dom.feed(rendered)
    visible = " ".join(dom.primary_text)

    for expected in ("Hosts (1)", "Ports (1)", "Services (1)", "Web addresses (1)",
                     "8080", "tcp", "http", "GET", "302 Found", "Not recorded"):
        assert expected in visible, f"Retained inventory field was not readable: {expected}"

    assert "script" not in dom.tags, "An untrusted inventory identity must stay escaped"
    assert not any("untrusted.invalid" in link for link in dom.links), (
        "Retained endpoint addresses cannot become arbitrary clickable external URLs"
    )
    assert all(link[1:] in dom.ids for link in dom.links if link.startswith("#")), (
        "Readable inventory lost a canonical object anchor"
    )
    labels = [region["aria-labelledby"] for region in dom.tableRegions]
    assert labels == [
        "operations-table-heading", "model-host-table-heading", "model-port-table-heading",
        "model-service-table-heading", "model-endpoint-table-heading",
        "findings-severity-table-heading", "evidence-table-heading",
        "relationships-table-heading",
    ]
    assert dom.tableLabels == labels
    assert set(labels) <= dom.headingIds

    expected = {
        ObjectKind.HOST: (("Address", "Reported state"), ("Not recorded", "reported")),
        ObjectKind.PORT: (("Protocol", "Number", "Reported state"), ("tcp", "8080", "open")),
        ObjectKind.SERVICE: (("Name", "Version"), ("http", "Not recorded")),
        ObjectKind.ENDPOINT: (("Method", "HTTP status"), ("GET", "302 Found")),
    }

    for kind, (columns, values) in expected.items():
        tableHtml = rendered.split(f'aria-labelledby="model-{kind.value}-table-heading">', 1)[1]
        table = ElementTree.fromstring(tableHtml.split("</table>", 1)[0] + "</table>")
        columnHeaders = table.findall("thead/tr/*")
        assert [(cell.tag, cell.get("scope"), cell.text) for cell in columnHeaders] == [
            ("th", "col", column) for column in ("Saved identity", *columns, "Findings", "Details")
        ]
        entity, = state.Objects(kind)
        row, = table.findall("tbody/tr")
        identity, *cells = row
        assert row.get("id") == f"object-{entity.Reference()[7:]}"
        assert (identity.tag, identity.get("scope"), identity.text) == (
            "th", "row", entity.identity.key,
        )
        assert [cell.tag for cell in cells] == ["td"] * (len(values) + 2)
        assert [cell.text for cell in cells[:-2]] == list(values)


def test_HtmlPortsOrderRetainedIntegersWithCanonicalTies():
    """Order saved integer ports while preserving retained display values and links."""

    report = Fixture()
    host, = report.state.Objects(ObjectKind.HOST)
    ports = tuple(SecurityObject(
        ObjectIdentity("synthetic", ObjectKind.PORT, f"127.0.0.1/{key}"),
        attributes, host.provenance,
    ) for key, attributes in (
        ("tcp/8080", {"protocol": "tcp", "number": 8080}),
        ("tcp/80", {"protocol": "tcp", "number": 80}),
        ("udp/443", {"protocol": "udp", "number": 443}),
        ("tcp/443", {"protocol": "tcp", "number": 443}),
        ("tcp/53", {"protocol": "tcp", "number": "53"}),
        ("tcp/21", {"protocol": "tcp"}),
        ("tcp/7", {"protocol": "tcp", "number": True}),
    ))
    state, _ = report.state.Apply(objects=ports)
    finding = Finding(ports[2].Reference(), "synthetic.port-order", "saved", "Port finding",
                      host.provenance)
    state, _ = ApplyFindings(state, (finding,))
    rendered = RenderHtml(replace(report, state=state)).decode("utf-8")
    modelHtml = rendered.split('<section id="model">', 1)[1].split("</section>", 1)[0]
    model = ElementTree.fromstring(f"<section>{modelHtml}</section>")
    table, = model.findall('.//table[@aria-labelledby="model-port-table-heading"]')
    numberHeader, = table.findall('thead/tr/th[@aria-sort="ascending"]')
    assert numberHeader.text == "Number"
    canonical = state.Objects(ObjectKind.PORT)
    ties = [entity for entity in canonical if entity.attributes.get("number") == 443]
    other = [entity for entity in canonical if type(entity.attributes.get("number")) is not int]
    expected = [ports[1], *ties, ports[0], *other]
    portRows = table.findall("tbody/tr")
    assert [(row.get("id"), row.findtext("th")) for row in portRows] == [
        (f"object-{entity.Reference()[7:]}", entity.identity.key) for entity in expected
    ]
    assert [row.findall("td")[1].text for row in portRows] == [
        "80", "443", "443", "8080",
        *(str(entity.attributes.get("number", "Not recorded")) for entity in other),
    ]
    ownerRow, = table.findall(f'.//tr[@id="object-{ports[2].Reference()[7:]}"]')
    findingLink, = ownerRow.findall("td/ul/li/a")
    fragment = f"finding-{finding.ToObject(state.workspace_id).Reference()[7:]}"
    assert findingLink.get("href") == f"#{fragment}"
    assert f'id="{fragment}"' in rendered


def test_HtmlWebAddressesOrderSavedHttpStatuses():
    """Bring recorded HTTP errors together while preserving unknowns and finding links."""

    report = Fixture()
    host, = report.state.Objects(ObjectKind.HOST)
    endpoints = tuple(SecurityObject(
        ObjectIdentity("synthetic", ObjectKind.ENDPOINT, f"https://synthetic.invalid/{path}"),
        attributes, host.provenance,
    ) for path, attributes in (
        ("ok", {"status": 200}),
        ("client-error", {"status": 404}),
        ("server-error-a", {"status": 503}),
        ("server-error-b", {"status": 503}),
        ("text-status", {"status": "502"}),
        ("missing-status", {}),
        ("boolean-status", {"status": False}),
    ))
    state, _ = report.state.Apply(objects=endpoints)
    finding = Finding(endpoints[2].Reference(), "synthetic.endpoint-order", "saved",
                      "Endpoint finding", host.provenance)
    state, _ = ApplyFindings(state, (finding,))
    rendered = RenderHtml(replace(report, state=state)).decode("utf-8")
    modelHtml = rendered.split('<section id="model">', 1)[1].split("</section>", 1)[0]
    model = ElementTree.fromstring(f"<section>{modelHtml}</section>")
    table, = model.findall('.//table[@aria-labelledby="model-endpoint-table-heading"]')
    statusHeader, = table.findall('thead/tr/th[@aria-sort="descending"]')
    assert statusHeader.text == "HTTP status"
    canonical = state.Objects(ObjectKind.ENDPOINT)
    ties = [entity for entity in canonical if entity.attributes.get("status") == 503]
    other = [entity for entity in canonical if type(entity.attributes.get("status")) is not int]
    expected = [*ties, endpoints[1], endpoints[0], *other]
    endpointRows = table.findall("tbody/tr")
    assert [(row.get("id"), row.findtext("th")) for row in endpointRows] == [
        (f"object-{entity.Reference()[7:]}", entity.identity.key) for entity in expected
    ]
    assert [row.findall("td")[1].text for row in endpointRows] == [
        "503 Service Unavailable", "503 Service Unavailable", "404 Not Found", "200 OK",
        *(str(entity.attributes.get("status", "Not recorded")) for entity in other),
    ]
    ownerRow, = table.findall(f'.//tr[@id="object-{endpoints[2].Reference()[7:]}"]')
    findingLink, = ownerRow.findall("td/ul/li/a")
    fragment = f"finding-{finding.ToObject(state.workspace_id).Reference()[7:]}"
    assert findingLink.get("href") == f"#{fragment}"
    assert f'id="{fragment}"' in rendered


def test_HtmlAssetTypesJumpToPopulatedInventoryGroups():
    """Give each populated inventory group a counted, keyboard-focusable fragment target."""

    report = Fixture()
    host, = report.state.Objects(ObjectKind.HOST)
    endpoints = tuple(SecurityObject(
        ObjectIdentity("synthetic", ObjectKind.ENDPOINT, address), {}, host.provenance,
    ) for address in ("https://first.invalid/", "https://second.invalid/"))
    state, _ = report.state.Apply(objects=endpoints)
    rendered = RenderHtml(replace(report, state=state)).decode("utf-8")
    inventoryHtml = rendered.split('<section id="model">', 1)[1].split("</section>", 1)[0]
    inventory = ElementTree.fromstring(f"<section>{inventoryHtml}</section>")
    groups = (
        ("model-host-table-heading", "Hosts (1)"),
        ("model-endpoint-table-heading", "Web addresses (2)"),
        ("model-other-objects-heading", "Other retained objects (1)"),
    )
    navigation, = inventory.findall('nav[@aria-label="Asset types"]')

    assert [(link.get("href"), link.text) for link in navigation.findall("a")] == [
        (f"#{headingId}", label) for headingId, label in groups
    ]

    for headingId, label in groups:
        heading, = inventory.findall(f'h3[@id="{headingId}"]')
        assert (heading.get("tabindex"), heading.text) == ("-1", label)

    assert inventory.findtext('h3[@id="model-port-table-heading"]') == "Ports (0)"
    assert inventory.findtext('h3[@id="model-service-table-heading"]') == "Services (0)"
    assert b'aria-label="Asset types"' not in RenderHtml(ReportSnapshot(ModelState("empty")))


def test_HtmlAssetFindingsUseExactSavedSubjects():
    """Links and filtering use exact saved subjects across shared labels and relations."""

    summary = "Saved interpretation <script>inert</script>"
    report = Fixture(summary=summary)
    host, = report.state.Objects(ObjectKind.HOST)
    asset, = report.state.Objects(ObjectKind.ASSET)
    address = "https://inventory.invalid/"
    endpoint = SecurityObject(
        ObjectIdentity("synthetic", ObjectKind.ENDPOINT, address), {}, host.provenance,
    )
    service = SecurityObject(
        ObjectIdentity("synthetic", ObjectKind.SERVICE, address), {}, host.provenance,
    )
    otherEndpoint = SecurityObject(
        ObjectIdentity("synthetic", ObjectKind.ENDPOINT, address + "other"), {}, host.provenance,
    )
    relation = Relation(
        RelationKind.RELATED_TO, service.Reference(), endpoint.Reference(),
        provenance=host.provenance,
    )
    state, _ = report.state.Apply(objects=(endpoint, service, otherEndpoint), relations=(relation,))
    state, _ = ApplyFindings(state, tuple(
        Finding(subject.Reference(), "synthetic.test-check", "tcp/443", summary, host.provenance)
        for subject in (endpoint, asset)
    ))
    rendered = RenderHtml(replace(report, state=state)).decode("utf-8")
    inventoryHtml = rendered.split('<section id="model">', 1)[1].split("</section>", 1)[0]
    findingsHtml = rendered.split('<section id="findings">', 1)[1].split("</section>", 1)[0]
    inventory = ElementTree.fromstring(f"<section>{inventoryHtml}</section>")
    findings = ElementTree.fromstring(f"<section>{findingsHtml}</section>")
    cards = {f"#{card.get('id')}": card for card in findings.findall("article")}
    entities = state.Objects(ObjectKind.FINDING)

    assert len(cards) == len(entities)
    assert inventory.find(".//script") is None
    filters, = inventory.findall('nav[@aria-labelledby="asset-findings-filter-label"]')
    assert filters.get("hidden") == "hidden"
    assert [(link.get("href"), link.text) for link in filters.findall("a")] == [
        ("#model", "All (5)"), ("#assets-with-findings", "With findings (3)"),
        ("#assets-without-findings", "Without findings (2)"),
    ]
    withFindings, = inventory.findall('p[@id="assets-with-findings"]')
    withoutFindings, = inventory.findall('p[@id="assets-without-findings"]')
    assert (withFindings.get("hidden"), withFindings.get("tabindex")) == ("hidden", "-1")
    assert (withoutFindings.get("hidden"), withoutFindings.get("tabindex")) == ("hidden", "-1")
    assert withoutFindings.text == (
        "Showing 2 of 5 objects without retained findings for manual review. "
        "Security and check coverage remain unassessed. Group counts describe the full snapshot."
    )
    withSelector = (
        "#model:has(> #assets-with-findings:target) [data-asset-findings]"
        ':not([data-asset-findings="present"])'
    )
    withoutSelector = (
        "#model:has(> #assets-without-findings:target) [data-asset-findings]"
        ':not([data-asset-findings="none"])'
    )
    guard = (
        f"@media screen {{\n@supports selector({withSelector})\n"
        f"    and selector({withoutSelector}) {{\n"
    )
    defaults, guardStart, conditional = rendered.partition(guard)
    assert guardStart
    assert ".asset-findings-filter[hidden],.asset-findings-selection[hidden] {display:none}" in (
        defaults
    )
    screenRules = conditional.split("\n}\n}\n", 1)[0]
    assert f"{withSelector} {{display:none}}" in screenRules
    assert f"{withoutSelector} {{display:none}}" in screenRules

    for subject in (host, endpoint, asset):
        reference = subject.Reference()
        objectId = f"object-{reference[7:]}"
        entry, = (inventory.findall(f'.//tr[@id="{objectId}"]')
                  + inventory.findall(f'.//details[@id="{objectId}"]/..'))
        assert entry.get("data-asset-findings") == "present"
        expected = [
            (
                f"#finding-{entity.Reference()[7:]}",
                f"{summary} · {entity.attributes['status']} · {entity.attributes['location_key']}",
            )
            for entity in entities if entity.attributes["subject_reference"] == reference
        ]
        links = inventory.findall(f'.//tr[@id="{objectId}"]/td/ul/li/a')
        links += inventory.findall(f'.//details[@id="{objectId}"]/../ul/li/a')
        assert [(link.get("href"), link.text) for link in links] == expected

        for fragment, _ in expected:
            card = cards[fragment]
            assert card.get("tabindex") == "-1"
            assert card.findtext("h4") == summary
            assert card.find("p/a").get("href") == f"#{objectId}"

    serviceRow = inventory.find(f'.//tr[@id="object-{service.Reference()[7:]}"]')
    assert serviceRow is not None
    assert serviceRow.get("data-asset-findings") == "none"
    assert serviceRow.findall("td")[-2].text == "None retained"
    assert serviceRow.findall(".//a") == []
    assert inventory.find('h3[@id="model-service-table-heading"]').get("data-asset-findings") == (
        "none"
    )
    assert inventory.find('div[@aria-labelledby="model-service-table-heading"]').get(
        "data-asset-findings"
    ) == "none"
    assert inventory.find(f'.//tr[@id="object-{otherEndpoint.Reference()[7:]}"]').get(
        "data-asset-findings"
    ) == "none"
    endpointHeading, = inventory.findall('h3[@id="model-endpoint-table-heading"]')
    assert endpointHeading.get("data-asset-findings") is None
    assert inventory.find('div[@aria-labelledby="model-endpoint-table-heading"]').get(
        "data-asset-findings"
    ) is None


def test_RetainedReportRowsIndexEveryObservationOnceAndPreserveItsOwner(monkeypatch):
    """Keep canonical order, missing asset fields and distinct finding evidence attribution."""

    state = Fixture().state
    asset = state.Objects(ObjectKind.ASSET)[0]
    entities = state.Objects(ObjectKind.FINDING)
    directProvenance = next(record for record in entities[0].provenance
                            if record.evidence_references)
    directEvidence = directProvenance.evidence_references[0]
    secondEntity = entities[1]
    secondEvidence = replace(directEvidence, role="second-finding")
    secondProvenance = replace(directProvenance, evidence_references=(secondEvidence,))
    secondWithEvidence = replace(secondEntity, provenance=(secondProvenance,))
    state = replace(state, objects=tuple(
        secondWithEvidence if entity == secondEntity else entity for entity in state.objects
    ))
    entities = state.Objects(ObjectKind.FINDING)
    sourceEvidence = replace(directEvidence, role="source-assertion")
    attribution = replace(directProvenance, evidence_references=(sourceEvidence,))
    source = Observation("finding-intelligence", entities[0].Reference(), {
        "source_assertions": [
            {"association_state": "candidate", "record": {"feed": IntelligenceFeed.CVE.value,
                "data": {"cvss": [{"base_score": None}]}}},
            {"association_state": "candidate", "record": {"feed": IntelligenceFeed.EPSS.value,
                "data": {"probability": 0.12}}},
        ],
    }, attribution)
    assetObservation = Observation("asset-inventory", asset.Reference(), {}, attribution)
    state, _ = state.Apply(observations=(source, assetObservation))
    expected = {
        entity.Reference(): tuple(item for item in state.observations
                                  if item.subject_reference == entity.Reference())
        for entity in entities
    }
    subjectReads = 0
    original = Observation.__getattribute__

    def CountSubjectReads(observation, fieldName):
        """Count only canonical subject lookups during the row projection."""

        nonlocal subjectReads

        if fieldName == "subject_reference":
            subjectReads += 1

        return original(observation, fieldName)

    with monkeypatch.context() as counting:
        counting.setattr(Observation, "__getattribute__", CountSubjectReads)
        rows = reporting._ProjectRetainedReportRows(state)

    assert subjectReads == len(state.observations), "Projection rescanned observation history"
    assert tuple(rows.objects.values()) == state.objects, "Canonical object order changed"
    assert rows.assetsByKind[ObjectKind.ASSET] == ((asset.Reference(), asset),), (
        "Asset projection changed canonical identity, provenance or missing fields"
    )
    assert tuple(row.entity for row in rows.findings) == entities, "Finding order changed"
    assert {row.reference: row.observations for row in rows.findings} == expected, (
        "Finding history lost its canonical order or acquired observations from another object"
    )
    assert rows.findings[0].evidence == (directEvidence,), "Direct evidence linkage changed"
    assert rows.findings[1].evidence == (secondEvidence,), "Evidence crossed finding boundaries"
    retainedSource = next(item for item in rows.findings[0].observations
                          if item.kind == "finding-intelligence")
    assert retainedSource.attributes == source.attributes, "Candidate source assertion changed"
    assert retainedSource.provenance.evidence_references == (sourceEvidence,), (
        "Source evidence was blended with direct finding evidence"
    )



def test_HtmlNativeResponseRowsRequireAttributedEvidenceAndAnExactObservation():
    """Keep failed or ambiguous native response records in technical history only."""

    report = Fixture()
    host = report.state.Objects(ObjectKind.HOST)[0]
    attributed = replace(host.provenance[0], source_id="native.web-check",
                         execution=AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.1))
    endpoint = SecurityObject(ObjectIdentity("synthetic", ObjectKind.ENDPOINT,
                                             "http://127.0.0.1/<script>inert</script>"), {},
                              (attributed,))
    lexical = {"check_id": "native.html-reflection", "matched": False}
    records = (
        Observation("native.web-response-check", endpoint.Reference(), lexical, attributed),
        Observation("native.web-response-check", endpoint.Reference(),
                    {"check_id": "native.html-reflection", "matched": 1}, attributed),
        Observation("native.web-response-check", endpoint.Reference(),
                    {"check_id": "native.sql-boolean-sample"}, attributed),
        Observation("native.web-response-check", host.Reference(), lexical, attributed),
        Observation("native.web-response-check", endpoint.Reference(), lexical, host.provenance[0]),
        Observation("native.web-response-check", endpoint.Reference(), lexical,
                    replace(attributed, evidence_references=())),
        Observation("native.web-response-check", endpoint.Reference(), lexical,
                    replace(attributed, execution=host.provenance[0].execution)),
    )
    state, _ = report.state.Apply(objects=(endpoint,), observations=records)
    dom = Dom()
    dom.feed(RenderHtml(replace(report, state=state)).decode("utf-8"))
    visible = " ".join(dom.primary_text)

    assert visible.count("Lexical marker not observed") == 1, (
        "Only the exact native negative observation belongs in the readable rows."
    )
    assert "Response captured; assessment pending" not in visible, (
        "An absent match field must not be displayed as a SQL sample."
    )
    assert "script" not in dom.tags and all(
        link[1:] in dom.ids for link in dom.links if link.startswith("#")
    ), "Native response subject labels must stay inert and all evidence links must resolve."
    assert any(region.get("aria-labelledby") == "native-response-table-heading"
               and region.get("tabindex") == "0" for region in dom.tableRegions)
    assert "native-response-table-heading" in dom.headingIds
    assert dom.tableLabels == [region["aria-labelledby"] for region in dom.tableRegions]


def IntelReport(assertions, *, unmatched=None):
    """Attach explicit synthetic retained assertion metadata to one existing finding."""

    report = Fixture()
    entity = report.state.Objects(ObjectKind.FINDING)[0]
    observation = Observation("finding-intelligence", entity.Reference(), {
        "source_assertions": assertions, "unmatched_identifiers": unmatched or [],
    }, entity.provenance[0])
    state, _ = report.state.Apply(observations=(observation,))

    return replace(report, state=state)



def test_HtmlIntelExplainsDistinctSourceMeaningsWithoutChangingFindingState():
    """Readable source meanings keep provenance and unknown target applicability separate."""

    assertions = []

    for feed, data in (
        (IntelligenceFeed.CVE.value, {
            "state": "PUBLISHED", "description": "Synthetic affected product description",
            "cvss": [{"version": "3.1", "base_score": 9.8, "assessor": "CNA"}],
        }),
        (IntelligenceFeed.KEV.value, {
            "name": "Synthetic vulnerability", "required_action": "Apply vendor guidance",
        }),
        (IntelligenceFeed.EPSS.value, {"probability": 0.12, "percentile": 0.91}),
        (IntelligenceFeed.CWE.value, {"name": "Synthetic weakness", "status": "Draft"}),
    ):
        assertions.append({
            "record": {"feed": feed, "identifier": "CVE-2025-12345", "catalog_version": "v1",
                       "effective_at": "2026-10-13T00:00:00Z", "data": data},
            "source": {"publisher": "Synthetic publisher", "origin": "synthetic"},
            "association_state": "candidate",
            "stale": feed == IntelligenceFeed.EPSS.value,
        })

    report = IntelReport(assertions, unmatched=["CVE-2025-99999"])
    before = SerializeJson(report)
    dom = Dom()
    dom.feed(RenderHtml(report).decode("utf-8"))
    visible = " ".join(dom.primary_text)

    for expected in (
        "CVE-2025-99999", "Synthetic affected product description", "9.8/10", "CNA",
        "Source required action", "Apply vendor guidance", "known exploitation",
        "not a probability of compromise for this target", "0.12", "0.91", "Synthetic weakness",
        "Target applicability: not determined", "candidate", "stale", "Synthetic publisher",
        "Source origin: synthetic", "FuzzyRoutines",
    ):
        assert expected in visible, f"Human intelligence explanation lost a source fact: {expected}"

    assert SerializeJson(report) == before, "Human interpretation must not mutate the report model"
    assert "does not prove that this target is affected" in visible, (
        "A source association cannot manufacture a target applicability decision"
    )



@pytest.mark.parametrize("assertions,expected", [
    (None, "Readable source details are unavailable"),
    ([None], "Unsupported assertion structure"),
    ([{"record": {"data": None}}], "Readable assertion fields were not retained"),
    ([{"record": {"data": {}, "feed": "unsupported"}}], "Association: Unknown"),
    ([{"record": {"data": {"cvss": [None]}, "feed": IntelligenceFeed.CVE.value}}],
     "Source state: Unknown"),
])
def test_HtmlIntelPreservesUnsupportedOrMissingAssertionFieldsAsUnknown(assertions, expected):
    """An arbitrary observation cannot create trusted facts or crash the readable rendering."""

    dom = Dom()
    dom.feed(RenderHtml(IntelReport(assertions)).decode("utf-8"))
    visible = " ".join(dom.primary_text)

    assert expected in visible, "Missing or unsupported fields need an explicit explanation"
    assert "Target applicability: affected" not in visible, (
        "Malformed or missing intelligence data cannot become a target verdict"
    )


@pytest.mark.parametrize("value,label", [(0.0, "Very low"), (5.0, "Medium"), (10.0, "Very high"),
                                        (None, "Unknown"), (True, "Unknown"), (-1, "Unknown")])
def test_HtmlScaleUsesExplicitCvssInputsAndKeepsMissingScoresUnknown(value, label):
    """The actual consumer renders five library memberships without manufacturing a source score."""

    dom = Dom()
    dom.feed(report_formats.SeverityScale(value))
    visible = " ".join(dom.primary_text)

    assert label in visible, "CVSS input must retain its expected UFS linguistic level"
    assert "Membership grades are not probabilities" in visible, (
        "The HTML must explain the scientific meaning of the displayed membership grades"
    )
    assert "conventional CVSS severity labels have a separate definition" in visible, (
        "The pilot UFS scale must remain distinct from the CVSS source classification"
    )
    assert dom.tags.count("meter") == (0 if label == "Unknown" else 5), (
        "Missing or invalid source scores cannot become numeric zero memberships"
    )
    assert "fuzzyroutines" in " ".join(dom.text) and "scale_profile" in " ".join(dom.text), (
        "Saved HTML must retain library, scale and full rule metadata for offline reproduction"
    )



@pytest.mark.parametrize("status,expected", [(200, "200 OK"), (204, "204 No Content"),
                                           (599, "599"), (None, "Not recorded")])
def test_HtmlHttpStatusesKeepExactCodeAndExplainKnownResponseMeaning(status, expected):
    """Readable response labels explain known HTTP codes without recategorizing unknown status."""

    provenance = Fixture().state.Objects(ObjectKind.HOST)[0].provenance
    entity = SecurityObject(ObjectIdentity("synthetic", ObjectKind.ENDPOINT, "owned-address"),
                            {"status": status}, provenance)

    assert report_formats.AttributeText(entity, "status") == expected, (
        "HTTP presentation must retain the source code and a standard phrase only when known"
    )
