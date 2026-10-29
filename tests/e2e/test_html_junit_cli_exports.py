# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual console report formats, independent markup oracles and durable publication truth."""

from __future__ import annotations

import builtins
import hashlib
import json
import os
import shlex
import subprocess
import sys
from dataclasses import replace
from html.parser import HTMLParser
from io import StringIO
from pathlib import Path
from xml.etree import ElementTree

import pytest

from fuzzy1337 import report_commands
from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.cli import Main
from fuzzy1337.evidence import EvidenceProvenance, EvidenceRecord, LocalEvidenceStore
from fuzzy1337.findings import (
    ApplyVerifiedFindings,
    Finding,
    FindingSeverity,
    FindingStatus,
    TransitionFinding,
)
from fuzzy1337.model import (
    LocalModelStore,
    ModelProvenance,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from fuzzy1337.reporting import ReportSnapshot
from fuzzy1337.scope import AuthorizationState, LocalScopeStore, ScopeAuthorization, ScopeSnapshot
from fuzzy1337.shell import InteractiveShell
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration
from tests.contract.report_export_fixture import DenyExecution, Files, OutcomeValidator

HOSTILE_SUMMARY = 'Owned <script>run()</script> & "tag" \x01 \u202e'
TIME = "2026-10-14T00:00:00Z"
FORMATS = ("json", "sarif", "html", "junit")


class HtmlOracle(HTMLParser):
    """Read emitted markup structurally without running a browser or producer escape helper."""

    def __init__(self) -> None:
        """Initialize independent tag, attribute, anchor and decoded-text observations."""

        super().__init__()
        self.tags: list[str] = []
        self.attributes: list[tuple[str, str | None]] = []
        self.ids: list[str] = []
        self.hrefs: list[str] = []
        self.text: list[str] = []

    def StartTag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Retain actual parsed markup rather than interpreting escaped source as elements."""

        self.tags.append(tag)
        self.attributes.extend(attrs)

        for name, value in attrs:
            if name == "id" and value is not None:
                self.ids.append(value)

            elif name == "href" and value is not None:
                self.hrefs.append(value)

    def Data(self, data: str) -> None:
        """Collect independently decoded text for literal hostile-source display assertions."""

        self.text.append(data)

    # HTMLParser owns these callback spellings; authored methods retain house style.
    handle_starttag = StartTag
    handle_data = Data


def Console(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    """Run the installed module entry in its own process with argument arrays and finite cleanup."""

    return subprocess.run([sys.executable, "-m", "fuzzy1337", *arguments],
                          capture_output=True, text=True, timeout=30, check=False)


def RetainOwnedState(root: Path, *, findings: bool = True
                    ) -> tuple[ModelState, tuple[EvidenceRecord, ...]]:
    """Use production owners to retain synthetic evidence and explicit operator dispositions.

    The fixture asserts no scanner execution: its failed source facts are declared synthetic
    records. Workspace creation belongs to the actual console in the user workflow test.
    """

    workspace = LocalWorkspaceStore(root).Open()
    scope = LocalScopeStore(root).Create(ScopeSnapshot("owned", workspace.workspace_id))
    model = LocalModelStore(root).Open()
    evidence = LocalEvidenceStore(root / "evidence")
    records = tuple(evidence.Put(
        f"raw-only owned report record {index}".encode(), "stdout", "text/plain",
        EvidenceProvenance(workspace.workspace_id, scope.Reference(), "synthetic.report-oracle",
            "1", "owned", TIME, TIME, execution=AdapterExecution(ExecutionState.FAILED, 7, 0.01)),
    ) for index in range(2))
    provenance = ModelProvenance("synthetic.report-oracle", records[0].evidence_id, TIME,
        scope.Reference(), "target:owned-report", evidence_references=(records[0].reference,),
        execution=records[0].provenance.execution)
    host = SecurityObject(ObjectIdentity(workspace.workspace_id, ObjectKind.HOST, "127.0.0.1"),
        {"fixture": "owned offline source"}, (provenance,))
    model, delta = model.Apply(objects=(host,))
    LocalModelStore(root).Save(model, expected_revision=delta.previous_revision)

    if findings:
        dispositions = (FindingStatus.OPEN, FindingStatus.CONFIRMED,
                        FindingStatus.DISMISSED, FindingStatus.RESOLVED)
        interpreted = tuple(Finding(host.Reference(), "synthetic.report-oracle-check",
            "owned/" + status.value, HOSTILE_SUMMARY, (provenance,), FindingSeverity.HIGH, 0.75)
            for status in dispositions)
        model, delta = ApplyVerifiedFindings(model, interpreted, root)
        LocalModelStore(root).Save(model, expected_revision=delta.previous_revision)

        for status, finding in zip(dispositions, interpreted, strict=True):
            if status is FindingStatus.OPEN:
                continue

            decision = replace(provenance, source_id="operator.owned", execution=None,
                               run_reference="decision:" + status.value)
            model, delta = TransitionFinding(model,
                finding.ToObject(workspace.workspace_id).Reference(), status, decision,
                "Owned operator disposition <script>inert</script>")
            LocalModelStore(root).Save(model, expected_revision=delta.previous_revision)

    LocalWorkspaceStore(root).Save(replace(workspace, scope_references=(scope.Reference(),),
        object_references=tuple(sorted(entity.Reference() for entity in model.objects)),
        evidence_references=tuple(record.reference for record in records),
        evidence_record_references=tuple(record.evidence_id for record in records)))

    return model, records


def ExportArguments(root: Path, destination: Path, format_name: str) -> list[str]:
    """Require the same explicit owning workspace, format and new destination as a human."""

    return ["report", "export", str(root), "--format", format_name,
            "--output", str(destination), "--json"]


def CheckLiteralOracle(payload: bytes, format_name: str, model: ModelState,
                       *, findings: bool = True) -> None:
    """Compare actual outputs with handwritten disposition, escaping and completeness facts."""

    count = 4 if findings else 0

    if format_name == "html":
        parser = HtmlOracle()
        parser.feed(payload.decode("utf-8"))
        assert not {"script", "iframe", "img", "object", "embed", "svg"} & set(parser.tags), (
            "Hostile report source must not create executable or remotely loaded HTML elements"
        )
        assert not any(name.startswith("on") or name == "src" for name, _ in parser.attributes), (
            "Observed metadata cannot create event handlers or remote asset attributes"
        )
        assert len(parser.ids) == len(set(parser.ids)) and all(
            href.startswith("#") and href[1:] in parser.ids for href in parser.hrefs
        ), "Original object/evidence/navigation fragments must be unique and resolve locally"
        assert b"Scan completeness was not assessed." in payload and (
            f"revision {model.revision}".encode() in payload
        ), "HTML must expose its exact saved revision and unassessed completeness"
        assert b"verified bytes" in payload and b"Failed execution records" in payload, (
            "HTML must preserve original source failure and checked byte-integrity presentation"
        )

        if findings:
            assert b"&lt;script&gt;run()&lt;/script&gt; &amp; &quot;tag&quot;" in payload, (
                "Literal hostile source must be escaped without consulting producer escape code"
            )
            assert "<script>run()</script>" in "".join(parser.text) and (
                b"\\u0001" in payload and b"\\u202e" in payload and b"\x01" not in payload
            ), "HTML displays hostile text and controls inertly rather than changing model data"
            assert len([value for value in parser.ids if value.startswith("finding-")]) == 4, (
                "HTML retains all four independent operator disposition cases"
            )

    elif format_name == "junit":
        suite = ElementTree.fromstring(payload)
        assert suite.tag == "testsuite" and suite.attrib == {
            "name": "1337 retained findings", "tests": str(count),
            "failures": "2" if findings else "0", "errors": "0",
            "skipped": "2" if findings else "0",
        }, "JUnit counts describe retained Findings rather than executed security tests"
        properties = {item.attrib["name"]: item.attrib["value"]
                      for item in suite.findall("properties/property")}
        assert properties["scan_completeness"] == "not-assessed" and (
            properties["model_revision"] == str(model.revision)
        ), "JUnit must retain exact snapshot and unassessed completeness properties"
        integrity = json.loads(properties["evidence_integrity"])
        outcomes = json.loads(properties["execution_outcomes"])
        assert integrity["unverified_count"] == 0 and len(integrity["checked_references"]) == 1, (
            "JUnit must preserve actual verified linked evidence rather than inferred scan success"
        )
        assert len(outcomes) == 1 and outcomes[0]["execution"]["state"] == "failed" and (
            outcomes[0]["execution"]["exit_code"] == 7
        ), "Successful JUnit export cannot replace original failed source execution facts"
        assert len(suite.findall("testcase")) == count, "Zero findings cannot invent passing cases"

        if findings:
            details = [json.loads(case[0].text) for case in suite.findall("testcase")]
            assert {item["normalized"]["status"] for item in details} == {
                "open", "confirmed", "dismissed", "resolved"
            }, "JUnit retains every original operator disposition"

            for case, detail in zip(suite.findall("testcase"), details, strict=True):
                status = detail["normalized"]["status"]
                assert case[0].tag == (
                    "failure" if status in {"open", "confirmed"} else "skipped"
                ), (
                    "Only active dispositions fail; explicit dismissed/resolved dispositions skip"
                )

            assert b"&lt;script&gt;run()&lt;/script&gt;" in payload and b"\x01" not in payload, (
                "JUnit must keep source markup and forbidden XML controls inert"
            )

    elif format_name == "json":
        document = json.loads(payload)
        assert document["model"] == model.ToDict() and document["scan_completeness"] == (
            "not-assessed"
        ), "JSON remains the exact original canonical model projection"

        if findings:
            assert document["summary"]["finding_statuses"] == {
                "open": 1, "confirmed": 1, "dismissed": 1, "resolved": 1,
            }, "JSON preserves every original operator disposition"

        else:
            assert document["summary"]["findings"] == 0, "Empty JSON cannot invent passed checks"

    else:
        document = json.loads(payload)
        assert document["version"] == "2.1.0" and len(document["runs"][0]["results"]) == (
            2 if findings else 0
        ), "SARIF retains only active Finding results without passed-check invention"


@pytest.mark.parametrize("findings", [True, False], ids=["dispositions", "empty"])
def test_ActualConsoleExportsAllFormatsThenRelocatesAndRefusesChangedRawEvidence(
    tmp_path, findings
):
    """Create through CLI, retain real owned state and export with independent literal oracles."""

    root = tmp_path / "workspace with spaces"
    created = Console(["workspace", "create", str(root), "--id", "report-console",
                       "--name", "Report"])
    assert created.returncode == 0 and not created.stderr, "Console creates explicit owner state"
    model, records = RetainOwnedState(root, findings=findings)
    before = Files(root)
    payloads = {}

    for format_name in FORMATS:
        destination = tmp_path / ("selected report." + format_name)
        completed = Console(ExportArguments(root, destination, format_name))
        assert completed.returncode == 0 and not completed.stderr, (
            "Actual console export must complete independently of JUnit failures or source failure"
        )
        outcome = json.loads(completed.stdout)
        OutcomeValidator().validate(outcome)
        payload = destination.read_bytes()
        payloads[format_name] = payload
        assert outcome["model_revision"] == model.revision and (
            outcome["snapshot_sha256"] == ReportSnapshot(model).SnapshotDigest()
        ), "Actual console outcome must identify the exact saved full snapshot"
        assert outcome["report_sha256"] == hashlib.sha256(payload).hexdigest() and (
            outcome["verified_retained_acquisitions"] == 2
            and outcome["checked_model_evidence_references"] == 1
            and outcome["output_published"]
        ), "Outcome must bind complete published bytes and all original verified references"
        CheckLiteralOracle(payload, format_name, model, findings=findings)
        assert str(root).encode() not in payload and (
            b"raw-only owned report record" not in payload
        ), (
            "Reports cannot embed physical source paths or acquired raw bytes"
        )
        assert Files(root) == before, "Actual export must not write any owning source file"

    scope_store = LocalScopeStore(root)
    scope_store.Save(replace(scope_store.Open("owned"),
                            authorization=ScopeAuthorization(AuthorizationState.REVOKED)))
    moved = tmp_path / "relocated owning workspace"
    root.rename(moved)
    historical = Files(moved)

    for format_name in FORMATS:
        destination = tmp_path / ("relocated report." + format_name)
        completed = Console(ExportArguments(moved, destination, format_name))
        assert completed.returncode == 0 and destination.read_bytes() == payloads[format_name], (
            "Relocation and revoked current scope cannot rewrite original historical report bytes"
        )

    assert Files(moved) == historical, "Historical reporting supplies no grant or source mutation"
    changed, delta = model.Apply(objects=(SecurityObject(
        ObjectIdentity(model.workspace_id, ObjectKind.HOST, "127.0.0.2"),
        provenance=model.Objects(ObjectKind.HOST)[0].provenance),))
    LocalModelStore(moved).Save(changed, expected_revision=delta.previous_revision)
    later = tmp_path / "later report.html"
    assert Console(ExportArguments(moved, later, "html")).returncode == 0, (
        "An explicit later export may select the later actually saved revision"
    )
    assert later.read_bytes() != payloads["html"], "Later saved revision must remain distinct"
    assert (tmp_path / "selected report.html").read_bytes() == payloads["html"], (
        "A completed report is a pinned historical artifact rather than a live model view"
    )
    unused = records[1]
    (moved / "evidence" / unused.reference.locator).write_bytes(b"Z" * unused.reference.size_bytes)
    rejected_source = Files(moved)

    for format_name in ("html", "junit"):
        destination = tmp_path / ("refused." + format_name)
        refused = Console(ExportArguments(moved, destination, format_name))
        outcome = json.loads(refused.stdout)
        assert refused.returncode == 4 and outcome["failure"] == "integrity" and (
            not outcome["output_published"] and not destination.exists()
        ), "Even unused retained raw corruption must refuse the entire new-format export"

    assert Files(moved) == rejected_source, "Failed export cannot rewrite rejected evidence"


@pytest.mark.parametrize("format_name", ["html", "junit"])
def test_RealPublicationAndPureRendererBoundariesPreserveFailureAndAcknowledgementTruth(
    tmp_path, monkeypatch, capsys, format_name
):
    """Use actual CLI/stores/filesystem publication while injecting deterministic failure points."""

    root = tmp_path / "owned"
    assert Console(["workspace", "create", str(root), "--id", "report-owned", "--name", "Report"]
                   ).returncode == 0, "Console creates the source before boundary tests"
    model, _ = RetainOwnedState(root)
    before = Files(root)
    DenyExecution(monkeypatch)
    original_link = os.link
    renderer_name = "RenderHtml" if format_name == "html" else "SerializeJunit"
    original_renderer = getattr(report_commands, renderer_name)

    def DeniedIo(*_args, **_options):
        """Reject filesystem acquisition inside the unchanged pure renderer only."""

        raise AssertionError("Pure report renderer cannot read source or publish files")

    def PureRenderer(report):
        """Use original renderer while forbidding filesystem reads or writes during its call."""

        with monkeypatch.context() as boundary:
            boundary.setattr(builtins, "open", DeniedIo)
            boundary.setattr(Path, "open", DeniedIo)
            boundary.setattr(os, "open", DeniedIo)
            boundary.setattr(LocalModelStore, "Open", DeniedIo)
            boundary.setattr(LocalEvidenceStore, "Read", DeniedIo)

            return original_renderer(report)

    monkeypatch.setattr(report_commands, renderer_name, PureRenderer)
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    destination = tmp_path / ("shell report." + format_name)
    assert not shell.onecmd(shlex.join(ExportArguments(root, destination, format_name))), (
        "Foreground shell must reuse explicit same-owner export and remain available"
    )
    assert json.loads(output.getvalue())["status"] == "completed" and shell.lastcmd == "report", (
        "Shell success and protected namespace history must remain unchanged"
    )
    CheckLiteralOracle(destination.read_bytes(), format_name, model)
    assert Main(ExportArguments(root, destination, format_name)) == 2, (
        "Existing selected output must fail before publication without clobbering bytes"
    )
    capsys.readouterr()
    preserved = destination.read_bytes()

    for phase in ("before", "after", "interrupt-after", "race"):
        def Link(source, target):
            """Exercise the real no-clobber link or owned competing creation at its boundary."""

            if phase == "before":
                raise OSError("Owned pre-publication failure")

            if phase == "race":
                Path(target).write_bytes(b"owned competing destination")

                return original_link(source, target)

            original_link(source, target)

            if phase == "interrupt-after":
                raise KeyboardInterrupt

            raise OSError("Owned post-publication acknowledgement failure")

        monkeypatch.setattr(report_commands.os, "link", Link)
        selected = tmp_path / (phase + "." + format_name)
        status = Main(ExportArguments(root, selected, format_name))
        outcome = json.loads(capsys.readouterr().out)
        OutcomeValidator().validate(outcome)
        published = phase in {"after", "interrupt-after"}
        assert status == (130 if phase == "interrupt-after" else 4) and (
            outcome["output_published"] is published
        ), "Actual failed acknowledgement cannot invent or erase confirmed complete publication"

        if published:
            assert selected.read_bytes() == preserved and (
                hashlib.sha256(selected.read_bytes()).hexdigest() == outcome["report_sha256"]
            ), "Confirmed output must retain complete original renderer bytes"

        elif phase == "race":
            assert selected.read_bytes() == b"owned competing destination", (
                "No-clobber race must preserve the actual foreign selected output"
            )

        else:
            assert not selected.exists(), "Failed publication cannot expose partial report bytes"

        assert not list(tmp_path.glob(".1337-report-*.pending")), "Clean owned temporary files"
        assert Files(root) == before, "All failure and acknowledgement paths preserve source files"


@pytest.mark.parametrize("format_name", ["html", "junit"])
@pytest.mark.parametrize("error,status,category", [
    (ValueError("owned private renderer detail"), 4, "rendering"),
    (RuntimeError("owned private internal detail"), 4, "internal"),
    (KeyboardInterrupt(), 130, "interrupted"),
], ids=["rendering", "internal", "interrupt"])
def test_NewFormatMainRendererFailuresRetainSafeOutcomeWithoutPublication(
    tmp_path, monkeypatch, capsys, format_name, error, status, category
):
    """Exercise actual verified input and CLI failure presentation at the renderer boundary."""

    root = tmp_path / "owned"
    created = Console(["workspace", "create", str(root), "--id", "report-errors",
                       "--name", "Report"])
    assert created.returncode == 0, "Renderer failure test requires console-created owner state"
    RetainOwnedState(root)
    before = Files(root)
    DenyExecution(monkeypatch)

    def FailedRenderer(report):
        """Raise an explicit synthetic failure only after the command verifies real source input."""

        assert report.state.workspace_id == "report-errors", "Renderer receives the owning snapshot"

        raise error

    name = "RenderHtml" if format_name == "html" else "SerializeJunit"
    monkeypatch.setattr(report_commands, name, FailedRenderer)
    selected = tmp_path / ("failed." + format_name)
    assert Main(ExportArguments(root, selected, format_name)) == status, (
        "New-format CLI must preserve rendering, unexpected failure or interruption status"
    )
    output = capsys.readouterr().out
    outcome = json.loads(output)
    OutcomeValidator().validate(outcome)
    assert outcome["failure"] == category and not outcome["output_published"] and (
        "private" not in output and not selected.exists()
    ), "Renderer failure cannot expose private details or publish even partial output"
    assert Files(root) == before, "Failed rendering cannot change owning source files"


@pytest.mark.parametrize("format_name", ["html", "junit"])
@pytest.mark.parametrize("change", ["model", "workspace"])
def test_NewFormatMainRejectsCooperativeFullSnapshotChanges(
    tmp_path, monkeypatch, capsys, format_name, change
):
    """A real owner CAS change during rendering cannot be replaced by another snapshot silently."""

    root = tmp_path / "owned"
    created = Console(["workspace", "create", str(root), "--id", "report-changes",
                       "--name", "Report"])
    assert created.returncode == 0, "Snapshot mutation test requires console-created owner state"
    original_model, _ = RetainOwnedState(root)
    name = "RenderHtml" if format_name == "html" else "SerializeJunit"
    original_renderer = getattr(report_commands, name)
    changed_files = []
    DenyExecution(monkeypatch)

    def RenderThenSave(report):
        """Render original bytes and perform an actual cooperative save before publication."""

        payload = original_renderer(report)

        if change == "model":
            current = LocalModelStore(root).Open()
            host = SecurityObject(
                ObjectIdentity(current.workspace_id, ObjectKind.HOST, "127.0.0.2"),
                provenance=current.Objects(ObjectKind.HOST)[0].provenance)
            updated, delta = current.Apply(objects=(host,))
            LocalModelStore(root).Save(updated, expected_revision=delta.previous_revision)

        else:
            store = LocalWorkspaceStore(root)
            store.Save(replace(store.Open(), configuration=WorkspaceConfiguration("Owned change")))

        changed_files.append(Files(root))

        return payload

    monkeypatch.setattr(report_commands, name, RenderThenSave)
    selected = tmp_path / ("stale." + format_name)
    assert Main(ExportArguments(root, selected, format_name)) == 4, (
        "A changed full workspace/model snapshot must remain an explicit failed export"
    )
    outcome = json.loads(capsys.readouterr().out)
    OutcomeValidator().validate(outcome)
    assert outcome["failure"] == "input-changed" and (
        outcome["model_revision"] == original_model.revision
        and outcome["snapshot_sha256"] == ReportSnapshot(original_model).SnapshotDigest()
    ), "Failure outcome must retain the original selected snapshot rather than substitute new facts"
    assert not selected.exists() and not outcome["output_published"], (
        "Cooperative changes cannot publish the now-stale complete rendered bytes"
    )
    assert Files(root) == changed_files[0], "Export cannot repair or reverse an actual owner change"


@pytest.mark.parametrize("format_name", ["html", "junit"])
def test_NewFormatMainOutputQuotaRejectsCompleteBytesBeforePublication(
    tmp_path, monkeypatch, capsys, format_name
):
    """Actual new-format serialization remains bounded by the existing product output ceiling."""

    root = tmp_path / "owned"
    created = Console(["workspace", "create", str(root), "--id", "report-quota",
                       "--name", "Report"])
    assert created.returncode == 0, "Output quota test requires console-created owner state"
    RetainOwnedState(root)
    before = Files(root)
    DenyExecution(monkeypatch)
    monkeypatch.setattr(report_commands, "MAX_REPORT_BYTES", 1)
    selected = tmp_path / ("oversized." + format_name)
    assert Main(ExportArguments(root, selected, format_name)) == 4, (
        "An actual complete HTML/JUnit payload exceeding product quota must remain failed"
    )
    outcome = json.loads(capsys.readouterr().out)
    OutcomeValidator().validate(outcome)
    assert outcome["failure"] == "limit" and not outcome["output_published"] and (
        not selected.exists()
    ), "Output quota cannot expose partial report bytes or imply successful publication"
    assert Files(root) == before, "Output quota refusal must not truncate owning source evidence"
