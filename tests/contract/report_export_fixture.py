# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned report-export source fixtures; stored failure/disposition facts, without actual scans."""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
from dataclasses import replace
from io import StringIO
from pathlib import Path

from jsonschema import Draft202012Validator

from fuzzy1337 import report_commands as commands
from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
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
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from fuzzy1337.scope import LocalScopeStore, ScopeSnapshot
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

ROOT = Path(__file__).resolve().parents[2]


def OutcomeValidator():
    """Validate the command result without retrieving any remote schema resource."""

    schema = json.loads((ROOT / "contracts" / "report-export-result.schema.json").read_bytes())
    Draft202012Validator.check_schema(schema)

    return Draft202012Validator(schema)



def Context(tmp_path: Path, *, workspace_id: str = "report-case", findings: bool = True):
    """Build retained synthetic failed acquisitions and operator dispositions without scans."""

    root = tmp_path / workspace_id
    workspace = LocalWorkspaceStore(root).Create(
        WorkspaceConfiguration("Owned report"), workspace_id,
    )
    scope = LocalScopeStore(root).Create(ScopeSnapshot("local", workspace_id))
    model = LocalModelStore(root).Create()
    records = []

    for index in range(2):
        execution = AdapterExecution(ExecutionState.FAILED, 7, 0.01)
        record = LocalEvidenceStore(root / "evidence").Put(
            f"owned synthetic failure record {index}".encode(), "stdout", "text/plain",
            EvidenceProvenance(workspace_id, scope.Reference(), "synthetic.report-export", "1",
                               f"fixture-{index}", "2026-10-13T00:00:00Z",
                               "2026-10-13T00:00:01Z", execution=execution),
        )
        records.append(record)

    provenance = ModelProvenance("synthetic.report-export", records[0].evidence_id,
        "2026-10-13T00:00:01Z", scope.Reference(), "target:owned-fixture",
        evidence_references=(records[0].reference,), execution=records[0].provenance.execution)
    host = SecurityObject(ObjectIdentity(workspace_id, ObjectKind.HOST, "127.0.0.1"),
                          {"fixture": "no network contact"}, (provenance,))
    model, delta = model.Apply(objects=(host,))
    LocalModelStore(root).Save(model, expected_revision=delta.previous_revision)

    if findings:
        interpretations = tuple(Finding(
            host.Reference(), "synthetic.report-export-check", f"owned/{status.value}",
            "Owned retained interpretation <script>inert</script>", (provenance,),
            FindingSeverity.HIGH, 0.75,
        ) for status in FindingStatus)
        model, delta = ApplyVerifiedFindings(model, interpretations, root)
        LocalModelStore(root).Save(model, expected_revision=delta.previous_revision)

        for status, finding in zip(FindingStatus, interpretations, strict=True):
            if status is FindingStatus.OPEN:
                continue

            decision = replace(provenance, source_id="operator.triage",
                               run_reference=f"decision:owned-{status.value}",
                               observed_at="2026-10-13T00:00:02Z", execution=None)
            model, delta = TransitionFinding(model, finding.ToObject(workspace_id).Reference(),
                status, decision, "Owned operator disposition")
            LocalModelStore(root).Save(model, expected_revision=delta.previous_revision)

    LocalWorkspaceStore(root).Save(replace(workspace,
        scope_references=(scope.Reference(),),
        evidence_references=tuple(record.reference for record in records),
        evidence_record_references=tuple(record.evidence_id for record in records)))

    return root, records



def Files(root: Path) -> dict[str, bytes]:
    """Observe only test-owned source bytes and ensure the command does not rewrite them."""

    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*") if path.is_file()}



def Run(root: Path, output_path: Path, *, format_name: str = "json"):
    """Call the same foreground product consumer as CLI/shell with an explicit new destination."""

    output = StringIO()
    status = commands.RunReportCommands(
        ["export", str(root), "--format", format_name, "--output", str(output_path)],
        output, json_output=True,
    )
    result = json.loads(output.getvalue())
    OutcomeValidator().validate(result)

    return status, result



def DenyExecution(monkeypatch) -> None:
    """Make any process/network operation an immediate regression failure in the consumer path."""

    def Denied(*arguments, **options):
        """Reject provider execution regardless of argument values or purported authority."""

        raise AssertionError("Offline report export must not start a process or contact a target.")

    monkeypatch.setattr(subprocess, "Popen", Denied)
    monkeypatch.setattr(socket, "socket", Denied)
    monkeypatch.setattr(socket, "create_connection", Denied)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", Denied)
