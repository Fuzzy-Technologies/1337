# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual installed API console over original owned sources and independently durable owners."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from fuzzy1337 import api_commands as commands
from fuzzy1337.cli import Main
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.findings import Finding, Findings, FindingStatus, TransitionFinding
from fuzzy1337.model import LocalModelStore, ModelProvenance, SecurityObject
from fuzzy1337.requests import Endpoint, RequestsFromObject
from fuzzy1337.scope import LocalScopeStore
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.api_import_helpers import ENDPOINT, FIXTURE, Arguments, Files, Value


def Console(parent, arguments):
    """Run the installed console script with explicit owned local arguments and bounded capture."""

    executable = Path(sys.executable).parent / ("1337.exe" if os.name == "nt" else "1337")
    result = subprocess.run(
        [str(executable), *arguments],
        cwd=parent,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert not result.stderr, "Registered console emitted unexpected or unsafe diagnostics"

    return result.returncode, json.loads(result.stdout)


def ConsoleContext(parent, *, grant=True):
    """Set up exact workspace/scope through public console and seed explicit UNKNOWN endpoint
    data.
    """

    root = parent / "Owned GraphQL Workspace"
    status, _ = Console(
        parent,
        [
            "workspace",
            "create",
            str(root),
            "--id",
            "graphql-console",
            "--name",
            "Owned GraphQL",
            "--json",
        ],
    )
    assert status == 0, "Actual public workspace setup failed"
    arguments = ["scope", "create", str(root), "--id", "owned", "--allow-url", ENDPOINT]

    if grant:
        now = datetime.now(timezone.utc)
        arguments.extend(
            [
                "--grant-consent",
                "--owner",
                "actor:owned",
                "--consent-reference",
                "consent:endpoint",
                "--valid-from",
                (now - timedelta(minutes=2)).isoformat(),
                "--valid-until",
                (now + timedelta(hours=1)).isoformat(),
            ]
        )

    status, _ = Console(parent, [*arguments, "--json"])
    assert status == 0, "Actual public scope setup failed"
    scope = LocalScopeStore(root).Open("owned")
    basis = LocalModelStore(root).Open()
    endpoint = Endpoint(basis.workspace_id, "http://127.0.0.1:8080", "/graphql", "POST")
    provenance = ModelProvenance(
        "owned.endpoint",
        "run:endpoint",
        datetime.now(timezone.utc).isoformat(),
        "scope:owned",
        scope.targets[0].Reference(),
    )
    patch = SecurityObject(
        endpoint.Identity(), {"reachability": None, "operator_note": "owned"}, (provenance,)
    )
    proposed, _ = basis.Apply(objects=(patch,))
    saved = LocalModelStore(root).Save(proposed, expected_revision=basis.revision)
    source = parent / "Owned Introspection.json"
    source.write_bytes(FIXTURE.read_bytes())

    return root, saved, scope, LocalEvidenceStore(root / "evidence"), source


def Import(parent, context, *, evidence_id=None, arguments=None):
    """Invoke the assembled API route using explicit independently current owner bases."""

    selected = Arguments(context, evidence_id=evidence_id) if arguments is None else arguments

    return Console(parent, ["api", *selected, "--json"])


def test_InstalledApiConsolePreservesOriginalOracleTriageUnknownReplayAndReports(tmp_path):
    """Actual public setup/import/reopen/export retains structural truth and independent custody."""

    context = ConsoleContext(tmp_path)
    root, basis, scope, evidence, source = context
    scope_before = (root / "state/scopes/owned.json").read_bytes()
    original = source.read_bytes()
    status, first = Import(tmp_path, context)
    assert status == 0 and all(
        first[field] == "confirmed"
        for field in (
            "acquisition_commit",
            "model_commit",
            "workspace_commit",
        )
    ), "Actual console lost an independent storage acknowledgement"
    record = evidence.Get(first["evidence_id"])
    assert evidence.Read(record.reference) == original and (
        first["source_sha256"] == hashlib.sha256(original).hexdigest()
    ), "Actual console changed original unredacted bytes or their complete digest"
    saved = LocalModelStore(root).Open()
    endpoint = saved.objects[0]
    operations = endpoint.attributes["graphql_import"]["operations"]
    assert [
        (item["operation_kind"], item["field_name"], item["source_pointer"]) for item in operations
    ] == [
        ("mutation", "updateOwned", "#/data/__schema/types/11/fields/0"),
        ("query", "lookup", "#/data/__schema/types/10/fields/0"),
        ("query", "opaque", "#/data/__schema/types/10/fields/2"),
        ("query", "ping", "#/data/__schema/types/10/fields/1"),
        ("subscription", "ticks", "#/data/__schema/types/12/fields/0"),
    ], "Installed console lost handwritten typed root/pointer oracle"
    lookup = next(item for item in operations if item["field_name"] == "lookup")
    assert [item["type"] for item in lookup["arguments"]] == [
        {"kind": "INPUT_OBJECT", "name": "Filter", "wrappers": ()},
        {"kind": "SCALAR", "name": "ID", "wrappers": ("NON_NULL", "LIST", "NON_NULL")},
    ], "Actual immutable typed wrapper oracle failed"
    assert len(RequestsFromObject(endpoint)) == 5 and not Findings(saved), (
        "Descriptive import lost templates or manufactured findings"
    )
    assert endpoint.attributes["reachability"] is None and (
        endpoint.attributes["operator_note"] == "owned"
        and basis.objects[0].provenance[0] in endpoint.provenance
    ), "Actual import replaced UNKNOWN descriptions or unrelated endpoint provenance"
    assert all(template.session_reference is None for template in RequestsFromObject(endpoint)), (
        "Actual product import created a session default"
    )
    attribution = ModelProvenance(
        "owned.operator",
        "decision:owned",
        datetime.now(timezone.utc).isoformat(),
        scope.Reference(),
        scope.targets[0].Reference(),
        evidence_references=(record.reference,),
    )
    finding = Finding(
        endpoint.Reference(),
        "owned.existing-note",
        "owned/location",
        "Owned pre-existing synthetic note",
        (attribution,),
    )
    with_finding, _ = saved.Apply(objects=(finding.ToObject(saved.workspace_id),))
    saved = LocalModelStore(root).Save(with_finding, expected_revision=saved.revision)
    triaged, _ = TransitionFinding(
        saved,
        finding.ToObject(saved.workspace_id).Reference(),
        FindingStatus.DISMISSED,
        attribution,
        "Owned reviewed synthetic disposition",
    )
    LocalModelStore(root).Save(triaged, expected_revision=saved.revision)
    status, second = Import(tmp_path, context)
    assert (
        status == 0
        and second["evidence_id"] != first["evidence_id"]
        and (second["source_sha256"] == first["source_sha256"])
    ), "Actual source acquisitions collapsed manifest identity to the raw digest"
    expected = LocalModelStore(root).Open()
    assert (
        len(Findings(expected)) == 1 and Findings(expected)[0].status is FindingStatus.DISMISSED
    ), "Actual repeated description import erased existing operator triage"
    assert (root / "state/scopes/owned.json").read_bytes() == scope_before, (
        "Import changed scope/grants"
    )
    workspace = LocalWorkspaceStore(root).Open()
    assert set(workspace.evidence_record_references) == {
        first["evidence_id"],
        second["evidence_id"],
    }
    assert not workspace.job_references, "Offline import manufactured a scanner invocation/job"
    before = Files(root)
    moved = tmp_path / "Moved GraphQL Workspace"
    root.rename(moved)
    source.unlink()
    relocated = moved, expected, scope, LocalEvidenceStore(moved / "evidence"), source

    for selected in (first, second):
        status, replay = Import(tmp_path, relocated, evidence_id=selected["evidence_id"])
        assert status == 0 and replay["created"] == replay["updated"] == 0, (
            "Actual replay changed graph"
        )
        assert Files(moved) == before, "Actual known-source replay rewrote portable owner bytes"

    status, _ = Console(tmp_path, ["workspace", "open", str(moved), "--json"])
    assert status == 0, "Public authoritative relocated reopen failed"

    for report_format in ("json", "sarif"):
        destination = tmp_path / ("graphql-report." + report_format)
        status, exported = Console(
            tmp_path,
            [
                "report",
                "export",
                str(moved),
                "--format",
                report_format,
                "--output",
                str(destination),
                "--json",
            ],
        )
        assert status == 0 and exported["output_published"] is True, "Actual report export failed"
        document = json.loads(destination.read_bytes())

        if report_format == "json":
            assert document["model"] == expected.ToDict(), (
                "JSON report changed exact saved API truth"
            )

        else:
            run = document["runs"][0]
            assert not run["results"] and len(run["properties"]["closedFindings"]) == 1, (
                "SARIF changed existing triage or manufactured active GraphQL findings"
            )

        assert b"synthetic-private-default" not in destination.read_bytes(), "Raw defaults leaked"


@pytest.mark.parametrize(
    "mode,expected,failure",
    [
        ("scope", 4, "scope"),
        ("no-consent", 2, "configuration"),
        ("stale-model", 4, "revision-conflict"),
        ("stale-workspace", 4, "workspace-conflict"),
        ("missing-file", 4, "acquisition"),
        ("malformed", 4, "normalization"),
        ("oversized", 4, "limit"),
        ("model-busy", 4, "model-busy"),
        ("workspace-busy", 4, "workspace-busy"),
        ("occupied", 4, "occupied-endpoint"),
    ],
)
def test_InstalledApiRefusalsPreserveActualIndependentOwnerTruth(tmp_path, mode, expected, failure):
    """Actual console setup, denied reads, conflicts and locks retain the real owner outcomes."""

    context = ConsoleContext(tmp_path, grant=mode != "scope")
    root, basis, _, _, source = context
    arguments = Arguments(context)
    lock = None

    if mode == "no-consent":
        index = arguments.index("--read-consent-reference")
        del arguments[index : index + 2]

    elif mode in {"stale-model", "stale-workspace"}:
        arguments = Value(
            arguments,
            "--expected-revision" if mode == "stale-model" else "--expected-workspace-revision",
            99,
        )

    elif mode == "missing-file":
        source.unlink()

    elif mode in {"malformed", "oversized"}:
        source.write_bytes(
            b'{"private":"PRIVATE_SOURCE_MARKER"}'
            if mode == "malformed"
            else b"x" * (512 * 1024 + 1)
        )

    elif mode in {"model-busy", "workspace-busy"}:
        lock = root / "state/model/.write-lock" if mode == "model-busy" else root / ".write-lock"
        lock.mkdir()

    elif mode == "occupied":
        endpoint = basis.objects[0]
        patch = SecurityObject(endpoint.identity, {"request_templates": []}, endpoint.provenance)
        proposed, _ = basis.Apply(objects=(patch,))
        basis = LocalModelStore(root).Save(proposed, expected_revision=basis.revision)
        arguments = Arguments(context)

    try:
        status, outcome = Import(tmp_path, context, arguments=arguments)
        assert status == expected and outcome["failure"] == failure, (
            "Actual console refusal changed"
        )
        assert LocalModelStore(root).Open().revision == basis.revision + int(
            mode == "workspace-busy"
        ), "Refusal changed or rolled back actual canonical model truth"
        assert LocalWorkspaceStore(root).Open().revision == 0, "Refused import saved workspace"
        assert "PRIVATE_SOURCE_MARKER" not in str(outcome), "Refused original source leaked"

        if lock is not None:
            owner = "model" if mode == "model-busy" else "workspace"
            assert lock.is_dir() and outcome[owner + "_commit"] == "not-committed", (
                "Known busy refusal lost the real lock or became unknown"
            )

        else:
            assert outcome["acquisition_commit"] == (
                "confirmed" if mode in {"malformed", "occupied"} else "not-attempted"
            ), "Console guessed acquisition truth after refusal"

    finally:
        if lock is not None:
            lock.rmdir()


@pytest.mark.parametrize("owner", ["acquisition", "model", "workspace"])
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("interrupt", [False, True])
def test_RegisteredMainLostAckPreservesActualCommitTruth(
    tmp_path,
    monkeypatch,
    capsys,
    owner,
    after,
    interrupt,
):
    """The registered CLI handler retains unknown acknowledgements before/after actual owner
    saves.
    """

    context = ConsoleContext(tmp_path)
    storage = {
        "acquisition": commands.ApiEvidenceStore,
        "model": LocalModelStore,
        "workspace": LocalWorkspaceStore,
    }[owner]
    name = "Put" if owner == "acquisition" else "Save"
    original = getattr(storage, name)

    def Save(self, *args, **kwargs):
        """Call the real storage boundary only when simulating loss after committed publication."""

        if after:
            original(self, *args, **kwargs)

        if interrupt:
            raise KeyboardInterrupt

        raise OSError("PRIVATE_STORAGE_MARKER")

    monkeypatch.setattr(storage, name, Save)
    status = Main(["api", *Arguments(context), "--json"])
    output = capsys.readouterr()
    assert not output.err, "Registered failure emitted unexpected unsafe diagnostics"
    outcome = json.loads(output.out)
    assert status == (130 if interrupt else 4) and outcome[owner + "_commit"] == "unknown", (
        "Registered CLI guessed success or rollback after lost acknowledgement"
    )
    assert "PRIVATE_STORAGE_MARKER" not in output.out, "Registered failure exposed storage details"
    assert LocalModelStore(context[0]).Open().revision == context[1].revision + int(
        owner == "workspace" or owner == "model" and after
    ), "Registered CLI summary disagreed with the actual saved model owner"
    assert LocalWorkspaceStore(context[0]).Open().revision == int(owner == "workspace" and after), (
        "Registered CLI summary disagreed with the actual saved workspace owner"
    )
