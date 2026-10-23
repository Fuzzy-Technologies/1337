# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent owned-file OpenAPI product acceptance through installed console and shell."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path

import pytest

from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.findings import Findings
from fuzzy1337.model import LocalModelStore, ModelProvenance, ObjectKind, SecurityObject
from fuzzy1337.requests import Endpoint, RequestsFromObject
from fuzzy1337.shell import InteractiveShell
from fuzzy1337.workspace import LocalWorkspaceStore

FIXTURES = Path(__file__).parents[1] / "contract/fixtures"
ORIGIN = "http://127.0.0.1:19001"


def Console(parent, arguments):
    """Use the installed product entry point with bounded capture and no shell evaluation."""

    executable = Path(sys.executable).parent / ("1337.exe" if os.name == "nt" else "1337")
    result = subprocess.run([str(executable), *arguments, "--json"], cwd=parent,
        capture_output=True, text=True, check=False, timeout=15)
    assert not result.stderr, "The product emitted unexpected source-bearing diagnostics."

    return result.returncode, json.loads(result.stdout)


def Setup(parent, kind):
    """Create explicit offline owners through the console and seed unrelated operator state."""

    root = parent / "Owned API Workspace"
    status, _ = Console(parent, ["workspace", "create", str(root), "--id", "openapi-product",
                                 "--name", "Owned offline API"])
    assert status == 0, "The installed workspace command failed."
    now = datetime.now(timezone.utc)
    status, _ = Console(parent, ["scope", "create", str(root), "--id", "owned",
        "--allow-url", ORIGIN + "/api/ping", "--allow-url", ORIGIN + "/api/notes",
        "--grant-consent", "--owner", "actor:owned", "--consent-reference", "consent:offline",
        "--valid-from", (now - timedelta(minutes=1)).isoformat(),
        "--valid-until", (now + timedelta(hours=1)).isoformat()])
    assert status == 0, "The installed explicit scope command failed."
    store = LocalModelStore(root)
    original = store.Open()
    endpoint = Endpoint(original.workspace_id, ORIGIN, "/api/ping", "GET")
    attribution = ModelProvenance("operator.annotation", "run:prior",
        datetime(2026, 10, 23, tzinfo=timezone.utc).isoformat(), "scope:owned", "target:prior")
    seeded, _ = original.Apply(objects=(SecurityObject(endpoint.Identity(),
        {"operator_note": "retain owned annotation", "reachability": None}, (attribution,)),))
    store.Save(seeded, expected_revision=original.revision)
    source = parent / "Owned Original API.json"
    source.write_bytes((FIXTURES / f"openapi_product.{kind}.json").read_bytes())

    return root, source, attribution


def ImportArguments(root, *, source=None, evidence_id=None, kind="oas"):
    """Bind exact current independent owner revisions and one original source selection."""

    arguments = ["api", "import", "openapi-json", str(root), "--scope", "owned",
        "--run", "run:owned-openapi", "--expected-revision",
        str(LocalModelStore(root).Open().revision), "--expected-workspace-revision",
        str(LocalWorkspaceStore(root).Open().revision)]

    if source is not None:
        arguments.extend(["--file", str(source), "--owner", "actor:owned",
                          "--read-consent-reference", "consent:original-api"])

    else:
        arguments.extend(["--evidence", evidence_id])

    if kind == "oas":
        arguments.extend(["--base-url", ORIGIN + "/"])

    return arguments


@pytest.mark.parametrize("kind", ["oas", "swagger"])
def test_InstalledOpenApiImportMatchesHandwrittenOracleAndReplaysAfterRelocation(tmp_path, kind):
    """Actual offline import preserves typed requests, original custody and operator data."""

    root, source, attribution = Setup(tmp_path, kind)
    raw = source.read_bytes()
    status, first = Console(tmp_path, ImportArguments(root, source=source, kind=kind))
    assert status == 0 and all(first[name] == "confirmed" for name in (
        "acquisition_commit", "model_commit", "workspace_commit",
    )), "The actual import lost its independent storage acknowledgement."
    record = LocalEvidenceStore(root / "evidence").Get(first["evidence_id"])
    assert LocalEvidenceStore(root / "evidence").Read(record.reference) == raw and (
        first["source_sha256"] == hashlib.sha256(raw).hexdigest()
    ), "Product import changed the original source bytes or complete digest."
    oracle = json.loads((FIXTURES / "openapi_product.oracle.json").read_text(encoding="utf-8"))
    model = LocalModelStore(root).Open()
    endpoints = model.Objects(ObjectKind.ENDPOINT)
    assert len(endpoints) == len(oracle["endpoints"]) and not Findings(model), (
        "Descriptive import omitted endpoints or invented vulnerability Findings."
    )

    for item in endpoints:
        templates = RequestsFromObject(item)
        assert len(templates) == 1, "A single declared media variant changed its template count."
        template = templates[0]
        expected = next(row for row in oracle["endpoints"]
                        if row["path"] == template.endpoint.path_template)
        assert template.endpoint.method == expected["method"] and (
            template.body_kind.value == expected["body_kind"]
            and [list(point.Coordinate()) for point in template.injection_points]
            == expected["coordinates"]
        ), "The actual product lost the independent method/body/injection oracle."
        operations = item.attributes["openapi_operations"]
        assert len(operations) == 1 and operations[0]["operation_id"] == expected["operation_id"], (
            "The actual product changed its declared operation identity."
        )
        assert operations[0]["source_pointer"] == expected["source_pointer"] and (
            operations[0]["source_digest"] == "sha256:" + hashlib.sha256(raw).hexdigest()
            and operations[0]["request_reference"] == template.Reference()
        ), "The actual product lost original source-pointer/template joins."

        if expected["method"] == "GET":
            assert item.attributes["operator_note"] == "retain owned annotation" and (
                item.attributes["reachability"] is None and attribution in item.provenance
            ), "Import discarded operator state or its prior attribution."

    assert oracle["raw_only_marker"] not in json.dumps(model.ToDict()) and (
        oracle["raw_only_marker"] not in json.dumps(first)
    ), "Original-only default data leaked into public metadata or presentation."
    references = tuple(item.Reference() for item in model.objects)
    source.unlink()
    relocated = tmp_path / "Relocated API Workspace"
    shutil.move(str(root), relocated)
    status, reopened = Console(tmp_path, ["workspace", "open", str(relocated)])
    assert status == 0 and reopened["verified_evidence_records"] == 1, (
        "Actual relocation/reopen lost original acquisition verification."
    )
    status, replayed = Console(tmp_path, ImportArguments(relocated,
        evidence_id=first["evidence_id"], kind=kind))
    assert status == 0 and replayed["evidence_id"] == first["evidence_id"], (
        "Known-original replay needed the deleted input file or created different custody."
    )
    assert tuple(item.Reference() for item in LocalModelStore(relocated).Open().objects) == (
        references
    ), "Known-original replay changed existing structural identities."


def test_ForegroundShellUsesTheOwnedOpenApiProductRoute(tmp_path):
    """The foreground shell reaches the same original-source import owner and finite profile."""

    root, source, _ = Setup(tmp_path, "swagger")
    arguments = ImportArguments(root, source=source, kind="swagger")
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    assert not shell.onecmd(shlex.join([*arguments, "--json"])), "Import closed the workbench."
    result = json.loads(output.getvalue())
    assert result["status"] == "succeeded" and result["model_commit"] == "confirmed", (
        "The shell did not complete the actual shared product route."
    )
