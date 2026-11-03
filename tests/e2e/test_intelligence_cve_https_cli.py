# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual pinned CVE HTTPS CLI custody over owned isolated workers and offline source replay."""

from __future__ import annotations

import hashlib
import json
import shutil

import pytest

from fuzzy1337 import intelligence_cve_remote as remote
from fuzzy1337 import intelligence_receiver as receiver
from fuzzy1337.cli import Main
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.intelligence import IntelligenceFeed
from fuzzy1337.model import LocalModelStore
from tests.e2e.test_intelligence_cli import Files
from tests.e2e.test_intelligence_cli import ImportArguments as LocalImportArguments
from tests.integration.test_intelligence_acquisition_persistence import Context
from tests.unit.test_intelligence_cve_https_commands import Arguments, Body, Refuse


def Run(arguments, capsys):
    """Traverse actual product dispatch and require one safe caller-stream JSON outcome."""

    status = Main(["intel", *arguments, "--json"])
    captured = capsys.readouterr()
    assert not captured.err, "Actual CVE HTTPS CLI emitted an unintended diagnostic stream."

    return status, json.loads(captured.out)


def Selection(root, outcome):
    """Select both exact immutable remote custody roots without replacing source identity."""

    return ["cve", "https", "inspect", str(root), "--selection", outcome["selection_id"],
            "--receipt", outcome["receipt_id"]]


def OwnedWorker(tmp_path, monkeypatch, *, raw=None, status=200, exit_code=0):
    """Observe a real isolated child with owned bytes, exact source and finite receive limits."""

    raw = Body() if raw is None else raw
    worker = tmp_path / "intelligence_transport.py"
    worker.write_text(
        '# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies\n'
        '# SPDX-License-Identifier: Apache-2.0\n\n'
        '"""Owned receiver fixture; no network or official corpus acceptance claim."""\n'
        'import sys\n'
        'sys.stdout.buffer.write(' + repr((json.dumps({"status": status}) + "\n").encode() + raw)
        + ')\n' + f'sys.exit({exit_code})\n', encoding="utf-8",
    )
    monkeypatch.setattr(receiver, "__file__", str(tmp_path / "intelligence_receiver.py"))
    original = receiver.subprocess.Popen
    processes = []

    def Popen(*args, **kwargs):
        """Observe the actual isolated worker without admitting caller URLs or ambient clients."""

        arguments = args[0]
        assert arguments[1:3] == ["-I", "-S"] and arguments[4] == (
            "https://raw.githubusercontent.com/CVEProject/cvelistV5/" + "a" * 40
            + "/cves/1900/9xxx/CVE-1900-9999.json"
        ), "Actual CVE fetch lost the fixed immutable source or isolated-worker flags."
        assert arguments[5:] == [str(1024 * 1024), "15.0"] and kwargs["env"] == {}, (
            "CVE fetch changed JSON receiver limits or inherited ambient settings."
        )
        process = original(*args, **kwargs)
        processes.append(process)

        return process

    monkeypatch.setattr(receiver.subprocess, "Popen", Popen)

    return processes, worker


def test_ActualCveFetchOwnsWorkerAndOfflineInspectReopensAfterRelocation(
    tmp_path, monkeypatch, capsys,
):
    """The assembled product preserves source assertions and original read-only remote custody."""

    model, _ = Context(tmp_path)
    before_model = model.Open()
    processes, worker = OwnedWorker(tmp_path, monkeypatch)
    monkeypatch.setattr(LocalModelStore, "Save", Refuse)
    status, acquired = Run(["cve", "https", *Arguments(model.root)], capsys)
    assert status == 0 and acquired["profile"] == "cve-https-selected-cli" and acquired[
        "command"
    ] == "intel.cve.https.fetch", "Actual CLI did not enter its separate CVE HTTPS profile."
    assert len(processes) == 1 and processes[0].poll() == 0, (
        "Actual CVE fetch failed to reap exactly one owned isolated worker."
    )
    assert all(acquired[name] == "confirmed" for name in (
        "raw_ack", "selection_ack", "receipt_ack",
    )), "Successful CVE CLI custody omitted an independent publication acknowledgement."
    assert acquired["http_status"] == 200 and acquired["receive_state"] == "succeeded" and (
        acquired["body_complete"] and acquired["received_bytes"] == len(Body())
    ), "CVE output changed observed HTTP completeness or original byte count."
    source = remote.CveHttpsSource("a" * 40, "CVE-1900-9999", hashlib.sha256(Body()).hexdigest())
    assert acquired["source"] == source.ToDict(), "CVE source attribution or fixed notices changed."
    snapshot = acquired["snapshot"]
    records = snapshot["records"]
    assert snapshot["feed"] == "cve-record-5" and snapshot["catalog_version"] == "a" * 40 and len(
        records,
    ) == 1, "Nested CVE snapshot changed source family, revision or explicit record selection."
    record = records[0]
    assert record["identifier"] == "CVE-1900-9999" and record["effective_at"] == (
        "2026-10-12T10:00:00.000000+00:00"
    ), "Original CVE identity or source assertion time changed."
    assert record["data"]["state"] == "PUBLISHED" and record["data"]["cwe_ids"] == [
        "CWE-89",
    ] and record["data"]["unsupported_metrics"] == ["cvssV2_0"], (
        "Source state, weakness assertions or unsupported metrics became inferred conclusions."
    )
    assert record["data"]["cvss"] == [{"version": "3.1", "base_score": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "assessor": "owned-cna"}], (
        "Original supported CVSS source assessment was replaced or relabeled."
    )
    assert acquired["selection_reference"].startswith("cve-https-selection:") and snapshot[
        "reference"
    ].startswith("intel-snapshot:") and "snapshot_id" not in acquired, (
        "Remote selection reused a legacy top-level snapshot identity."
    )
    assert acquired["publisher_authentication"] == "not-assessed" and acquired[
        "target_applicability"
    ] == acquired["risk_assessment"] == "not-evaluated" and acquired[
        "model_commit"
    ] == "not-attempted", "HTTPS custody became publisher, applicability, risk or model assessment."
    store = LocalEvidenceStore(model.root / "evidence")
    raw = store.Get(acquired["raw_id"])
    assert store.Read(raw.reference) == Body(), "CVE fetch changed original source JSON bytes."
    worker.unlink()
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", Refuse)
    relocated = tmp_path / "relocated"
    shutil.move(model.root, relocated)
    before = Files(relocated)
    status, inspected = Run(Selection(relocated, acquired), capsys)
    assert status == 0 and inspected["snapshot"] == snapshot and inspected[
        "source"
    ] == acquired["source"], "Offline relocation changed source facts or required the input."
    assert Files(relocated) == before and LocalModelStore(relocated).Open() == before_model, (
        "Read-only source inspection changed model or retained original custody."
    )
    (relocated / "evidence" / raw.reference.locator).write_bytes(b"x" * raw.reference.size_bytes)
    corrupt_before = Files(relocated)
    status, rejected = Run(Selection(relocated, acquired), capsys)
    assert status == 4 and rejected["failure"] == "integrity" and "snapshot" not in rejected, (
        "Offline CVE inspection trusted normalized assertions despite corrupt original source."
    )
    assert Files(relocated) == corrupt_before, "Integrity refusal rewrote original source storage."


@pytest.mark.parametrize("case,expected", [("digest", "digest-mismatch"),
    ("parse", "parse-failed"), ("http", "http-rejected"), ("partial", "transport-failed"),
    ("rejected", "parse-failed"), ("wire", "parse-failed"), ("identifier", "parse-failed")])
def test_ActualCveFailureKeepsTransportAndIndependentCustodyFacts(
    tmp_path, monkeypatch, capsys, case, expected,
):
    """Receive, source-pin, identity and wire-profile failures retain honest original facts."""

    model, _ = Context(tmp_path)
    raw = Body()

    if case == "parse":
        raw = b"invalid owned JSON"

    elif case in ("rejected", "wire", "identifier"):
        document = json.loads(raw)

        if case == "rejected":
            document["cveMetadata"]["state"] = "REJECTED"

        elif case == "wire":
            document["dataVersion"] = "5.1"

        else:
            document["cveMetadata"]["cveId"] = "CVE-1900-8888"

        raw = json.dumps(document).encode()

    http_status = 503 if case == "http" else 200
    exit_code = 3 if case == "http" else (1 if case == "partial" else 0)
    processes, _ = OwnedWorker(tmp_path, monkeypatch, raw=raw, status=http_status,
                              exit_code=exit_code)
    arguments = Arguments(model.root)
    arguments[arguments.index("--expected-sha256") + 1] = (
        "0" * 64 if case == "digest" else hashlib.sha256(raw).hexdigest()
    )
    before_model = model.Open()
    status, outcome = Run(["cve", "https", *arguments], capsys)
    assert status == 4 and outcome["acquisition_state"] == expected and (
        outcome["status"] == "failed" and "snapshot" not in outcome
    ), "Actual failed CVE acquisition exposed successful source assertions."
    assert outcome["http_status"] == http_status and outcome["received_bytes"] == len(raw), (
        "Failed CVE output discarded actual HTTP status or original byte count."
    )
    assert outcome["body_complete"] == (case not in ("http", "partial")) and outcome[
        "selection_ack"
    ] == "not-attempted", "Source rejection was confused with transport or publication success."
    assert outcome["raw_ack"] == outcome["receipt_ack"] == "confirmed" and outcome[
        "selection_id"
    ] is None and model.Open() == before_model, "Failed CVE acquisition invented model custody."
    assert len(processes) == 1 and processes[0].poll() is not None, "Failed receiver child leaked."
    store = LocalEvidenceStore(model.root / "evidence")
    assert store.Read(store.Get(outcome["raw_id"]).reference) == raw, (
        "Failure replaced retained original or partial source bytes."
    )


def test_ActualCveInspectRejectsLegacyLocalRootsAndIdentifierReplacement(
    tmp_path, monkeypatch, capsys,
):
    """Legacy local snapshots cannot be relabeled HTTPS or expanded by inspection options."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.json"
    source.write_bytes(Body())
    status, local = Run(LocalImportArguments(model.root, source, IntelligenceFeed.CVE), capsys)
    assert status == 0, "Owned local CVE setup failed before remote custody refusal."
    selected = {"selection_id": local["snapshot_id"], "receipt_id": local["receipt_id"]}
    before = Files(model.root)
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", Refuse)
    monkeypatch.setattr(LocalModelStore, "Save", Refuse)
    status, rejected = Run(Selection(model.root, selected), capsys)
    assert status == 4 and rejected["failure"] == "integrity", (
        "Remote CVE inspection accepted local-profile roots as original HTTPS custody."
    )
    status, rejected = Run(
        [*Selection(model.root, selected), "--identifier", "CVE-1900-8888"], capsys,
    )
    assert status == 2 and rejected["failure"] == "configuration" and Files(model.root) == before, (
        "Inspection accepted caller identity replacement or changed retained storage."
    )


def test_ActualUnsupportedApplyHelpCannotBypassNamespaceAdmission(capsys):
    """The complete product router rejects an unsupported apply action even when help is present."""

    status, outcome = Run(["cve", "https", "apply", "--help"], capsys)
    assert status == 2 and outcome["failure"] == "configuration", (
        "General product help bypassed CVE HTTPS action admission."
    )
