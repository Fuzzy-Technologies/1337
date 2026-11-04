# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual pinned HTTPS CLI routes over owned isolated workers and offline immutable replay."""

from __future__ import annotations

import hashlib
import json
import shutil

import pytest

from fuzzy1337 import intelligence_epss_remote as remote
from fuzzy1337 import intelligence_receiver as receiver
from fuzzy1337.cli import Main
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import LocalModelStore
from tests.e2e.test_intelligence_cli import Files
from tests.e2e.test_intelligence_epss_cli import Body, ImportArguments
from tests.integration.test_intelligence_acquisition_persistence import Context
from tests.unit.test_intelligence_epss_https_commands import Arguments, Refuse


def Run(arguments, capsys):
    """Traverse the actual executable entry point and require a single safe JSON outcome."""

    status = Main(["intel", *arguments, "--json"])
    captured = capsys.readouterr()
    assert not captured.err, "Actual HTTPS CLI emitted diagnostics outside its output profile."

    return status, json.loads(captured.out)


def Selection(root, outcome):
    """Select both exact immutable HTTPS custody roots without any CVE replacement."""

    return ["epss", "https", "inspect", str(root), "--selection", outcome["selection_id"],
            "--receipt", outcome["receipt_id"]]


def OwnedWorker(tmp_path, monkeypatch, *, raw=None, status=200, exit_code=0):
    """Run a real isolated child emitting owned bytes, observing pinned URL and isolation."""

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
        """Observe the real receiver request without admitting a caller URL or ambient settings."""

        arguments = args[0]
        assert arguments[1:3] == ["-I", "-S"] and arguments[4] == (
            "https://raw.githubusercontent.com/empiricalsec/epss_scores/" + "a" * 40
            + "/2026/epss_scores-2026-10-12.csv.gz"
        ), "Actual CLI receiver lost isolation or the immutable pinned source locator."
        assert arguments[-1] == "gzip" and kwargs["env"] == {}, (
            "Actual CLI receiver inherited ambient settings or used the wrong resource profile."
        )
        process = original(*args, **kwargs)
        processes.append(process)

        return process

    monkeypatch.setattr(receiver.subprocess, "Popen", Popen)

    return processes, worker


def test_ActualHttpsCliOwnsWorkerAndReopensAfterRelocationAndInputDeletion(
    tmp_path, monkeypatch, capsys,
):
    """Actual CLI keeps original source meaning and supports read-only offline inspection."""

    model, _ = Context(tmp_path)
    beforeModel = model.Open()
    processes, worker = OwnedWorker(tmp_path, monkeypatch)
    monkeypatch.setattr(LocalModelStore, "Save", Refuse)
    status, acquired = Run(["epss", "https", *Arguments(model.root)], capsys)
    assert status == 0 and acquired["profile"] == "epss-https-selected-cli" and acquired[
        "command"
    ] == "intel.epss.https.fetch", "Actual CLI did not enter the separate HTTPS profile."
    assert len(processes) == 1 and processes[0].poll() == 0, (
        "Actual fetch did not reap exactly one owned isolated receiver child."
    )
    assert all(acquired[name] == "confirmed" for name in (
        "raw_ack", "selection_ack", "receipt_ack",
    )), "Actual HTTPS success omitted independent publication acknowledgement."
    assert acquired["http_status"] == 200 and acquired["receive_state"] == "succeeded" and (
        acquired["body_complete"] and acquired["received_bytes"] == len(Body())
    ), "Actual CLI invented or dropped complete original HTTP receipt facts."
    selected = acquired["selection"]
    assert selected["records"] == [{"identifier": "CVE-1900-9999", "probability": "2e-1",
                                     "percentile": "0.8"}], "CLI changed source scientific lexemes."
    assert selected["unmatched_ids"] == ["CVE-1900-8888"] and selected[
        "requested_ids"
    ] == ["CVE-1900-8888", "CVE-1900-9999"], "Actual CLI changed selected scope or absence."
    assert selected["model_version"] == "synthetic-1" and selected[
        "effective_at"
    ] == "2026-10-12T00:00:00.000000+00:00", "Original source model or score time changed."
    assert acquired["source"]["data_license"] == "not-established" and acquired[
        "publisher_authentication"
    ] == "not-assessed", "HTTPS custody became data licensing or publisher authentication."
    assert acquired["selection_reference"].startswith("epss-https-selection:") and (
        "snapshot_id" not in acquired and acquired["model_commit"] == "not-attempted"
    ), "Separate HTTPS custody reused a legacy snapshot or committed model interpretation."
    store = LocalEvidenceStore(model.root / "evidence")
    raw = store.Get(acquired["raw_id"])
    assert store.Read(raw.reference) == Body() and raw.reference.sha256 == hashlib.sha256(
        Body(),
    ).hexdigest(), "Actual HTTPS fetch changed the original compressed source."
    worker.unlink()
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", Refuse)
    relocated = tmp_path / "relocated"
    shutil.move(model.root, relocated)
    before = Files(relocated)
    status, inspected = Run(Selection(relocated, acquired), capsys)
    assert status == 0 and inspected["selection"] == selected and inspected[
        "source"
    ] == acquired["source"], "Offline relocated inspection changed source assertions."
    assert inspected["http_status"] == 200 and Files(relocated) == before and LocalModelStore(
        relocated,
    ).Open() == beforeModel, "Read-only inspection mutated storage or discarded HTTP proof."
    blob = relocated / "evidence" / raw.reference.locator
    blob.write_bytes(b"x" * raw.reference.size_bytes)
    corruptBefore = Files(relocated)
    status, rejected = Run(Selection(relocated, acquired), capsys)
    assert status == 4 and rejected["failure"] == "integrity" and "selection" not in rejected, (
        "Offline inspection trusted normalized selection despite corrupt original bytes."
    )
    assert Files(relocated) == corruptBefore, "Integrity refusal rewrote owning storage."


@pytest.mark.parametrize("case,expected", [("digest", "digest-mismatch"),
    ("parse", "parse-failed"), ("http", "http-rejected"), ("partial", "transport-failed")])
def test_ActualCliFailureRetainsNetworkAndIndependentStorageFacts(
    tmp_path, monkeypatch, capsys, case, expected,
):
    """Real receiver and SDK failures retain observed HTTP/body facts without usable assertions."""

    model, _ = Context(tmp_path)
    raw = b"invalid owned gzip" if case == "parse" else Body()
    httpStatus = 503 if case == "http" else 200
    exitCode = 3 if case == "http" else (1 if case == "partial" else 0)
    processes, _ = OwnedWorker(tmp_path, monkeypatch, raw=raw, status=httpStatus,
                                exit_code=exitCode)
    arguments = Arguments(model.root)

    if case in ("digest", "parse"):
        arguments[arguments.index("--expected-sha256") + 1] = (
            "0" * 64 if case == "digest" else hashlib.sha256(raw).hexdigest()
        )

    beforeModel = model.Open()
    status, outcome = Run(["epss", "https", *arguments], capsys)
    assert status == 4 and outcome["acquisition_state"] == expected and (
        outcome["status"] == "failed" and "selection" not in outcome
    ), "Actual failed HTTPS acquisition exposed a usable selected assertion."
    assert outcome["http_status"] == httpStatus and outcome["received_bytes"] == len(raw), (
        "Failure output discarded observed original HTTP status or bounded body bytes."
    )
    assert outcome["body_complete"] == (case in ("digest", "parse")) and outcome[
        "selection_ack"
    ] == "not-attempted", "Failure confused transport completeness with normalized publication."
    assert outcome["raw_ack"] == outcome["receipt_ack"] == "confirmed" and (
        outcome["selection_id"] is None and model.Open() == beforeModel
    ), "Failure lost independent custody or changed model state."
    assert len(processes) == 1 and processes[0].poll() is not None, "Failed receiver child leaked."
    store = LocalEvidenceStore(model.root / "evidence")
    assert store.Read(store.Get(outcome["raw_id"]).reference) == raw, (
        "Actual failed acquisition lost unchanged original or partial bytes."
    )


def test_ActualInspectionRejectsLocalCustodyAndSelectionExpansion(tmp_path, monkeypatch, capsys):
    """Local profile roots cannot be relabeled remote, and inspection cannot replace CVE scope."""

    model, _ = Context(tmp_path)
    source = tmp_path / "owned.csv.gz"
    source.write_bytes(Body())
    status, local = Run(ImportArguments(model.root, source), capsys)
    assert status == 0, "Owned local-profile setup failed before remote root refusal."
    before = Files(model.root)
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", Refuse)
    monkeypatch.setattr(LocalModelStore, "Save", Refuse)
    status, rejected = Run(Selection(model.root, local), capsys)
    assert status == 4 and rejected["failure"] == "integrity", (
        "HTTPS inspection relabeled local-profile roots as remote custody."
    )
    status, rejected = Run([*Selection(model.root, local), "--identifier", "CVE-1900-7777"], capsys)
    assert status == 2 and rejected["failure"] == "configuration" and Files(model.root) == before, (
        "Inspection admitted selection expansion or changed owning storage on refusal."
    )
