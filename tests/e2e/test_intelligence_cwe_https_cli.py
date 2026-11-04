# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Assembled CWE HTTPS CLI custody over owned isolated ZIP worker fixtures."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

import pytest

from fuzzy1337 import intelligence_cwe_remote as remote
from fuzzy1337 import intelligence_receiver as receiver
from fuzzy1337.cli import Main
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import LocalModelStore
from tests.e2e.test_intelligence_cli import Files
from tests.integration.test_intelligence_acquisition_persistence import Context
from tests.unit.test_intelligence_cwe_https_commands import (
    Body,
    FetchArguments,
    InspectArguments,
    Refuse,
    RequireNoSelection,
)


def Run(arguments, capsys):
    """Call the actual product router and parse one clean machine document."""

    status = Main(["intel", "cwe", "https", *arguments, "--json"])
    captured = capsys.readouterr()
    assert not captured.err, "The product emitted diagnostics on a separate stream"

    return status, json.loads(captured.out)


def Worker(root, raw):
    """Provide an owned isolated child body without external network access."""

    path = root / "intelligence_transport.py"
    payload = b'{"status":200}\n' + raw
    path.write_text(
        '"""Owned ZIP receiver fixture with a synthetic HTTP status."""\n'
        "import sys\n"
        f"sys.stdout.buffer.write({payload!r})\n",
        encoding="utf-8",
    )

    return path


@pytest.mark.parametrize("version,schema", [("5.0", "8.0"), ("4.21", "7.4")])
def test_ActualFetchOwnsOneIsolatedWorkerAndRelocatedReplayWritesNothing(
    tmp_path, monkeypatch, capsys, version, schema,
):
    """Verify assembled routing, bounded receiver execution and read-only exact-root replay."""

    model, _ = Context(tmp_path)
    beforeModel = model.Open()
    raw = Body(version, name="Owned é ▼ 😀 source")
    worker = Worker(tmp_path, raw)
    monkeypatch.setattr(receiver, "__file__", str(tmp_path / "intelligence_receiver.py"))
    original = receiver.subprocess.Popen
    processes = []

    def Popen(*args, **kwargs):
        """Observe the real isolated worker's fixed resource and empty environment."""

        arguments = args[0]
        assert arguments[1:4] == ["-I", "-S", str(worker)], "The child lost isolation"
        assert arguments[4:] == [
            f"https://cwe.mitre.org/data/xml/cwec_v{version}.xml.zip", str(len(raw)), "15.0", "zip",
        ], "The CLI changed source identity, finite limits or resource kind"
        assert kwargs["env"] == {}, "The receiver inherited ambient settings"
        process = original(*args, **kwargs)
        processes.append(process)

        return process

    monkeypatch.setattr(receiver.subprocess, "Popen", Popen)
    monkeypatch.setattr(LocalModelStore, "Save", Refuse)
    status, acquired = Run([
        *FetchArguments(model.root, raw, version), "--max-bytes", str(len(raw)),
    ], capsys)
    assert status == 0 and acquired["command"] == "intel.cwe.https.fetch", (
        "The actual route did not complete its distinct HTTPS CLI profile"
    )
    assert len(processes) == 1 and processes[0].poll() == 0, "Expected one reaped receiver"
    assert acquired["profile"] == "cwe-https-selected-cli" and acquired[
        "transport_profile"
    ] == remote.TRANSPORT_PROFILE, "The output lost its selected transport identity"
    assert acquired["ack_basis"] == "sdk-returned" and all(
        acquired[key] == "confirmed" for key in ("raw_ack", "selection_ack", "receipt_ack")
    ), "Successful acquisition omitted an independent publication acknowledgement"
    assert acquired["http_status"] == 200 and acquired["body_complete"] is True, (
        "The synthetic worker's complete response facts were lost"
    )
    assert acquired["limits"] == {"max_zip_bytes": len(raw), "timeout_seconds": 15.0}, (
        "The finite request facts were changed in presentation"
    )
    selected = acquired["selection"]
    assert selected["catalog_version"] == version and selected["cwe_schema_version"] == schema, (
        "The exact catalog or schema profile changed"
    )
    assert selected["records"][0]["identifier"] == "CWE-79" and selected["records"][0][
        "name"
    ] == "Owned é ▼ 😀 source", "A matched source assertion changed"
    assert selected["unsupported_entries"] == [{"identifier": "CWE-1000", "source_kind": "View"}], (
        "An unsupported source kind became a Weakness record"
    )
    assert selected["unmatched_ids"] == ["CWE-999"], "An absent ID became a risk assertion"
    assert acquired["source"]["notice_bundle"]["text"].endswith("[image alt: HSSEDI]\n"), (
        "The CLI omitted part of the captured notice"
    )
    store = LocalEvidenceStore(model.root / "evidence")
    originalRecord = store.Get(acquired["raw_id"])
    assert store.Read(originalRecord.reference) == raw, "CLI custody changed original ZIP bytes"
    assert all(store.Get(acquired[key]).provenance == originalRecord.provenance
               for key in ("selection_id", "receipt_id")), "Custody roots lost joined provenance"
    assert model.Open() == beforeModel, "Acquisition wrote authoritative model state"

    worker.unlink()
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", Refuse)
    monkeypatch.setattr(receiver.subprocess, "Popen", Refuse)
    monkeypatch.setattr(LocalEvidenceStore, "Put", Refuse)
    relocated = tmp_path / "relocated"
    shutil.move(model.root, relocated)
    before = Files(relocated)
    status, inspected = Run(InspectArguments(relocated, acquired), capsys)
    assert status == 0 and inspected["command"] == "intel.cwe.https.inspect", (
        "Relocated exact-root custody failed"
    )
    assert inspected["ack_basis"] == "verified-present", "Replay claimed historical returned ACKs"
    assert all(inspected[key] == acquired[key] for key in (
        "source", "selection", "selection_reference", "limits", "http_status", "source_sha256",
    )), "Offline inspection changed verified original facts"
    status = Main(["intel", "cwe", "https", *InspectArguments(relocated, acquired)])
    captured = capsys.readouterr()
    assert status == 0 and not captured.err, "Human replay failed through the product entry point"
    assert all(line in captured.out for line in (
        "CWE-79: Weakness, Owned \\xe9 \\u25bc \\U0001f600 source",
        "CWE-1000: unsupported source kind View",
        "Not present in this selected source: CWE-999",
        "[image alt: HSSEDI]",
    )), "Human replay lost source facts or merged distinct source partitions"
    assert Files(relocated) == before, "Offline inspection wrote owning files"
    status, refused = Run([*InspectArguments(relocated, acquired), "--max-bytes", "123"], capsys)
    assert status == 2 and refused["failure"] == "configuration", "Inspect replaced custody limits"
    assert Files(relocated) == before, "Rejected inspection changed owning files"
    RequireNoSelection(refused)


def test_HumanConfigurationFailureDoesNotEchoCallerData(capsys):
    """The real human failure path preserves a fixed diagnostic and no caller data."""

    status = Main(["intel", "cwe", "https", "apply", "owned-untrusted-value"])
    captured = capsys.readouterr()
    assert status == 2 and "failure: configuration" in captured.out and not captured.err, (
        "Human invalid configuration was not translated into a fixed terminal outcome"
    )
    assert "owned-untrusted-value" not in captured.out, "Human failure exposed caller arguments"


@pytest.mark.parametrize("artifact", ["raw_id", "selection_id", "receipt_id"])
def test_ActualInspectRejectsCorruptionWithoutLeakingUsableFacts(
    tmp_path, monkeypatch, capsys, artifact,
):
    """Corruption of any custody body fails read-only replay through the product route."""

    model, _ = Context(tmp_path)
    raw = Body()
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps",
                        lambda *args, **kwargs: (raw, "succeeded", 200))
    status, acquired = Run(FetchArguments(model.root, raw), capsys)
    assert status == 0, "Owned fixture acquisition failed"
    store = LocalEvidenceStore(model.root / "evidence")
    record = store.Get(acquired[artifact])
    (model.root / "evidence" / record.reference.locator).write_bytes(b"owned corrupt bytes")
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", Refuse)
    before = Files(model.root)
    status, refused = Run(InspectArguments(model.root, acquired), capsys)
    assert status == 4 and refused["failure"] == "integrity", "Corruption became verified custody"
    assert refused["ack_basis"] == "not-attempted", "Unverified roots were acknowledged"
    RequireNoSelection(refused)
    assert Files(model.root) == before, "Refused replay changed owning files"


CHILD = """import sys
from fuzzy1337 import intelligence_receiver as receiver
from fuzzy1337.cli import Main
assert sys.stdout.encoding == sys.argv[1] and sys.stdout.errors == "strict", (
    "Product child used the wrong narrow stdout codec"
)
receiver.__file__ = sys.argv[2]
raise SystemExit(Main(["intel", "cwe", "https", *sys.argv[3:]]))
"""


@pytest.mark.parametrize("codec", ["ascii", "cp1252"])
def test_ActualNarrowChildWritesLosslessJsonAndCompleteHumanNotice(tmp_path, codec):
    """The actual command writes portable output through strict legacy-code-page streams."""

    environment = {**os.environ, "PYTHONUTF8": "0", "PYTHONIOENCODING": codec + ":strict"}
    model, _ = Context(tmp_path)
    name = "Owned é ▼ 😀 source"
    raw = Body(name=name)
    worker = Worker(tmp_path, raw)
    invocation = [sys.executable, "-c", CHILD, codec,
                  str(tmp_path / "intelligence_receiver.py")]
    result = subprocess.run(
        [*invocation, *FetchArguments(model.root, raw), "--json"],
        env=environment, capture_output=True, timeout=30, check=False,
    )
    assert result.returncode == 0 and not result.stderr and result.stdout.isascii(), (
        "Strict redirected fetch failed or emitted nonportable stdout"
    )
    acquired = json.loads(result.stdout)
    assert acquired["selection"]["records"][0]["name"] == name, "JSON changed source Unicode"
    assert "▼" in acquired["source"]["notice_bundle"]["text"], "JSON changed the notice"
    worker.unlink()
    before = Files(model.root)
    inspected = subprocess.run(
        [*invocation, *InspectArguments(model.root, acquired)],
        env=environment, capture_output=True, timeout=30, check=False,
    )
    assert inspected.returncode == 0 and not inspected.stderr and inspected.stdout.isascii(), (
        "Strict redirected human inspection failed or emitted nonportable stdout"
    )
    assert all(token in inspected.stdout for token in (
        b"\\u25bc", b"\\U0001f600", b"[image alt: HSSEDI]",
        b"HTTP facts describe the original acquisition verified offline.",
    )), "Human output omitted escaped source text, notice footer or historical context"
    assert Files(model.root) == before, "Portable inspection wrote owning files"


def test_ActualHelpLeavesTheRemoteSdkUnimported():
    """The full dispatcher handles exact help without initializing the remote SDK."""

    driver = """import sys
from fuzzy1337.cli import Main
status = Main(["intel", "cwe", "https", "fetch", "--help"])
assert "fuzzy1337.intelligence_cwe_remote" not in sys.modules, "Help initialized the remote SDK"
raise SystemExit(status)
"""
    result = subprocess.run([sys.executable, "-c", driver], capture_output=True, timeout=15,
                            check=False)
    assert result.returncode == 0 and not result.stderr, "Exact help imported the SDK or failed"
    assert b"usage: 1337 intel cwe https fetch" in result.stdout, "Help was routed elsewhere"
