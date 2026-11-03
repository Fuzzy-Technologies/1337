# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pinned public-source acceptance cannot turn partial or mismatched CLI facts into success."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

from fuzzy1337 import intelligence_epss_remote as remote
from fuzzy1337.intelligence_epss_remote import EpssHttpsSource

SPEC = importlib.util.spec_from_file_location("epss_https_acceptance",
    Path(__file__).resolve().parents[2] / "tools/epss_https_acceptance.py")
assert SPEC is not None and SPEC.loader is not None, "Acceptance source specification is missing"
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


def Document():
    """Make only controlled terminal facts; original-store verification remains separate."""

    source = EpssHttpsSource(acceptance.SOURCE_COMMIT, acceptance.SOURCE_DAY,
                            acceptance.SOURCE_MODEL, acceptance.EXPECTED_SHA256)

    return {"profile": "epss-https-selected-cli", "command": "intel.epss.https.fetch",
        "status": "succeeded", "acquisition_state": "succeeded", "receive_state": "succeeded",
        "transport": "https", "http_status": 200, "body_complete": True,
        "received_bytes": acceptance.EXPECTED_BYTES, "source_sha256": acceptance.EXPECTED_SHA256,
        "source": source.ToDict(), "raw_ack": "confirmed", "selection_ack": "confirmed",
        "receipt_ack": "confirmed", "model_commit": "not-attempted",
        "publisher_authentication": "not-assessed", "raw_id": "sha256:" + "a" * 64,
        "selection_id": "sha256:" + "b" * 64, "receipt_id": "sha256:" + "c" * 64}


def test_ExactPinnedTerminalStillRequiresLaterOriginalCustodyVerification():
    """The finite preflight accepts only exact expected terminal metadata."""

    document = Document()
    assert acceptance.VerifyFetch(document) is document, "Pinned terminal preflight changed facts"


@pytest.mark.parametrize("field,value", [
    ("profile", "local"), ("command", "intel.epss.import"), ("status", "failed"),
    ("acquisition_state", "timed-out"), ("receive_state", "transport-failed"),
    ("transport", "local-bytes"), ("http_status", True), ("http_status", 302),
    ("body_complete", 1), ("body_complete", False), ("received_bytes", True),
    ("received_bytes", 0), ("source_sha256", "0" * 64), ("source", {}),
    ("raw_ack", "unknown"), ("selection_ack", "not-attempted"), ("receipt_ack", "unknown"),
    ("model_commit", "confirmed"), ("publisher_authentication", "verified"),
    ("raw_id", None), ("selection_id", "epss-selection:" + "b" * 64),
    ("receipt_id", "sha256:" + "b" * 64),
])
def test_PartialMisattributedOrUnacknowledgedTerminalFactsCannotPass(field, value):
    """Malformed or independently failed source facts refuse before original reads."""

    document = Document()
    document[field] = value

    with pytest.raises(ValueError):
        acceptance.VerifyFetch(document)


@pytest.mark.parametrize("document", [None, [], "succeeded"])
def test_NonObjectTerminalRefuses(document):
    """A textual success marker is not structured original acquisition evidence."""

    with pytest.raises(ValueError):
        acceptance.VerifyFetch(document)


def test_ExistingAcceptanceOutputIsNeverRewritten(tmp_path):
    """A repeated invocation refuses before fetch and preserves earlier evidence exactly."""

    output = tmp_path / "original"
    output.mkdir()
    original = output / "acceptance.json"
    original.write_text('{"status":"passed"}\n', encoding="utf-8")
    before = {p.name: p.read_bytes() for p in output.iterdir()}
    status = acceptance.Main(["--output", str(output)])
    assert status == 1 and {p.name: p.read_bytes() for p in output.iterdir()} == before, (
        "Repeated acceptance overwrote original evidence or attempted another fetch"
    )


def test_ActualStoredSourceCannotBeReplacedByPinnedTerminalSource(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Valid same-byte custody under another commit cannot inherit the terminal's source pin.

    Args:
        tmp_path: Disposable owning workspace and acceptance evidence directory.
        monkeypatch: Scoped owned receiver, expected corpus and terminal substitutions.
    """

    csv = (f"#model_version:{acceptance.SOURCE_MODEL},"
           f"score_date:{acceptance.SOURCE_DAY}T12:00:30Z\n"
           "cve,epss,percentile\nCVE-1999-0001,0.1,0.2\n"
           "CVE-2023-20914,0.2,6e-05\n").encode("utf-8")
    payload = gzip.compress(csv, mtime=0)

    for name, value in {
        "EXPECTED_SHA256": hashlib.sha256(payload).hexdigest(),
        "EXPECTED_DECODED_SHA256": hashlib.sha256(csv).hexdigest(),
        "EXPECTED_BYTES": len(payload), "EXPECTED_DECODED_BYTES": len(csv), "EXPECTED_ROWS": 2,
    }.items():
        monkeypatch.setattr(acceptance, name, value)

    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", lambda *args, **kwargs:
                        (payload, "succeeded", 200))
    observed_sources = []

    def Run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        """Publish genuine fixture custody, then spoof only the terminal's declared source.

        Args:
            command: Actual pinned product invocation selecting the created owning workspace.
            kwargs: Unchanged subprocess controls; no real process is launched by this fixture.

        Returns:
            Controlled successful terminal with genuine artifacts and inconsistent source facts.
        """

        root = Path(command[command.index("fetch") + 1])
        alternate = EpssHttpsSource("b" * 40, acceptance.SOURCE_DAY, acceptance.SOURCE_MODEL,
                                   acceptance.EXPECTED_SHA256)
        acquired = remote.AcquireHttpsEpssSelection(
            root, remote.EpssHttpsRequest(alternate, acceptance.SELECTED_IDS),
            scope_reference="scope:owned-acceptance-fixture",
        )
        assert acquired.state is remote.EpssHttpsState.SUCCEEDED and acquired.envelope, (
            "The alternate-source fixture must retain valid actual original custody"
        )
        assert remote.LoadHttpsEpssSelection(
            root, acquired.selection_record.evidence_id, acquired.receipt.evidence_id,
        ) == acquired.envelope, "The alternate-source fixture must independently reopen"
        observed_sources.append(acquired.envelope.source.commit)
        document = Document()
        document.update({
            "raw_id": acquired.raw.evidence_id,
            "selection_id": acquired.selection_record.evidence_id,
            "receipt_id": acquired.receipt.evidence_id,
            "selection": acquired.envelope.selection.ToDict(),
            "selection_reference": acquired.envelope.Reference(),
        })

        return subprocess.CompletedProcess(command, 0, json.dumps(document), "")

    monkeypatch.setattr(acceptance.subprocess, "run", Run)

    with pytest.raises(ValueError):
        acceptance.RunAcceptance(tmp_path / "acceptance")

    assert observed_sources == ["b" * 40], "The refusal must follow actual alternate custody"
    assert not (tmp_path / "acceptance" / "acceptance.json").exists(), (
        "A spoofed terminal source published a successful acceptance marker"
    )
