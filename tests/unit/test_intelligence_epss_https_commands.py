# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pinned HTTPS CLI admission, independent custody acknowledgements and safe presentation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from io import StringIO

import pytest

from fuzzy1337 import intelligence_epss_https_commands as commands
from fuzzy1337 import intelligence_epss_remote as remote
from fuzzy1337.evidence import EvidenceError
from tests.e2e.test_intelligence_cli import Files
from tests.e2e.test_intelligence_epss_cli import Body
from tests.integration.test_intelligence_acquisition_persistence import Context


def Arguments(root):
    """Declare one immutable synthetic pinned body with two explicit CVE selections."""

    return ["fetch", str(root), "--commit", "a" * 40, "--score-date", "2026-10-12",
            "--model-version", "synthetic-1", "--expected-sha256",
            hashlib.sha256(Body()).hexdigest(),
            "--identifier", "CVE-1900-9999", "--identifier", "CVE-1900-8888",
            "--scope", "scope:owned"]


def Run(arguments, *, human=False):
    """Invoke the owned handler with caller-owned output and deterministic JSON parsing."""

    output = StringIO()
    status = commands.RunEpssHttpsCommands(arguments, output, json_output=not human)

    return status, output.getvalue() if human else json.loads(output.getvalue())


def Refuse(*args, **kwargs):
    """Trip on any network acquisition, model save or workspace read outside its contract."""

    raise AssertionError("Forbidden side effect reached the HTTPS CLI boundary.")


@pytest.mark.parametrize("arguments", [[], ["apply", "--help"], ["latest", "--help"],
    ["fetch", "untrusted-value"], ["inspect", "untrusted-value"],
    ["--help", "--source-url", "untrusted-value"], ["fetch", "--help", "--apply"]])
def test_InvalidGrammarNeverEchoesRejectedValues(arguments, monkeypatch):
    """Unsupported actions and help bypasses remain fixed configuration failures."""

    monkeypatch.setattr(remote, "AcquireHttpsEpssSelection", Refuse)
    status, outcome = Run(arguments)
    assert status == 2 and outcome["failure"] == "configuration", (
        "Malformed HTTPS grammar escaped fixed configuration diagnostics."
    )
    assert "untrusted-value" not in json.dumps(outcome), "Rejected source values leaked."


@pytest.mark.parametrize("arguments,expected", [(["--help"], "fetch,inspect"),
    (["-h"], "fetch,inspect"), (["fetch", "--help"], "--commit"),
    (["inspect", "-h"], "--selection")])
def test_HelpDoesNotReadWorkspace(arguments, expected, monkeypatch):
    """Supported focused help exposes the explicit namespace without storage or network."""

    monkeypatch.setattr(commands.LocalWorkspaceStore, "Open", Refuse)
    monkeypatch.setattr(remote, "AcquireHttpsEpssSelection", Refuse)
    status, text = Run(arguments, human=True)
    assert status == 0 and expected in text, "HTTPS help lost its explicit action contract."


@pytest.mark.parametrize("case", ["commit", "uppercase", "date", "model", "pin", "scope",
    "max-zero", "max-large", "max-type", "timeout-zero", "timeout-large", "timeout-nan",
    "timeout-inf", "timeout-type", "identifier", "duplicate-id", "many-ids", "duplicate",
    "abbreviation", "url", "latest", "publisher", "license", "payload", "workspace"])
def test_AdmissionBeforeWorkspaceOrNetwork(tmp_path, monkeypatch, case):
    """All source, scope, identifier and budget constraints precede workspace or receiver reads."""

    arguments = Arguments(tmp_path / "absent")

    if case in ("duplicate-id", "many-ids"):
        values = ["CVE-1900-9999"] if case == "duplicate-id" else [
            f"CVE-1900-{10000 + index}" for index in range(63)
        ]

        for value in values:
            arguments.extend(["--identifier", value])

    elif case == "duplicate":
        arguments.append("--commit=" + "b" * 40)

    elif case == "abbreviation":
        arguments[arguments.index("--commit")] = "--com"

    elif case == "workspace":
        arguments[1] = "../untrusted-value"

    else:
        name, value = {
            "commit": ("--commit", "main"), "uppercase": ("--commit", "A" * 40),
            "date": ("--score-date", "2026-02-30"), "model": ("--model-version", ""),
            "pin": ("--expected-sha256", "untrusted-value"), "scope": ("--scope", ""),
            "max-zero": ("--max-bytes", "0"), "max-large": ("--max-bytes", "4194305"),
            "max-type": ("--max-bytes", "untrusted-value"),
            "timeout-zero": ("--timeout-seconds", "0.049"),
            "timeout-large": ("--timeout-seconds", "60.1"),
            "timeout-nan": ("--timeout-seconds", "nan"),
            "timeout-inf": ("--timeout-seconds", "inf"),
            "timeout-type": ("--timeout-seconds", "untrusted-value"),
            "identifier": ("--identifier", "CWE-89"),
            "url": ("--source-url", "https://example.invalid/untrusted-value"),
            "latest": ("--latest", "untrusted-value"),
            "publisher": ("--publisher", "untrusted-value"),
            "license": ("--license-name", "untrusted-value"),
            "payload": ("--payload", "untrusted-value"),
        }[case]

        if name in arguments:
            arguments[arguments.index(name) + 1] = value

        else:
            arguments.extend([name, value])

    monkeypatch.setattr(commands.LocalWorkspaceStore, "Open", Refuse)
    monkeypatch.setattr(remote, "AcquireHttpsEpssSelection", Refuse)
    status, outcome = Run(arguments)
    assert status == 2 and outcome["failure"] == "configuration", (
        "Invalid pinned source or finite admission escaped preflight."
    )
    assert all(outcome[name] == "not-attempted" for name in (
        "raw_ack", "selection_ack", "receipt_ack",
    )), "Configuration refusal invented storage attempts."
    assert "untrusted-value" not in json.dumps(outcome), "Admission leaked rejected metadata."


@pytest.mark.parametrize("kind", ["missing", "file", "symlink", "parent-symlink"])
def test_PhysicalExistingWorkspaceRequiredBeforeAcquisition(tmp_path, monkeypatch, kind):
    """A real existing owning workspace is mandatory; lexical or linked substitutions fail."""

    model, _ = Context(tmp_path)
    root = tmp_path / "selected"

    if kind == "file":
        root.write_text("owned fixture", encoding="utf-8")

    elif kind == "symlink":
        root.symlink_to(model.root, target_is_directory=True)

    elif kind == "parent-symlink":
        root.symlink_to(tmp_path, target_is_directory=True)
        root = root / model.root.name

    monkeypatch.setattr(remote, "AcquireHttpsEpssSelection", Refuse)
    before = Files(model.root)
    status, outcome = Run(Arguments(root))
    assert status in (2, 4) and outcome["status"] == "failed", (
        "Missing or linked workspace reached HTTPS acquisition."
    )
    assert outcome["raw_ack"] == "not-attempted" and Files(model.root) == before, (
        "Workspace refusal changed custody or invented publication."
    )


@pytest.fixture(name="acquired_context")
def Acquired(tmp_path, monkeypatch):
    """Acquire real immutable artifacts using deterministic original bytes and no network."""

    model, _ = Context(tmp_path)
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", lambda *a, **k: (Body(), "succeeded", 200))
    request = remote.EpssHttpsRequest(
        remote.EpssHttpsSource("a" * 40, "2026-10-12", "synthetic-1",
                              hashlib.sha256(Body()).hexdigest()),
        ("CVE-1900-8888", "CVE-1900-9999"),
    )
    acquired = remote.AcquireHttpsEpssSelection(model.root, request, scope_reference="scope:owned")
    assert acquired.state is remote.EpssHttpsState.SUCCEEDED, "Owned custody fixture failed."

    return model, acquired


@pytest.mark.parametrize("case", ["state", "http", "raw_ack", "selection_ack", "receipt_ack",
                                  "raw", "envelope", "selection_record", "receipt"])
def test_SuccessRequiresAllIndependentFacts(acquired_context, monkeypatch, case):
    """A success token, complete body or subset of handles cannot substitute for full custody."""

    model, acquired = acquired_context

    if case == "state":
        acquired = replace(acquired, state=remote.EpssHttpsState.STORAGE_FAILED)

    elif case == "http":
        acquired = replace(acquired, http_status=503, body_complete=False,
                           receive_state="http-rejected")

    elif case.endswith("_ack"):
        acquired = replace(acquired, **{case: remote.EpssHttpsAcknowledgement.UNKNOWN})

    else:
        acquired = replace(acquired, **{case: None})

    monkeypatch.setattr(remote, "AcquireHttpsEpssSelection", lambda *a, **k: acquired)
    status, outcome = Run(Arguments(model.root))
    assert status == 4 and outcome["status"] == "failed" and "selection" not in outcome, (
        "Incomplete custody became usable source assertions."
    )
    assert outcome["http_status"] == acquired.http_status and outcome[
        "body_complete"
    ] == acquired.body_complete, "Failure discarded observed network facts."
    assert outcome["raw_ack"] == acquired.raw_ack.value and outcome[
        "selection_ack"
    ] == acquired.selection_ack.value and outcome["receipt_ack"] == acquired.receipt_ack.value, (
        "Independent acknowledgement uncertainty was overwritten."
    )


@pytest.mark.parametrize("failure", [KeyboardInterrupt, EvidenceError, OSError, ValueError])
def test_UnexpectedEnteredAcquisitionKeepsUnknownAcks(tmp_path, monkeypatch, failure):
    """Interrupted or exceptional acquisition cannot assert rollback or unobserved publication."""

    model, _ = Context(tmp_path)

    def Fail(*args, **kwargs):
        """Raise after entering acquisition without returning observed custody acknowledgements."""

        raise failure("untrusted-value")

    monkeypatch.setattr(remote, "AcquireHttpsEpssSelection", Fail)
    status, outcome = Run(Arguments(model.root))
    assert status == (130 if failure is KeyboardInterrupt else 4), "Wrong terminal failure status."
    assert all(outcome[name] == "unknown" for name in (
        "raw_ack", "selection_ack", "receipt_ack",
    )), "Unobserved storage acknowledgements became negative or successful facts."
    assert outcome["http_status"] is None and "untrusted-value" not in json.dumps(outcome), (
        "Exceptional acquisition fabricated a status or exposed exception content."
    )


def test_SuccessfulHumanPresentationRetainsSourceMeaning(acquired_context, monkeypatch):
    """Human output preserves scientific lexemes, unmatched IDs, terms and applicability limits."""

    model, acquired = acquired_context
    monkeypatch.setattr(remote, "AcquireHttpsEpssSelection", lambda *a, **k: acquired)
    status, text = Run(Arguments(model.root), human=True)
    assert status == 0 and len(text) < 12000, "Human source output was unsuccessful or unbounded."
    assert all(value in text for value in ("2e-1", "0.8", "CVE-1900-8888", "synthetic-1",
        "2026-10-12", "next 30 days", "not assessed", "not established",
        "https://www.first.org/epss/faq", "https://www.first.org/about/policies/terms")), (
        "Human presentation changed score assertions or dropped honest source attribution."
    )
    assert not any(ord(character) < 32 and character != "\n" for character in text), (
        "Human presentation emitted terminal control bytes."
    )


@pytest.mark.parametrize("case", ["selection", "receipt", "missing-receipt", "duplicate-receipt",
                                  "scope", "model", "network", "apply-help"])
def test_InspectRequiresExactRootsAndNoReplacementArguments(acquired_context, monkeypatch, case):
    """Offline inspection rejects absent custody or fetch/apply options without receiver access."""

    model, acquired = acquired_context
    arguments = ["inspect", str(model.root), "--selection", acquired.selection_record.evidence_id,
                 "--receipt", acquired.receipt.evidence_id]

    if case in ("selection", "receipt"):
        arguments[arguments.index("--" + case) + 1] = "sha256:" + "0" * 64

    elif case == "missing-receipt":
        arguments = arguments[:-2]

    elif case == "duplicate-receipt":
        arguments.extend(["--receipt", acquired.receipt.evidence_id])

    elif case == "apply-help":
        arguments = ["apply", "--help"]

    else:
        arguments.extend({"scope": ["--scope", "scope:replacement"],
                          "model": ["--model-version", "replacement"],
                          "network": ["--timeout-seconds", "15"]}[case])

    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", Refuse)
    before = Files(model.root)
    status, outcome = Run(arguments)
    expected = 4 if case in ("selection", "receipt") else 2
    assert status == expected and outcome["status"] == "failed" and "selection" not in outcome, (
        "Inspection accepted missing exact roots or replacement source/application arguments."
    )
    assert Files(model.root) == before, "Read-only inspection refusal changed retained storage."


def test_FailedHumanPresentationHasSafeFixedFacts(tmp_path, monkeypatch):
    """Human configuration failure exposes useful bounded facts without rejected control content."""

    monkeypatch.setattr(remote, "AcquireHttpsEpssSelection", Refuse)
    status, text = Run(["fetch", str(tmp_path), "--source-url", "\x1b[31muntrusted"], human=True)
    assert status == 2 and "configuration" in text and "not-attempted" in text, (
        "Failed human output lost the fixed failure and custody-attempt facts."
    )
    assert "\x1b" not in text and "untrusted" not in text, "Human failure leaked rejected controls."
