# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pinned HTTPS CLI admission, independent custody acknowledgements and safe presentation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from io import StringIO

import pytest

from fuzzy1337 import intelligence_cve_https_commands as commands
from fuzzy1337 import intelligence_cve_remote as remote
from fuzzy1337.evidence import EvidenceError
from tests.e2e.test_intelligence_cli import Files
from tests.integration.test_intelligence_acquisition_persistence import Context


def Body():
    """Return owned PUBLISHED CVE 5.2 assertions with supported and unsupported source metrics."""

    return json.dumps({
        "dataType": "CVE_RECORD", "dataVersion": "5.2",
        "cveMetadata": {"cveId": "CVE-1900-9999", "state": "PUBLISHED",
                        "dateUpdated": "2026-10-12T10:00:00Z"},
        "containers": {"cna": {"providerMetadata": {"orgId": "owned-cna"},
            "descriptions": [{"lang": "en", "value": "Owned synthetic CVE assertion"}],
            "problemTypes": [{"descriptions": [{"cweId": "CWE-89"}]}],
            "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": 9.8,
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
                {"cvssV2_0": {"version": "2.0", "baseScore": 10.0,
                               "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C"}}]}}}).encode()


def Arguments(root):
    """Declare one immutable byte-pinned CVE source without caller-supplied URL or source claims."""

    return ["fetch", str(root), "--commit", "a" * 40, "--identifier", "CVE-1900-9999",
            "--expected-sha256", hashlib.sha256(Body()).hexdigest(), "--scope", "scope:owned"]


def Run(arguments, *, human=False):
    """Invoke the owned handler with caller-owned output and deterministic JSON parsing."""

    output = StringIO()
    status = commands.RunCveHttpsCommands(arguments, output, json_output=not human)

    return status, output.getvalue() if human else json.loads(output.getvalue())


def Refuse(*args, **kwargs):
    """Trip on any network acquisition, model save or workspace read outside its contract."""

    raise AssertionError("Forbidden side effect reached the HTTPS CLI boundary.")


@pytest.mark.parametrize("arguments", [[], ["apply", "--help"], ["latest", "--help"],
    ["fetch", "untrusted-value"], ["inspect", "untrusted-value"],
    ["--help", "--source-url", "untrusted-value"], ["fetch", "--help", "--apply"]])
def test_InvalidGrammarNeverEchoesRejectedValues(arguments, monkeypatch):
    """Unsupported actions and help bypasses remain fixed configuration failures."""

    monkeypatch.setattr(remote, "AcquireHttpsCveSelection", Refuse)
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
    monkeypatch.setattr(remote, "AcquireHttpsCveSelection", Refuse)
    status, text = Run(arguments, human=True)
    assert status == 0 and expected in text, "HTTPS help lost its explicit action contract."


@pytest.mark.parametrize("case", ["commit", "uppercase", "pin", "scope", "identifier",
    "lowercase-id", "space-id", "duplicate-id", "max-zero", "max-large", "max-type",
    "timeout-zero", "timeout-large", "timeout-nan", "timeout-inf", "timeout-type", "duplicate",
    "abbreviation", "url", "latest", "publisher", "license", "payload", "model", "workspace"])
def test_AdmissionBeforeWorkspaceOrNetwork(tmp_path, monkeypatch, case):
    """Source identity, scalar uniqueness, scope and finite limits validate before owning reads."""

    arguments = Arguments(tmp_path / "absent")

    if case in ("duplicate", "duplicate-id"):
        arguments.append("--commit=" + "b" * 40 if case == "duplicate" else
                         "--identifier=CVE-1900-8888")

    elif case == "abbreviation":
        arguments[arguments.index("--commit")] = "--com"

    elif case == "workspace":
        arguments[1] = "../untrusted-value"

    else:
        name, value = {
            "commit": ("--commit", "main"), "uppercase": ("--commit", "A" * 40),
            "pin": ("--expected-sha256", "untrusted-value"), "scope": ("--scope", ""),
            "identifier": ("--identifier", "CWE-89"),
            "lowercase-id": ("--identifier", "cve-1900-9999"),
            "space-id": ("--identifier", " CVE-1900-9999"),
            "max-zero": ("--max-bytes", "0"), "max-large": ("--max-bytes", "1048577"),
            "max-type": ("--max-bytes", "untrusted-value"),
            "timeout-zero": ("--timeout-seconds", "0.049"),
            "timeout-large": ("--timeout-seconds", "60.1"),
            "timeout-nan": ("--timeout-seconds", "nan"),
            "timeout-inf": ("--timeout-seconds", "inf"),
            "timeout-type": ("--timeout-seconds", "untrusted-value"),
            "url": ("--source-url", "https://example.invalid/untrusted-value"),
            "latest": ("--latest", "untrusted-value"),
            "publisher": ("--publisher", "untrusted-value"),
            "license": ("--license-name", "untrusted-value"),
            "payload": ("--payload", "untrusted-value"),
            "model": ("--model-version", "untrusted-value"),
        }[case]

        if name in arguments:
            arguments[arguments.index(name) + 1] = value

        else:
            arguments.extend([name, value])

    monkeypatch.setattr(commands.LocalWorkspaceStore, "Open", Refuse)
    monkeypatch.setattr(remote, "AcquireHttpsCveSelection", Refuse)
    status, outcome = Run(arguments)
    assert status == 2 and outcome["failure"] == "configuration", (
        "Invalid pinned CVE source or finite admission escaped preflight."
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

    monkeypatch.setattr(remote, "AcquireHttpsCveSelection", Refuse)
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
    request = remote.CveHttpsRequest(
        remote.CveHttpsSource("a" * 40, "CVE-1900-9999", hashlib.sha256(Body()).hexdigest()),
    )
    acquired = remote.AcquireHttpsCveSelection(model.root, request, scope_reference="scope:owned")
    assert acquired.state is remote.CveHttpsState.SUCCEEDED, "Owned custody fixture failed."

    return model, acquired


@pytest.mark.parametrize("case", ["state", "http", "raw_ack", "snapshot_ack", "receipt_ack",
                                  "raw", "envelope", "snapshot_record", "receipt"])
def test_SuccessRequiresAllIndependentFacts(acquired_context, monkeypatch, case):
    """A success token, complete body or subset of handles cannot substitute for full custody."""

    model, acquired = acquired_context

    if case == "state":
        acquired = replace(acquired, state=remote.CveHttpsState.STORAGE_FAILED)

    elif case == "http":
        acquired = replace(acquired, http_status=503, body_complete=False,
                           receive_state="http-rejected")

    elif case.endswith("_ack"):
        acquired = replace(acquired, **{case: remote.CveHttpsAcknowledgement.UNKNOWN})

    else:
        acquired = replace(acquired, **{case: None})

    monkeypatch.setattr(remote, "AcquireHttpsCveSelection", lambda *a, **k: acquired)
    status, outcome = Run(Arguments(model.root))
    assert status == 4 and outcome["status"] == "failed" and "snapshot" not in outcome, (
        "Incomplete custody became usable source assertions."
    )
    assert outcome["http_status"] == acquired.http_status and outcome[
        "body_complete"
    ] == acquired.body_complete, "Failure discarded observed network facts."
    assert outcome["raw_ack"] == acquired.raw_ack.value and outcome[
        "selection_ack"
    ] == acquired.snapshot_ack.value and outcome["receipt_ack"] == acquired.receipt_ack.value, (
        "Independent acknowledgement uncertainty was overwritten."
    )


@pytest.mark.parametrize("failure", [KeyboardInterrupt, EvidenceError, OSError, ValueError])
def test_UnexpectedEnteredAcquisitionKeepsUnknownAcks(tmp_path, monkeypatch, failure):
    """Interrupted or exceptional acquisition cannot assert rollback or unobserved publication."""

    model, _ = Context(tmp_path)

    def Fail(*args, **kwargs):
        """Raise after entering acquisition without returning observed custody acknowledgements."""

        raise failure("untrusted-value")

    monkeypatch.setattr(remote, "AcquireHttpsCveSelection", Fail)
    status, outcome = Run(Arguments(model.root))
    assert status == (130 if failure is KeyboardInterrupt else 4), "Wrong terminal failure status."
    assert all(outcome[name] == "unknown" for name in (
        "raw_ack", "selection_ack", "receipt_ack",
    )), "Unobserved storage acknowledgements became negative or successful facts."
    assert outcome["http_status"] is None and "untrusted-value" not in json.dumps(outcome), (
        "Exceptional acquisition fabricated a status or exposed exception content."
    )


def test_SuccessfulHumanPresentationRetainsSourceMeaning(acquired_context, monkeypatch):
    """Human output preserves source state/time/metrics and honest applicability/authentication."""

    model, acquired = acquired_context
    monkeypatch.setattr(remote, "AcquireHttpsCveSelection", lambda *a, **k: acquired)
    status, text = Run(Arguments(model.root), human=True)
    assert status == 0 and len(text) < 20000, "Human source output was unsuccessful or unbounded."
    assert all(value in text for value in ("CVE-1900-9999", "PUBLISHED", "5.2", "2026-10-12",
        "cvssV2_0", "9.8", "owned-cna", "not assessed", "have not been evaluated")), (
        "Human presentation changed source assertions or dropped interpretation boundaries."
    )
    assert not any(ord(character) < 32 and character != "\n" for character in text), (
        "Human presentation emitted terminal control bytes."
    )


@pytest.mark.parametrize("case", ["selection", "receipt", "missing-receipt", "duplicate-receipt",
                                  "scope", "model", "network", "apply-help"])
def test_InspectRequiresExactRootsAndNoReplacementArguments(acquired_context, monkeypatch, case):
    """Offline inspection rejects absent custody or fetch/apply options without receiver access."""

    model, acquired = acquired_context
    arguments = ["inspect", str(model.root), "--selection", acquired.snapshot_record.evidence_id,
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
    assert status == expected and outcome["status"] == "failed" and "snapshot" not in outcome, (
        "Inspection accepted missing exact roots or replacement source/application arguments."
    )
    assert Files(model.root) == before, "Read-only inspection refusal changed retained storage."


def test_FailedHumanPresentationHasSafeFixedFacts(tmp_path, monkeypatch):
    """Human configuration failure exposes useful bounded facts without rejected control content."""

    monkeypatch.setattr(remote, "AcquireHttpsCveSelection", Refuse)
    status, text = Run(["fetch", str(tmp_path), "--source-url", "\x1b[31muntrusted"], human=True)
    assert status == 2 and "configuration" in text and "not-attempted" in text, (
        "Failed human output lost the fixed failure and custody-attempt facts."
    )
    assert "\x1b" not in text and "untrusted" not in text, "Human failure leaked rejected controls."
