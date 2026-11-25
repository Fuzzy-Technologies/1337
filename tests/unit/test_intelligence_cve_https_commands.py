# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pinned HTTPS CLI admission, independent custody acknowledgements and safe presentation."""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import replace
from io import BytesIO, StringIO, TextIOWrapper

import pytest

from fuzzy1337 import intelligence_cve_https_commands as commands
from fuzzy1337 import intelligence_cve_remote as remote
from fuzzy1337.evidence import EvidenceError
from tests.e2e.test_intelligence_cli import Files
from tests.integration.test_intelligence_acquisition_persistence import Context
from tests.integration.test_intelligence_cve_batch import (
    OwnedReceiver,
    Requests,
    Workspace,
)


def SavedMembers(temporaryPath, monkeypatch, requests):
    """Retain independent original custody from owned bytes without contacting a source."""

    owner = Workspace(temporaryPath)
    OwnedReceiver(monkeypatch, requests)
    outcomes = tuple(remote.AcquireHttpsCveSelection(
        owner.root, request, scope_reference=f"scope:owned-{index}",
    ) for index, request in enumerate(requests))
    assert all(outcome.state is remote.CveHttpsState.SUCCEEDED for outcome in outcomes), (
        "Saved selection fixture must retain complete independent original custody"
    )
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", Refuse)
    monkeypatch.setattr(remote, "AcquireHttpsCveSelection", Refuse)

    return owner.root, outcomes


def SavedArguments(root, outcomes):
    """Select explicit original manifest pairs in caller order without a synthetic set ID."""

    return ["inspect-set", str(root), *(value for outcome in outcomes for value in (
        "--member", outcome.snapshot_record.evidence_id, outcome.receipt.evidence_id,
    ))]


@pytest.mark.parametrize("count", [2, 4])
def test_SavedSetInspectionPreservesIndependentCustodyAndCallerOrder(
    tmp_path, monkeypatch, count,
):
    """An operator reopens an explicit ordered set after relocation without receive or writes."""

    root, outcomes = SavedMembers(tmp_path, monkeypatch, Requests(count))
    relocated = tmp_path / "relocated"
    shutil.move(root, relocated)
    before = Files(relocated)
    status, result = Run(SavedArguments(relocated, outcomes[::-1]))
    assert status == 0 and result["profile"] == "cve-https-saved-set-cli", (
        "The saved-set operator route must verify every original member"
    )
    assert [member["source"]["identifier"] for member in result["members"]] == [
        outcome.source.identifier for outcome in outcomes[::-1]
    ], "Saved set inspection must preserve caller order rather than sorting CVEs"
    assert [member["provenance"] for member in result["members"]] == [
        outcome.raw.provenance.ToDict() for outcome in outcomes[::-1]
    ], "Each member must retain its independent original owner, scope and acquisition clocks"
    assert all(member["selection_reference"] == outcome.envelope.Reference()
               and member["receipt_id"] == outcome.receipt.evidence_id
               and member["snapshot"]["reference"] == outcome.envelope.snapshot.Reference()
               for member, outcome in zip(result["members"], outcomes[::-1], strict=True)), (
        "A set projection must preserve both original custody roots and distinct reference families"
    )
    assert result["publisher_authentication"] == "not-assessed" and result[
        "target_applicability"
    ] == result["risk_assessment"] == "not-evaluated" and result[
        "model_commit"
    ] == "not-attempted", "Saved custody must confer no new assessment or model authority"
    assert "set_id" not in result and "batch_id" not in result, (
        "A caller's explicit list must not become a fabricated persisted batch identity"
    )
    assert Files(relocated) == before, "Offline saved-set inspection must change no owning file"


@pytest.mark.parametrize("case", ["zero", "one", "five", "duplicate-selection", "duplicate-receipt",
                                  "prefix", "digest", "duplicate-workspace", "abbreviation"])
def test_SavedSetPreflightBeforeStorage(tmp_path, monkeypatch, case):
    """All finite pair admission completes before even opening the owning workspace."""

    pairs = [("sha256:" + str(index) * 64, "sha256:" + str(index + 4) * 64)
             for index in (1, 2)]

    if case in {"zero", "one", "five"}:
        pairs = {"zero": [], "one": pairs[:1], "five": pairs + pairs + pairs[:1]}[case]

    elif case == "duplicate-selection":
        pairs[1] = (pairs[0][0], pairs[1][1])

    elif case == "duplicate-receipt":
        pairs[1] = (pairs[1][0], pairs[0][1])

    elif case in {"prefix", "digest"}:
        pairs[1] = ("untrusted-value" if case == "prefix" else "sha256:" + "A" * 64,
                    pairs[1][1])

    arguments = ["inspect-set", str(tmp_path / "absent"),
                 *(value for pair in pairs for value in ("--member", *pair))]

    if case == "duplicate-workspace":
        arguments += ["--workspace", "untrusted-value"]

    elif case == "abbreviation":
        arguments[2] = "--mem"

    monkeypatch.setattr(remote, "LoadHttpsCveSelection", Refuse)
    monkeypatch.setattr(commands.LocalWorkspaceStore, "Open", Refuse)
    status, result = Run(arguments)
    assert status == 2 and result["failure"] == "configuration" and result["members"] == [], (
        "Invalid explicit pair selection must fail before original custody reads"
    )
    assert "untrusted-value" not in json.dumps(result), "Rejected pins must not enter diagnostics"


@pytest.mark.parametrize("case", ["swapped-receipt", "raw-root", "corrupt-original",
                                  "mixed-commit", "duplicate-cve"])
def test_SavedSetRequiresEveryOriginalMemberWithoutPartialAssertions(
    tmp_path, monkeypatch, case,
):
    """Foreign families, broken joins and incompatible source members cannot supply a set result."""

    requests = Requests(2)

    if case == "mixed-commit":
        requests = (requests[0], replace(requests[1], source=replace(
            requests[1].source, commit="b" * 40,
        )))

    elif case == "duplicate-cve":
        requests = (requests[0], replace(requests[0], timeout_seconds=1))

    root, outcomes = SavedMembers(tmp_path, monkeypatch, requests)
    arguments = SavedArguments(root, outcomes)

    if case == "swapped-receipt":
        arguments[-1] = outcomes[0].receipt.evidence_id
        arguments[4] = outcomes[1].receipt.evidence_id

    elif case == "raw-root":
        arguments[-2] = outcomes[1].raw.evidence_id

    elif case == "corrupt-original":
        (root / "evidence" / outcomes[1].raw.reference.locator).write_bytes(b"corrupt")

    before = Files(root)
    status, result = Run(arguments)
    assert status == 4 and result["failure"] == "integrity" and result["members"] == [], (
        "An invalid original member must refuse the whole projection without partial assertions"
    )
    assert Files(root) == before, "Saved custody refusal must leave all original bytes unchanged"


def test_SavedSetRefusesLegacyLocalFamilyWithoutReinterpretingRoots(tmp_path, monkeypatch):
    """An independently valid local receipt/snapshot pair cannot enter the remote CVE family."""

    from fuzzy1337.intelligence_acquisition import AcquireIntelligenceSnapshot, SnapshotRequest
    from tests.integration.test_intelligence_acquisition_persistence import RAW, Source

    root, outcomes = SavedMembers(tmp_path, monkeypatch, Requests(2))
    local = AcquireIntelligenceSnapshot(
        root, SnapshotRequest(Source(), RAW), scope_reference="scope:local",
    )
    assert local.snapshot_record is not None and local.receipt is not None, (
        "Legacy local fixture must retain its own independently valid roots"
    )
    arguments = SavedArguments(root, outcomes)
    arguments[-2:] = [local.snapshot_record.evidence_id, local.receipt.evidence_id]
    before = Files(root)
    status, result = Run(arguments)
    assert status == 4 and result["failure"] == "integrity" and result["members"] == [], (
        "Saved CVE set inspection must refuse valid custody from another source family"
    )
    assert Files(root) == before, "Source-family refusal must not rewrite original custody"


def test_SavedSetHelpReadsNothing(monkeypatch):
    """Focused saved-set help documents the input ceiling without reading a workspace."""

    monkeypatch.setattr(commands.LocalWorkspaceStore, "Open", Refuse)
    status, text = Run(["inspect-set", "--help"], human=True)
    assert status == 0 and "two to four" in text, "Saved-set help must expose its finite selection"


@pytest.mark.parametrize("human", [False, True], ids=["json", "human"])
def test_SavedSetPresentationLimitRefusesWithoutPartialAssertions(tmp_path, monkeypatch, human):
    """A terminal projection is complete, portable and bounded before its single output write."""

    root, outcomes = SavedMembers(tmp_path, monkeypatch, Requests(2))
    monkeypatch.setattr(commands, "MAX_SAVED_SET_TERMINAL_BYTES", 1024)
    before = Files(root)
    status, result = Run(SavedArguments(root, outcomes), human=human)
    assert status == 4 and "presentation-limit" in str(result), (
        "An excessive saved-set terminal document must produce a fixed bounded refusal"
    )
    assert "CVE-1900" not in str(result), (
        "Presentation failure must not print partial CVE assertions"
    )
    assert Files(root) == before, "Terminal refusal must not mutate saved original custody"


@pytest.mark.parametrize("failure,expected", [(KeyboardInterrupt, 130), (OSError, 4)])
def test_SavedSetReadInterruptionKeepsNoSuccessfulSubset(tmp_path, monkeypatch, failure, expected):
    """A later original-read failure cannot publish an earlier verified subset as success."""

    root, outcomes = SavedMembers(tmp_path, monkeypatch, Requests(2))
    original = remote.LoadHttpsCveSelection
    calls = []

    def Load(root, selection, receipt):
        """Interrupt only the second owning loader after the first verifies normally."""

        calls.append(selection)

        if len(calls) == 2:
            raise failure("untrusted-value")

        return original(root, selection, receipt)

    monkeypatch.setattr(remote, "LoadHttpsCveSelection", Load)
    status, result = Run(SavedArguments(root, outcomes))
    assert status == expected and result["status"] == "failed" and result["members"] == [], (
        "Interrupted saved-set verification must not publish an earlier successful subset"
    )
    assert "untrusted-value" not in json.dumps(result), (
        "Saved-set read failures must not echo input"
    )


def test_SavedSetPortablePresentationAndShortWriteAreExplicit(tmp_path, monkeypatch):
    """Source Unicode remains reversible in JSON and one incomplete stream write is an error."""

    value = {"command": "intel.cve.https.inspect-set", "status": "succeeded",
             "description": "Owned \u00e9\u6d4b\u8bd5\nsource"}
    encoded = commands.CveSavedSetTerminal(value, jsonOutput=True)
    assert encoded.isascii() and json.loads(encoded) == value, (
        "Portable saved-set JSON must retain exact source text through ASCII escaping"
    )
    human = commands.CveSavedSetTerminal(value, jsonOutput=False)
    assert human.isascii() and "\\xe9" in human and "\\nsource" in human, (
        "Human saved-set presentation must escape Unicode and source controls"
    )

    with monkeypatch.context() as boundary:
        boundary.setattr(commands, "MAX_SAVED_SET_TERMINAL_BYTES", len(encoded))
        assert commands.CveSavedSetTerminal(value, jsonOutput=True) == encoded, (
            "A complete terminal document exactly at the byte ceiling must remain admissible"
        )
        boundary.setattr(commands, "MAX_SAVED_SET_TERMINAL_BYTES", len(encoded) - 1)

        with pytest.raises(ValueError, match="byte ceiling"):
            commands.CveSavedSetTerminal(value, jsonOutput=True)

    root, outcomes = SavedMembers(tmp_path, monkeypatch, Requests(2))

    stream = StringIO()
    originalWrite = stream.write
    monkeypatch.setattr(stream, "write", lambda text: originalWrite(text[:3]))

    with pytest.raises(OSError, match="Incomplete"):
        commands.RunCveHttpsCommands(SavedArguments(root, outcomes), stream, json_output=True)

    assert len(stream.getvalue()) == 3, (
        "A short terminal write must not retry or append another result"
    )


def test_SavedSetLateCancellationClearsAlreadyVerifiedAssertions(tmp_path, monkeypatch):
    """Cancellation during presentation cannot expose the already verified member projection."""

    root, outcomes = SavedMembers(tmp_path, monkeypatch, Requests(2))
    original = commands.CveSavedSetTerminal
    calls = []

    def Render(outcome, *, jsonOutput):
        """Cancel the first render, then permit only the fixed interruption fallback."""

        calls.append(outcome["status"])

        if len(calls) == 1:
            raise KeyboardInterrupt

        return original(outcome, jsonOutput=jsonOutput)

    monkeypatch.setattr(commands, "CveSavedSetTerminal", Render)
    status, result = Run(SavedArguments(root, outcomes))
    assert status == 130 and result["failure"] == "interrupted" and result["members"] == [], (
        "Late cancellation must clear the successful member projection before terminal publication"
    )
    assert calls == ["succeeded", "failed"], "Cancellation must render only one fixed fallback"


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


@pytest.mark.parametrize("encoding", ["utf-8", "ascii", "latin-1", "cp1252"])
def test_SavedInspectJsonPreservesFactsThroughStrictOutputStreams(
    acquired_context, monkeypatch, encoding,
):
    """Narrow JSON streams preserve original notices without changing UTF-8 output or custody."""

    model, acquired = acquired_context
    arguments = ["inspect", str(model.root), "--selection", acquired.snapshot_record.evidence_id,
                 "--receipt", acquired.receipt.evidence_id]
    monkeypatch.setattr(remote, "AcquireHttpsCveSelection", Refuse)
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", Refuse)
    before = Files(model.root)
    expectedStatus, expected = Run(arguments)
    target = BytesIO()
    output = TextIOWrapper(target, encoding=encoding, errors="strict", newline="\n")
    status = commands.RunCveHttpsCommands(arguments, output, json_output=True)
    output.flush()
    payload = target.getvalue()
    assert status == expectedStatus == 0 and json.loads(payload.decode(encoding)) == expected, (
        "Output encoding must preserve the verified inspection and original Unicode notices"
    )

    if encoding == "utf-8":
        from fuzzy1337.model import CanonicalModelJson

        assert payload == CanonicalModelJson(expected) + b"\n", (
            "UTF-8 inspection must retain its original canonical JSON bytes and final newline"
        )

    elif encoding in ("ascii", "latin-1"):
        assert payload.isascii() and b"\\u00a9" in payload, (
            "Narrow output must use valid JSON Unicode escapes rather than losing notice text"
        )

    assert Files(model.root) == before, "Terminal encoding must not change saved source custody"


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
