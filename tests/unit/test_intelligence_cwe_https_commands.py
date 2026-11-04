# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Selected CWE HTTPS CLI admission, custody failures and bounded terminal outcomes."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from io import StringIO

import pytest

from fuzzy1337 import intelligence_cwe_https_commands as commands
from fuzzy1337 import intelligence_cwe_remote as remote
from fuzzy1337.evidence import EvidenceError, LocalEvidenceStore
from tests.integration.test_intelligence_acquisition_persistence import Context
from tests.unit.test_intelligence_cwe_selection import Archive, Catalog, Entry


def Body(version="5.0", *, name="Owned weakness"):
    """Build an owned ZIP with matched, unsupported and absent identifiers."""

    inner = (b"<Weaknesses>" + Entry(name=name) + b"</Weaknesses><Views>"
             + Entry("1000", kind="View") + b"</Views>")

    return Archive(Catalog(inner, version), version)


def FetchArguments(root, raw, version="5.0"):
    """Select a fixed source and deliberately unsorted distinct identifiers."""

    return ["fetch", str(root), "--catalog-version", version,
            "--expected-sha256", hashlib.sha256(raw).hexdigest(),
            "--identifier", "CWE-999", "--identifier", "CWE-79",
            "--identifier", "CWE-1000", "--scope", "scope:owned"]


def InspectArguments(root, acquired):
    """Select exact immutable roots using the terminal custody handles."""

    return ["inspect", str(root), "--selection", acquired["selection_id"],
            "--receipt", acquired["receipt_id"]]


def Run(arguments):
    """Obtain one JSON command outcome through the leaf adapter."""

    output = StringIO()
    status = commands.RunCweHttpsCommands(arguments, output, json_output=True)

    return status, json.loads(output.getvalue())


def Refuse(*args, **kwargs):
    """Fail on any unexpected filesystem, acquisition or output work."""

    raise AssertionError("Rejected input crossed a resource boundary")


def RequireNoSelection(outcome):
    """Require a failure to withhold all usable selected assertions."""

    assert not {"source", "selection", "selection_reference"} & outcome.keys(), (
        "A failed outcome included usable assertions"
    )


@pytest.mark.parametrize("arguments", [["--help"], ["-h"], ["fetch", "--help"], ["inspect", "-h"]])
def test_ExactHelpUsesNoPhysicalWorkspaceOrAcquisition(arguments, monkeypatch):
    """Only exact supported help is printed without opening storage."""

    monkeypatch.setattr(commands, "IntelPath", Refuse)
    monkeypatch.setattr(remote, "AcquireHttpsCweSelection", Refuse)
    output = StringIO()
    status = commands.RunCweHttpsCommands(arguments, output, json_output=True)
    assert status == 0 and "usage: 1337 intel cwe https" in output.getvalue(), (
        "Exact help failed without resource access"
    )


@pytest.mark.parametrize("arguments", [
    [], ["apply", "--help"], ["latest", "-h"], ["fetch", "--help", "--extra"],
    ["inspect", "workspace", "--selection", "invalid", "--receipt", "sha256:" + "a" * 64],
    ["inspect", "workspace", "--selection", "sha256:" + "a" * 64, "--receipt", "invalid"],
])
def test_UnsupportedHelpAndMalformedRootsFailBeforePhysicalReads(arguments, monkeypatch):
    """Unsupported help and invalid immutable IDs never become default actions."""

    monkeypatch.setattr(commands, "IntelPath", Refuse)
    status, outcome = Run(arguments)
    assert status == 2 and outcome["failure"] == "configuration", (
        "Unsupported grammar or a malformed root reached an action"
    )
    assert outcome["ack_basis"] == "not-attempted", "Invalid grammar acquired evidence"
    RequireNoSelection(outcome)


@pytest.mark.parametrize("option,value", [
    ("--catalog-version", "latest"), ("--expected-sha256", "A" * 64),
    ("--scope", ""), ("--identifier", "CVE-2024-3094"), ("--max-bytes", "0"),
    ("--max-bytes", "4194305"), ("--max-bytes", "secret-value"),
    ("--timeout-seconds", "inf"), ("--timeout-seconds", "nan"),
    ("--timeout-seconds", "1e999"), ("--timeout-seconds", "0.049"),
    ("--timeout-seconds", "60.001"), ("--timeout-seconds", "secret-value"),
])
def test_InvalidRequestIsRejectedBeforePhysicalPathRead(tmp_path, monkeypatch, option, value):
    """Validate the finite source, identifier, scope and limit contracts before storage."""

    arguments = FetchArguments(tmp_path, Body())

    if option in arguments:
        arguments[arguments.index(option) + 1] = value

    else:
        arguments.extend([option, value])

    monkeypatch.setattr(commands, "IntelPath", Refuse)
    status, outcome = Run(arguments)
    assert status == 2 and outcome["failure"] == "configuration", "Invalid request was accepted"
    assert "secret-value" not in json.dumps(outcome), "Rejected caller data leaked"


@pytest.mark.parametrize("extras", [
    ["--scope=scope:duplicate"], ["--scope", "scope:duplicate"],
    ["--max-bytes=1024", "--max-bytes", "1024"],
    ["--identifier", "CWE-79"], ["--timeout", "10"], ["--source-url", "http://example.invalid"],
    ["--identifier", "CWE-79"] * 62,
])
def test_ClosedGrammarRejectsDuplicatesOverflowAndOverrides(tmp_path, monkeypatch, extras):
    """Forwarded duplicates, ambiguous flags and excess identifiers fail closed."""

    monkeypatch.setattr(commands, "IntelPath", Refuse)
    status, outcome = Run([*FetchArguments(tmp_path, Body()), *extras])
    assert status == 2 and outcome["raw_ack"] == "not-attempted", (
        "A duplicate, override or oversized selection entered acquisition"
    )


def test_AbsentWorkspaceIsAnIntegrityFailureWithoutPublication(tmp_path, monkeypatch):
    """A valid source request does not implicitly create its owning workspace."""

    root = tmp_path / "absent"
    monkeypatch.setattr(remote, "AcquireHttpsCweSelection", Refuse)
    status, outcome = Run(FetchArguments(root, Body()))
    assert status == 4 and outcome["failure"] == "integrity", "Missing workspace was accepted"
    assert not root.exists() and outcome["ack_basis"] == "not-attempted", (
        "Missing workspace was created or attributed to an acquisition"
    )


@pytest.mark.parametrize("receive,status_code,raw", [
    ("redirect-rejected", 302, b""), ("http-rejected", 404, b""),
    ("format-rejected", 200, b""), ("size-exceeded", 200, b"partial"),
    ("transport-failed", None, b""), ("timed-out", 200, b"partial"),
    ("succeeded", 200, b"malformed complete ZIP"),
])
def test_ActualSdkFailureKeepsObservedBytesStatusAndIndependentAcks(
    tmp_path, monkeypatch, receive, status_code, raw,
):
    """Exercise actual owning writes for each refused or malformed acquisition."""

    model, _ = Context(tmp_path)
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", lambda *args, **kwargs: (
        raw, receive, status_code,
    ))
    status, outcome = Run(FetchArguments(model.root, raw))
    assert status == 4 and outcome["failure"] == "acquisition", "A failed acquisition succeeded"
    assert (outcome["receive_state"], outcome["http_status"], outcome["received_bytes"]) == (
        receive, status_code, len(raw),
    ), "Terminal facts lost the actual receiver outcome"
    assert outcome["body_complete"] is (receive == "succeeded"), "Completeness was misclassified"
    assert outcome["acquisition_state"] == (
        "parse-failed" if receive == "succeeded" else receive
    ), "Receiver refusal was conflated with source parsing"
    assert (outcome["raw_ack"], outcome["selection_ack"], outcome["receipt_ack"]) == (
        "confirmed", "not-attempted", "confirmed",
    ), "Failure inferred publication or rollback"
    store = LocalEvidenceStore(model.root / "evidence")
    assert store.Read(store.Get(outcome["raw_id"]).reference) == raw, "Original bytes changed"
    assert outcome["source_sha256"] == hashlib.sha256(raw).hexdigest(), "Actual digest was lost"
    RequireNoSelection(outcome)


def test_WrongPinUsesActualRetainedDigest(tmp_path, monkeypatch):
    """Digest mismatch preserves the actual original without admitting selected content."""

    model, _ = Context(tmp_path)
    raw = Body()
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps",
                        lambda *args, **kwargs: (raw, "succeeded", 200))
    status, outcome = Run(FetchArguments(model.root, b"other expected original"))
    assert status == 4 and outcome["acquisition_state"] == "digest-mismatch", "Wrong pin passed"
    assert outcome["source_sha256"] == hashlib.sha256(raw).hexdigest(), "Declared pin replaced SHA"
    RequireNoSelection(outcome)


@pytest.mark.parametrize("role,acks", [
    (remote.RAW_ROLE, ("unknown", "not-attempted", "not-attempted")),
    (remote.ENVELOPE_ROLE, ("confirmed", "unknown", "not-attempted")),
    (remote.RECEIPT_ROLE, ("confirmed", "confirmed", "unknown")),
])
@pytest.mark.parametrize("committed", [False, True])
def test_OwningStorePublicationFaultPreservesOnlyReturnedHandles(
    tmp_path, monkeypatch, role, acks, committed,
):
    """Independent failures before or after a write retain honest acknowledgement uncertainty."""

    model, _ = Context(tmp_path)
    raw = Body()
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps",
                        lambda *args, **kwargs: (raw, "succeeded", 200))
    original = LocalEvidenceStore.Put
    failed_writes = []

    def Put(store, payload, record_role, media_type, provenance):
        """Refuse acknowledgement at one owning-store stage."""

        if record_role == role:
            if committed:
                failed_writes.append(original(store, payload, record_role, media_type, provenance))

            raise EvidenceError("Owned publication failure")

        return original(store, payload, record_role, media_type, provenance)

    monkeypatch.setattr(LocalEvidenceStore, "Put", Put)
    status, outcome = Run(FetchArguments(model.root, raw))
    assert status == 4 and outcome["acquisition_state"] == "storage-failed", "Store fault passed"
    assert tuple(outcome[key] for key in ("raw_ack", "selection_ack", "receipt_ack")) == acks, (
        "The CLI inferred an acknowledgement after a failed SDK publication"
    )
    assert tuple(outcome[key] is not None for key in ("raw_id", "selection_id", "receipt_id")) == (
        tuple(ack == "confirmed" for ack in acks)
    ), "CLI exposed an unreturned handle or lost a returned one"
    assert bool(failed_writes) is committed, "The fault seam did not exercise its intended timing"
    RequireNoSelection(outcome)


@pytest.mark.parametrize("error,exit_code", [(RuntimeError, 4), (KeyboardInterrupt, 130)])
def test_UnreturnedAcquisitionDoesNotInferRollback(tmp_path, monkeypatch, error, exit_code):
    """A call interrupted before returning conservatively exposes unknown acknowledgements."""

    model, _ = Context(tmp_path)

    def Fail(*args, **kwargs):
        """Interrupt or fail the acquisition after entering the SDK call."""

        raise error("Owned unreturned outcome")

    monkeypatch.setattr(remote, "AcquireHttpsCweSelection", Fail)
    status, outcome = Run(FetchArguments(model.root, Body()))
    assert status == exit_code and outcome["ack_basis"] == "unreturned", "Outcome was misreported"
    assert all(outcome[key] == "unknown" for key in ("raw_ack", "selection_ack", "receipt_ack")), (
        "The missing SDK outcome implied rollback or publication success"
    )
    RequireNoSelection(outcome)


def test_ReturnedSuccessWithoutConfirmedReceiptDoesNotExposeSelection(tmp_path, monkeypatch):
    """A successful state label cannot replace complete immutable handles and ACKs."""

    model, _ = Context(tmp_path)
    raw = Body()
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps",
                        lambda *args, **kwargs: (raw, "succeeded", 200))
    original = remote.AcquireHttpsCweSelection

    def Acquire(*args, **kwargs):
        """Keep complete source facts but withhold the receipt acknowledgement."""

        return replace(original(*args, **kwargs), receipt=None,
                       receipt_ack=remote.CweHttpsAcknowledgement.UNKNOWN)

    monkeypatch.setattr(remote, "AcquireHttpsCweSelection", Acquire)
    status, outcome = Run(FetchArguments(model.root, raw))
    assert status == 4 and outcome["acquisition_state"] == "succeeded", "State bypassed custody"
    assert outcome["raw_ack"] == "confirmed" and outcome["receipt_ack"] == "unknown", (
        "Partial acknowledgements were collapsed into one status"
    )
    RequireNoSelection(outcome)


def test_InterruptedSuccessAssemblyKeepsKnownCustody(tmp_path, monkeypatch):
    """Withhold source facts even when interruption follows a returned complete acquisition."""

    model, _ = Context(tmp_path)
    raw = Body()
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps",
                        lambda *args, **kwargs: (raw, "succeeded", 200))
    original = remote.AcquireHttpsCweSelection

    def Interrupt(*args, **kwargs):
        """Interrupt detached success assembly after all custody writes return."""

        raise KeyboardInterrupt

    def Acquire(*args, **kwargs):
        """Complete the actual SDK operation before interrupting display assembly."""

        result = original(*args, **kwargs)
        monkeypatch.setattr(remote.CweHttpsSelection, "Reference", Interrupt)

        return result

    monkeypatch.setattr(remote, "AcquireHttpsCweSelection", Acquire)
    status, outcome = Run(FetchArguments(model.root, raw))
    assert status == 130 and outcome["failure"] == "interrupted", "Interruption was lost"
    assert outcome["ack_basis"] == "sdk-returned" and outcome["receipt_ack"] == "confirmed", (
        "An interruption after acquisition erased completed custody"
    )
    RequireNoSelection(outcome)


@pytest.mark.parametrize("interrupted", [False, True])
def test_PresentationRefusalPublishesOneFailureWithoutUsableSelection(
    tmp_path, monkeypatch, interrupted,
):
    """Real committed custody survives an output cap or rendering interruption."""

    model, _ = Context(tmp_path)
    raw = Body(name="Owned é ▼ 😀 source")
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps",
                        lambda *args, **kwargs: (raw, "succeeded", 200))

    if interrupted:
        original = commands.CweHttpsTerminal

        def Terminal(outcome, envelope, **kwargs):
            """Interrupt success assembly while permitting its finite fallback."""

            if envelope is not None:
                raise KeyboardInterrupt

            return original(outcome, envelope, **kwargs)

        monkeypatch.setattr(commands, "CweHttpsTerminal", Terminal)

    else:
        monkeypatch.setattr(commands, "MAX_TERMINAL_BYTES", 512)

    status, outcome = Run(FetchArguments(model.root, raw))
    assert (status, outcome["failure"]) == (
        (130, "interrupted") if interrupted else (4, "presentation-limit")
    ), "Presentation failure exposed or misclassified success"
    assert all(outcome[key] == "confirmed" for key in (
        "raw_ack", "selection_ack", "receipt_ack",
    )), "The fallback lost completed independent acknowledgements"
    RequireNoSelection(outcome)


def test_AsciiEscapedFramingIsCountedInTerminalBudget():
    """Measure complete escaped JSON bytes including its one trailing newline."""

    facts = {"name": "é 😀"}
    rendered = commands.CweHttpsTerminal(facts, None, json_output=True, maximum=1024)
    assert rendered.isascii() and json.loads(rendered) == facts, "Escapes changed source Unicode"
    assert commands.CweHttpsTerminal(
        facts, None, json_output=True, maximum=len(rendered.encode("ascii")),
    ) == rendered, "Exact byte ceiling did not admit the framed document"

    with pytest.raises(ValueError):
        commands.CweHttpsTerminal(
            facts, None, json_output=True, maximum=len(rendered.encode("ascii")) - 1,
        )


@pytest.mark.parametrize("arguments", [["fetch", "--help"], ["apply"]])
@pytest.mark.parametrize("short_write", [False, True])
def test_CallerWriteFailurePropagates(arguments, short_write):
    """A caller stream failure must not become successful output or a second attempted write."""

    writes = []

    class FailingStream(StringIO):
        """Simulate an output transport that rejects its first publication."""

        def write(self, text):
            """Refuse the terminal document."""

            writes.append(text)

            if short_write:
                return super().write(text[:5])

            raise OSError("Owned output stream failure")

    message = "Incomplete CWE HTTPS" if short_write else "Owned output stream failure"

    with pytest.raises(OSError, match=message):
        commands.RunCweHttpsCommands(arguments, FailingStream(), json_output=True)

    assert len(writes) == 1, "Caller write failure triggered another publication attempt"
