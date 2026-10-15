# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Path handler failure, typed original-record and bounded safe presentation contracts."""

from __future__ import annotations

from io import StringIO

import pytest

from fuzzy1337 import path_commands as commands
from fuzzy1337.model import LocalModelStore, ObjectIdentity, ObjectKind, SecurityObject
from tests.path_command_helpers import Files, Run, SmallArguments, SmallGraph, Value


def test_NoAssessmentsRequiresExplicitAcknowledgement(tmp_path):
    """An absent assessment selection cannot silently become an unassessed graph default."""

    context = SmallGraph(tmp_path)
    arguments = SmallArguments(context)
    arguments.remove("--no-assessments")
    status, result = Run(arguments)
    assert status == 2 and result["analysis"] is None, (
        "Missing explicit proof selection was inferred"
    )


@pytest.mark.parametrize("field", ["--transition", "--source", "--assessment"])
def test_ForeignOrDuplicateSelectionsFailBeforeProofReads(tmp_path, monkeypatch, field):
    """Invalid selection identity or duplicates cannot trigger source proof I/O."""

    context = SmallGraph(tmp_path)
    arguments = SmallArguments(context)

    if field == "--assessment":
        arguments.remove("--no-assessments")
        arguments.extend(("--assessment", "sha256:" + "a" * 64,
                          "--assessment", "sha256:" + "a" * 64))

    elif field == "--transition":
        arguments.extend((field, arguments[arguments.index(field) + 1]))

    else:
        arguments = Value(arguments, field, "object:" + "a" * 64)

    def NoProof(*args, **kwargs):
        """Expose proof access before malformed selections are refused."""

        raise AssertionError("Invalid path selection reached proof I/O")

    monkeypatch.setattr(commands, "PreflightAssessments", NoProof)
    status, result = Run(arguments)
    assert status == 2 and result["analysis"] is None, "Invalid path selection was accepted"


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt], ids=("storage", "interrupted"))
def test_OwnerReadFailureNeverProducesAnalysisOrWrites(tmp_path, monkeypatch, error):
    """Read failures have fixed safe outcomes without acquisition or mutation acknowledgements."""

    context = SmallGraph(tmp_path)
    arguments = SmallArguments(context)
    before = Files(context[0])

    def Open(*args, **kwargs):
        """Fail the actual owning snapshot read without retaining the untrusted exception text."""

        raise error("secret-marker")

    monkeypatch.setattr(LocalModelStore, "Open", Open)
    status, result = Run(arguments)
    assert status == (130 if error is KeyboardInterrupt else 4) and result["analysis"] is None, (
        "Interrupted/failed owner read supplied a usable path analysis"
    )
    assert "secret-marker" not in str(result) and Files(context[0]) == before, (
        "Owner read failure leaked diagnostics or wrote saved state"
    )


def test_ChangedModelAfterAnalysisIsRefusedBeforeSuccessPresentation(tmp_path, monkeypatch):
    """A last owning reread detects a competing saved basis without overwriting that owner."""

    context = SmallGraph(tmp_path)
    original = commands.AnalyzeReachabilityPaths

    def Analyze(*args, **kwargs):
        """Complete actual analysis then simulate a different current owning model read."""

        result = original(*args, **kwargs)
        monkeypatch.setattr(LocalModelStore, "Open", lambda *args: object())

        return result

    monkeypatch.setattr(commands, "AnalyzeReachabilityPaths", Analyze)
    before = Files(context[0])
    status, result = Run(SmallArguments(context))
    assert status == 4 and result["failure"] == "basis-changed" and Files(context[0]) == before, (
        "Last-read changed model was accepted or silently replaced by the path consumer"
    )


def test_ForeignAnalysisWrapperIsRejectedBeforeAttributes(tmp_path, monkeypatch):
    """A substituted result never invokes foreign serialization or attribute methods."""

    context = SmallGraph(tmp_path)
    monkeypatch.setattr(commands, "AnalyzeReachabilityPaths", lambda *args, **kwargs: object())
    status, result = Run(SmallArguments(context))
    assert status == 4 and result["failure"] == "integrity", "Foreign path wrapper was presented"


def test_OutputBudgetFailsWithoutReturningPartialOrUnboundedDto(tmp_path, monkeypatch):
    """A rendering limit preserves owner bytes and returns no incomplete explanation."""

    context = SmallGraph(tmp_path)
    before = Files(context[0])
    monkeypatch.setattr(commands, "MAX_PATH_OUTPUT_BYTES", 4096)
    status, result = Run(SmallArguments(context))
    assert status == 4 and result["failure"] == "output-limit" and result["analysis"] is None, (
        "Path rendering silently truncated facts or returned oversized partial output"
    )
    assert len(str(result)) < 4096 and Files(context[0]) == before, (
        "Output-limit failure changed saved model/evidence or emitted an unbounded diagnostic"
    )


def test_ExpectedDigestGrammarRefusesBeforeWorkspaceAccess(tmp_path, monkeypatch):
    """An invalid content digest is a configuration error without reading any local source."""

    context = SmallGraph(tmp_path)
    arguments = Value(SmallArguments(context), "--expected-snapshot-sha256", "secret-marker")

    def Path(*args, **kwargs):
        """Expose filesystem selection before complete model-pin grammar validation."""

        raise AssertionError("Malformed expected path digest reached filesystem access")

    monkeypatch.setattr(commands, "RuntimePath", Path)
    status, result = Run(arguments)
    assert status == 2 and "secret-marker" not in str(result), (
        "Expected digest was inferred or echoed"
    )


def test_HelpAndHumanResultsUseSafeOperatorPresentation(tmp_path, monkeypatch):
    """Help reads no workspace, and human output distinguishes enumeration from cut completeness."""

    context = SmallGraph(tmp_path)
    output = StringIO()
    status = commands.RunPathCommands(SmallArguments(context), output)
    assert status == 0 and "Returned candidate paths: 2" in output.getvalue() and (
        "verified cuts: 2" in output.getvalue()
    ), "Human path output omitted its actual independent count/cut result"

    def Path(*args, **kwargs):
        """Expose forbidden workspace access during static help."""

        raise AssertionError("Path help accessed storage")

    monkeypatch.setattr(commands, "RuntimePath", Path)
    output = StringIO()
    status = commands.RunPathCommands(["--help"], output)
    assert status == 0 and "--no-assessments" in output.getvalue(), "Static path help failed"


def test_ExistingWholeModelNodeCeilingRefusesBeforeProofReads(tmp_path, monkeypatch):
    """Small selections cannot silently partition a saved model beyond its SDK profile ceiling."""

    context = SmallGraph(tmp_path)
    root, model, objects, relations = context
    added = tuple(SecurityObject(ObjectIdentity(model.workspace_id, ObjectKind.ASSET,
        "extra-owned:" + str(index)), provenance=objects["source"].provenance)
        for index in range(507))
    changed, _ = model.Apply(objects=added)
    saved = LocalModelStore(root).Save(changed, expected_revision=model.revision)
    selected = (root, saved, objects, relations)

    def NoProof(*args, **kwargs):
        """Expose support I/O before the existing full eligible-model ceiling is enforced."""

        raise AssertionError("Oversized saved eligible model reached proof I/O")

    monkeypatch.setattr(commands, "PreflightAssessments", NoProof)
    before = Files(root)
    status, result = Run(SmallArguments(selected))
    assert status == 2 and result["analysis"] is None and Files(root) == before, (
        "Path product bypassed the existing 512-node whole-model projection ceiling"
    )
