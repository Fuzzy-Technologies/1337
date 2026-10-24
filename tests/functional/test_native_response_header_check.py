# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent source oracles and future genuine offline native-header acceptance.

The pure tests read only the frozen wire catalog. Integration fixtures below own
actual accepted acquisition before closing its listener; collection executes none
of those fixtures. Their execution requires a separately authorized genuine phase.
Only optional unsupported genuine lanes skip; required acceptance fails without
real Linux acquisition custody. Portable pure/mock/source tests remain runnable.
"""

from __future__ import annotations

import ast
import asyncio
import hashlib
import importlib
import json
import multiprocessing
import os
import shutil
import socket
import subprocess
import sys
import threading
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from fuzzy1337 import owned_response_capture as capture_parent
from fuzzy1337 import owned_response_workflow as acquisition
from fuzzy1337.adapters import ImpactLevel
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.executors import LocalExecutor
from fuzzy1337.findings import Finding, FindingSeverity, FindingStatus
from fuzzy1337.model import LocalModelStore, ModelProvenance, ObjectKind
from fuzzy1337.owned_response_custody import OwnedResponseEvidenceStore, OwnedResponseStage
from fuzzy1337.policy import CapabilityPermission, GovernedLocalExecutor, ImpactPolicy, PolicyEngine
from fuzzy1337.scope import LocalScopeStore, Target, TargetKind
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.contract import native_response_header_evidence as artifacts
from tests.contract.native_response_header_evidence import (
    HeaderConsumer,
    HeaderListener,
)
from tests.contract.native_response_header_evidence import (
    header_case_evidence as header_case_evidence,
)
from tests.contract.native_response_header_evidence import (
    header_evidence_run as header_evidence_run,
)
from tests.contract.native_response_header_evidence import (
    header_platform as header_platform,
)
from tests.contract.native_response_header_evidence import (
    installed_header_worker as installed_header_worker,
)
from tests.contract.native_response_header_oracle import (
    ASSESSMENT,
    CAPABILITY,
    CHECK,
    PROVIDER,
    AssertInterpretation,
    AssertNoNewInterpretation,
    FrozenOriginals,
    HeaderAbsent,
    NativeFindingObjects,
    OriginalState,
)
from tests.contract.owned_response_product_runner import Setup
from tests.integration.test_owned_response_product import Policy
from tests.integration.test_owned_response_worker_execution import ExpectedRequest

REPOSITORY = Path(__file__).resolve().parents[2]
WORKFLOW = "fuzzy1337.native_response_header_workflow"
OWNER = "actor:owned-response-product"


def test_FrozenActualHeaderFieldsHaveHandwrittenOneZeroOneTruth():
    """Exact original field names establish native truth independently of ZAP/provider metadata."""

    originals = FrozenOriginals()
    assert tuple(HeaderAbsent(originals[case]["header_section"])
        for case in ("missing", "fixed", "body-decoy")) == (True, False, True), (
        'Exact original field names establish native truth independently of ZAP/provider '
        'metadata.'
    )
    assert originals["missing"]["body"] == originals["fixed"]["body"], (
        'Exact original field names establish native truth independently of ZAP/provider '
        'metadata.'
    )
    assert b"X-Content-Type-Options: nosniff" in originals["body-decoy"]["body"], (
        'Exact original field names establish native truth independently of ZAP/provider '
        'metadata.'
    )
    assert b"X-Content-Type-Options" not in originals["body-decoy"]["header_section"], (
        'Exact original field names establish native truth independently of ZAP/provider '
        'metadata.'
    )


@pytest.mark.parametrize("field,absent", [(b"x-CoNtEnT-tYpE-oPtIoNs", False),
    (b"Other-X-Content-Type-Options", True), (b"X-Content-Type-Options-Extra", True)])
def test_OracleComparesCompleteCaseInsensitiveNamesWithoutValueAssumptions(field, absent):
    """A complete present field, even with an empty value, negates only the absence predicate."""

    assert HeaderAbsent(b"HTTP/1.1 200 OK\r\n" + field + b":\r\n\r\n") is absent, (
        'A complete present field, even with an empty value, negates only the absence '
        'predicate.'
    )


def test_GenuineFixtureHasExplicitPlatformAdmissionWithoutFakePosixOrHiddenSkips():
    """Allow only the explicit optional-platform skip before genuine fixture build dependencies."""

    tree = ast.parse(Path(__file__).read_text())
    imports = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert not any(name.startswith("tests.unit") for name in imports), (
        'Acceptance owns actual prerequisites and never imports the portable unit runtime '
        'doubles.'
    )
    assert not any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name) and node.func.value.id == "pytest"
        and node.func.attr in ("skip", "skipif") for node in ast.walk(tree)), (
        "Required genuine prerequisites may not become skipped acceptance"
    )
    source = ast.parse(Path(artifacts.__file__).read_text())
    guard = next(node for node in source.body if isinstance(node, ast.FunctionDef)
        and node.name == "AdmitHeaderPlatform")
    skip_calls = [node for node in ast.walk(source) if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute) and node.func.attr in ("skip", "skipif")]
    assert len(skip_calls) == 1 and skip_calls[0] in tuple(ast.walk(guard)), (
        "The only unsupported skip must belong to the explicit platform admission guard"
    )

    for module in (tree, source):
        assert not any(isinstance(statement, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "pytestmark"
                for target in statement.targets)
            and any(isinstance(item, ast.Attribute) and item.attr in ("skip", "skipif")
                for item in ast.walk(statement)) for statement in module.body), (
            "Module-wide skips must not suppress portable pure, mocked or source assertions"
        )

    for name in ("installed_header_worker", "header_evidence_run"):
        fixture = next(node for node in source.body if isinstance(node, ast.FunctionDef)
            and node.name == name)
        assert "header_platform" in {item.arg for item in fixture.args.args}, (
            "Genuine installation/evidence setup must depend on platform admission before build"
        )


@pytest.mark.parametrize("platform,flag,outcome", [("linux", None, "run"),
    ("linux", "1", "run"), ("win32", None, "unsupported"), ("win32", "1", "required-failure"),
    ("darwin", None, "unsupported"), ("darwin", "1", "required-failure")])
def test_PlatformAndRequiredFlagHaveExplicitDeterministicOutcomes(platform, flag, outcome):
    """Explicit input counterexamples never change host platform or execute genuine fixtures."""

    if outcome == "run":
        assert artifacts.AdmitHeaderPlatform(platform, flag) is None, (
            "Linux must proceed to actual required capabilities rather than skip their absence"
        )

    elif outcome == "required-failure":
        with pytest.raises(pytest.fail.Exception, match="Required.*supported Linux"):
            artifacts.AdmitHeaderPlatform(platform, flag)

    else:
        with pytest.raises(pytest.skip.Exception, match="not positive acceptance"):
            artifacts.AdmitHeaderPlatform(platform, flag)


@pytest.mark.parametrize("failure", ["invalid-json", "nonzero", "timeout", "launch"])
def test_MockedRawProcessFailureRetainsOriginalFactsBeforeAssertionsOrDecode(
    tmp_path, monkeypatch, failure,
):
    """Mocked process results preserve original streams/status even when consumers cannot decode."""

    owner = artifacts.HeaderEvidence(tmp_path / "local", tmp_path / "retained")
    stdout = b"not-json\x00original"
    stderr = b"original-error\xff"
    argv = ("unit-only-no-process",)

    def Run(arguments, **_options):
        """Return or raise a labelled unit double; never launch a process or helper."""

        invocation = owner.retained / "process-01-unit-process/invocation.json"
        value = json.loads(invocation.read_bytes())
        assert value["argv"] == list(argv) and value["state"] == "not-launched", (
            "Original invocation must be retained before entering the mocked process call"
        )

        if failure == "timeout":
            raise subprocess.TimeoutExpired(arguments, 1, output=stdout, stderr=stderr)

        if failure == "launch":
            raise OSError("Unit launch refusal; message is never artifact metadata")

        return subprocess.CompletedProcess(arguments, 7 if failure == "nonzero" else 0,
            stdout, stderr)

    monkeypatch.setattr(artifacts.subprocess, "run", Run)
    expected = {"invalid-json": json.JSONDecodeError, "nonzero": AssertionError,
        "timeout": subprocess.TimeoutExpired, "launch": OSError}[failure]

    with pytest.raises(expected):
        result = artifacts.HeaderProcess(owner, "unit-process", argv, cwd=tmp_path,
            environment={}, timeout=1)
        assert result.returncode == 0, "Mocked nonzero original return cannot pass consumer checks"
        json.loads(result.stdout)

    prefix = "process-01-unit-process"
    metadata = json.loads((owner.retained / prefix / "process.json").read_bytes())
    returned = failure in ("nonzero", "invalid-json")
    assert metadata["terminal_return_observed"] is returned, (
        "Only an actual returned unit result may have an observed terminal return"
    )
    assert metadata["returncode"] == (7 if failure == "nonzero" else 0 if returned else None), (
        "Raw exit/unknown state must survive independently of consumer assertions"
    )

    for role, raw in (("stdout", stdout), ("stderr", stderr)):
        retained = owner.retained / prefix / (role + ".bin")
        assert retained.exists() is (failure != "launch"), (
            "Absent original launch streams must remain absent rather than fabricated empty bytes"
        )

        if failure != "launch":
            assert retained.read_bytes() == raw, (
                "Original binary streams must survive failed decode"
            )
            assert metadata[role]["observed_sha256"] == hashlib.sha256(raw).hexdigest(), (
                "Original stream identity must match the retained bytes"
            )

        assert metadata[role]["complete_original"] is returned, (
            "Timeout prefixes and unavailable launch streams cannot become complete originals"
        )

    for path in owner.retained.rglob("*"):
        if path.is_file():
            assert path.read_bytes() == (
                owner.local / path.relative_to(owner.retained)
            ).read_bytes(), (
                "Canonical CI artifact root must preserve the same original facts as scratch"
            )


def test_MockedOverflowRetainsBoundedPrefixAndTruthfulOriginalSize(tmp_path, monkeypatch):
    """Unit output overflow refuses after retaining bounded explicitly incomplete bytes."""

    owner = artifacts.HeaderEvidence(tmp_path / "local", tmp_path / "retained")

    def Run(argv, **_options):
        """Return fixed unit bytes without invoking any actual process."""

        return subprocess.CompletedProcess(argv, 0, b"12345", b"")

    monkeypatch.setattr(artifacts.subprocess, "run", Run)

    with pytest.raises(AssertionError):
        artifacts.HeaderProcess(owner, "unit-overflow", ("unit-only-no-process",), cwd=tmp_path,
            environment={}, timeout=1, maximum=4)

    path = owner.retained / "process-01-unit-overflow"
    metadata = json.loads((path / "process.json").read_bytes())
    assert (path / "stdout.bin").read_bytes() == b"1234", "Only the bounded prefix may be retained"
    assert metadata["stdout"]["observed_size_bytes"] == 5 and (
        metadata["stdout"]["retention_overflow"] is True
        and metadata["stdout"]["complete_original"] is False
    ), "Overflow cannot become a complete successful stream despite the returned zero exit code"


@pytest.mark.parametrize("failure", ["consumer", "close", "constructor"])
def test_MockedListenerFailureAlwaysRetainsPostCloseTruth(tmp_path, monkeypatch, failure):
    """Labelled unit listener doubles preserve final cleanup/contact facts on every error path."""

    owner = artifacts.HeaderEvidence(tmp_path / "local", tmp_path / "retained")
    state = {"closed": False, "alive": True, "calls": 0}

    def Close():
        """Model actual close success or refusal without creating a thread, listener or socket."""

        state["calls"] += 1

        if failure == "close":
            raise OSError("Unit close refusal")

        state.update(closed=True, alive=False)

    def Construct(_wire):
        """Return only a labelled unit-owned object, or fail before an owner can be observed."""

        if failure == "constructor":
            raise OSError("Unit constructor refusal")

        return SimpleNamespace(Close=Close, origin="http://127.0.0.1:1", accepted=1,
            requests=[b"original-unit-get"],
            thread=SimpleNamespace(is_alive=lambda: state["alive"]),
            listener=SimpleNamespace(fileno=lambda: -1 if state["closed"] else 123))

    monkeypatch.setattr(artifacts, "OwnedResponseListener", Construct)

    with pytest.raises((ValueError, OSError)):
        with artifacts.HeaderListener(owner, b"unit-only-no-wire"):
            if failure == "consumer":
                raise ValueError("Unit consumer decode failure")

    final = json.loads((owner.retained / "listener-final.json").read_bytes())
    assert final == json.loads((owner.local / "listener-final.json").read_bytes()), (
        "Original post-cleanup facts must reach the canonical CI artifact destination on failure"
    )

    if failure == "constructor":
        assert final["cleanup"] == "unobserved" and final["listener_returned"] is False, (
            "An unobserved constructor owner cannot manufacture a completed cleanup"
        )

    else:
        assert state["calls"] == 1 and final["accepted"] == 1 and final["requests_hex"] == [
            b"original-unit-get".hex()], "Final facts must preserve actual controlled contacts"
        assert final["cleanup"] == ("unsettled" if failure == "close" else "settled"), (
            "An actual Close refusal must retain unsettled ownership rather than assert completion"
        )


def test_OfflineProductionSourceHasNoAcquisitionRuntimeOrEvidencePublicationCalls():
    """Reject newly introduced runtime imports/calls in the two fixed offline production owners."""

    forbidden_modules = {"socket", "subprocess", "threading", "multiprocessing", "asyncio",
        "http", "urllib", "requests", "httpx", "ctypes", "os", "pty", "importlib"}
    forbidden_calls = {"Put", "CaptureEvidence", "RunOwnedResponseCapture",
        "PlanOwnedResponseCapture", "PrepareOwnedResponseInvocation", "Popen", "system",
        "fork", "posix_spawn", "create_connection", "connect", "urlopen", "eval", "exec",
        "__import__"}

    for filename in ("native_response_headers.py", "native_response_header_workflow.py"):
        path = REPOSITORY / "src/fuzzy1337" / filename
        assert path.is_file(), "The separately reviewed offline production owner is required"
        tree = ast.parse(path.read_text())
        imports = {alias.name.split(".")[0] for node in ast.walk(tree)
            if isinstance(node, ast.Import) for alias in node.names}
        imports.update((node.module or "").split(".")[0] for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom))
        assert not imports & forbidden_modules, (
            'Reject newly introduced runtime imports/calls in the two fixed offline '
            'production owners.'
        )
        calls = {node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
            for node in ast.walk(tree) if isinstance(node, ast.Call)
            and isinstance(node.func, (ast.Attribute, ast.Name))}
        assert not calls & forbidden_calls, (
            'Reject newly introduced runtime imports/calls in the two fixed offline '
            'production owners.'
        )


def AnalysisPolicy(seconds: int = 300) -> ImpactPolicy:
    """Grant the explicit passive offline capability separately from acquisition permission."""

    return ImpactPolicy("independent-native-header", maximum_impact=ImpactLevel.PASSIVE,
        permissions=(CapabilityPermission(CAPABILITY, PROVIDER, ImpactLevel.PASSIVE),),
        max_authorization_seconds=seconds)


@pytest.fixture
def original(tmp_path, installed_header_worker, request, header_case_evidence):
    """Acquire actual originals and close/join the listener before exposing offline state."""

    assert sys.platform == "linux", "Genuine native-header acceptance requires actual Linux custody"
    case = getattr(request, "param", "missing")
    selected = "missing" if case == "refused" else case
    wire = FrozenOriginals()[selected]["response"]

    if case == "refused":
        wire = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"

    root = tmp_path / "workspace"

    with HeaderListener(header_case_evidence, wire) as listener:
        url = listener.origin + "/zap-passive/" + selected
        Setup({"workspace": str(root), "url": url})
        policy_path = tmp_path / "capture-policy.json"
        policy_path.write_text(json.dumps(Policy()))
        captured = HeaderConsumer(installed_header_worker, tmp_path, {"workspace": str(root),
            "policy": str(policy_path), "url": url}, header_case_evidence)
        assert captured["exception_type"] is None, "Actual capture SDK must return its owned result"
        assert Path(captured["runtime_module"]).is_relative_to(
            installed_header_worker.parents[1]
        ), (
            "Original capture SDK must import the clean actual installed wheel"
        )
        summary = captured["summary"]

    assert listener.accepted == 1 and listener.requests == [ExpectedRequest(listener, selected)], (
        'Acquire actual originals and close/join the listener before exposing offline '
        'state.'
    )
    assert listener.listener.fileno() == -1 and not listener.thread.is_alive(), (
        'Acquire actual originals and close/join the listener before exposing offline '
        'state.'
    )
    assert summary["original_receipt_id"] is not None, (
        "Use the actual retained original receipt only"
    )
    now = datetime.now(timezone.utc)
    state = None

    if case != "refused":
        assert summary["state"] == "completed" and summary["acquisition_outcome"] == "captured", (
            'Acquire actual originals and close/join the listener before exposing offline '
            'state.'
        )
        assert summary["custody_status"] == "complete", (
            'Acquire actual originals and close/join the listener before exposing offline '
            'state.'
        )
        assert summary["model_persistence_status"] == summary["workspace_persistence_status"] == (
            "acknowledged"), (
            'Acquire actual originals and close/join the listener before exposing offline '
            'state.'
        )
        state = OriginalState(root, summary["original_receipt_id"])
        assert len(captured["executions"]) == 1, (
            "Genuine source must preserve exactly one actual installed worker execution"
        )
        assert captured["executions"][0]["execution"] == state["receipt"]["execution"], (
            "Original receipt must retain the actual executor terminal result"
        )
        frozen = FrozenOriginals()[selected]
        assert state["bytes"]["owned-response-headers"] == frozen["header_section"], (
            'Acquire actual originals and close/join the listener before exposing offline '
            'state.'
        )
        assert state["bytes"]["owned-response-body"] == frozen["body"], (
            'Acquire actual originals and close/join the listener before exposing offline '
            'state.'
        )
        assert state["bytes"]["owned-response-wire"] == frozen["response"], (
            'Acquire actual originals and close/join the listener before exposing offline '
            'state.'
        )

    else:
        assert summary["state"] != "completed" and summary["acquisition_outcome"] != "captured", (
            'Acquire actual originals and close/join the listener before exposing offline '
            'state.'
        )

    return SimpleNamespace(root=root, url=url, receipt=summary["original_receipt_id"],
        source=state, now=now, listener=listener, capture=captured, evidence=header_case_evidence)


@pytest.fixture
def offline(original, monkeypatch):
    """Install tripwires only after actual source cleanup, before any new interpretation/replay."""

    path = REPOSITORY / "src/fuzzy1337/native_response_header_workflow.py"
    assert path.is_file(), "Missing separately reviewed native offline workflow implementation"
    workflow = importlib.import_module(WORKFLOW)

    def Forbidden(*_args, **_kwargs):
        """Reject every new target/runtime/helper/capture/publication path during offline work."""

        raise AssertionError("Offline native-header operation attempted forbidden external work")

    blocked = set()

    for module, names in ((socket, ("socket", "create_connection", "getaddrinfo")),
        (subprocess, ("Popen", "run", "call", "check_call", "check_output")),
        (asyncio, ("create_subprocess_exec", "create_subprocess_shell")),
        (os, ("system", "fork", "forkpty", "posix_spawn", "posix_spawnp", "startfile")),
        (threading.Thread, ("start",)), (multiprocessing.Process, ("start",)),
        (LocalExecutor, ("Execute",)), (GovernedLocalExecutor, ("Execute",)),
        (PolicyEngine, ("Plan", "Authorize")),
        (LocalEvidenceStore, ("Put", "PublishStoredBytes")),
        (OwnedResponseStage, ("__init__", "Append")),
        (capture_parent.OwnedResponseCaptureProvider, ("__init__",)),
        (capture_parent, ("PrepareOwnedResponseInvocation",)),
        (acquisition, ("RunOwnedResponseCapture", "PlanOwnedResponseCapture",
            "PrepareOwnedResponseInvocation")),
        (workflow, ("RunOwnedResponseCapture", "PlanOwnedResponseCapture",
            "PrepareOwnedResponseInvocation"))):
        for name in names:
            if hasattr(module, name):
                blocked.add(id(getattr(module, name)))
                monkeypatch.setattr(module, name, Forbidden)

    for name in ("fuzzy1337.native_response_headers", WORKFLOW):
        module = sys.modules[name]

        for attribute, value in tuple(vars(module).items()):
            if id(value) in blocked:
                monkeypatch.setattr(module, attribute, Forbidden)

    return workflow


def Apply(workflow, original, analysis: str = "analysis:independent-header", **options):
    """Use exact current selected revisions and fixed explicit attribution through the real SDK."""

    inputs = {"analysis_reference": analysis,
        "expected_model_revision": LocalModelStore(original.root).Open().revision,
        "expected_workspace_revision": LocalWorkspaceStore(original.root).Open().revision,
        "approve_passive_header_check": True, "clock": lambda: original.now}
    policy = options.pop("policy_provider", AnalysisPolicy)
    inputs.update(options)
    original.evidence.analysis_sequence += 1
    assert original.evidence.analysis_sequence <= 4, (
        "Each fixed test case permits only four retained offline analysis attempts"
    )

    summary = workflow.ApplyOwnedResponseHeaderCheck(original.root, "owned-source",
        original.receipt, Target(TargetKind.URL, original.url), OWNER, policy, **inputs)
    identity = hashlib.sha256(analysis.encode()).hexdigest()
    original.evidence.Json("actual-native-header-" + str(original.evidence.analysis_sequence)
        + "-" + identity + ".json", summary.ToDict())

    return summary


@pytest.mark.integration
@pytest.mark.parametrize("original", ["missing", "fixed", "body-decoy"], indirect=True)
def test_ActualSavedFindingTruthAndRelocatedReplayNeedNoLiveTarget(original, offline, monkeypatch):
    """Score actual originals and saved native Findings after listener removal."""

    summary = Apply(offline, original)
    assert summary.ToDict()["state"] == "completed", (
        'Score actual originals and saved native Findings after listener removal.'
    )
    fact, findings = AssertInterpretation(original.root, original.source,
        "analysis:independent-header", original.url)
    after = LocalModelStore(original.root).Open()
    workspace = LocalWorkspaceStore(original.root).Open()
    assert after.revision == original.source["model"].revision + 1, (
        'Score actual originals and saved native Findings after listener removal.'
    )
    assert workspace.revision == original.source["workspace"].revision + bool(findings), (
        'Score actual originals and saved native Findings after listener removal.'
    )
    unrelated = tuple(item for item in original.source["model"].objects
        if item.identity.kind is not ObjectKind.ENDPOINT)
    assert all(item in after.objects for item in unrelated), (
        'Score actual originals and saved native Findings after listener removal.'
    )
    relocated = original.root.parent / "relocated"
    shutil.move(original.root, relocated)

    def Refuse(*_args, **_kwargs):
        """Historical verification has no write or current-authority owner."""

        raise AssertionError("Historical native-header replay attempted Save or current scope")

    monkeypatch.setattr(LocalModelStore, "Save", Refuse)
    monkeypatch.setattr(LocalWorkspaceStore, "Save", Refuse)
    monkeypatch.setattr(LocalScopeStore, "Open", Refuse)
    replay = offline.ReplayOwnedResponseHeaderCheck(relocated, fact.Reference())
    assert replay.ToDict()["state"] == "verified", (
        'Score actual originals and saved native Findings after listener removal.'
    )
    assert LocalModelStore(relocated).Open() == after, (
        'Score actual originals and saved native Findings after listener removal.'
    )
    assert LocalWorkspaceStore(relocated).Open() == workspace, (
        'Score actual originals and saved native Findings after listener removal.'
    )


@pytest.mark.integration
def test_SuppliedCurrentOwnerIsDistinctFromConsentAttester(original, offline):
    """A genuine trusted-reader application retains selected owner without replacing consent."""

    scope = LocalScopeStore(original.root).Open("owned-source")
    assert scope.authorization.authority_reference != OWNER, (
        "Fixture consent must come from the distinct independent attester"
    )
    summary = Apply(offline, original, current_owner_provider=lambda: OWNER)
    assert summary.ToDict()["state"] == "completed", "Fresh exact owner attribution must admit"
    fact, _findings = AssertInterpretation(original.root, original.source,
        "analysis:independent-header", original.url)
    assert fact.attributes["authority_basis"]["owner_attribution"] == "trusted-reader", (
        "Assessment must record that the optional trusted reader was actually supplied"
    )


@pytest.mark.integration
@pytest.mark.parametrize("denial", ["opt-in", "capture-permission", "owner-before", "owner-save",
    "stale-model", "stale-workspace", "url-exclusion", "ip-exclusion", "expired",
    "unknown-receipt"])
def test_IndependentAuthorityAndSelectedSourceRefuseBeforeAnySave(
    original, offline, monkeypatch, denial,
):
    """Capture permission, attester identity, drift or stale bases cannot grant analysis."""

    model = LocalModelStore(original.root).Open()
    options = {}

    if denial == "opt-in":
        options["approve_passive_header_check"] = False

    elif denial == "capture-permission":
        options["policy_provider"] = lambda: ImpactPolicy("capture-only", permissions=(
            CapabilityPermission("http.synthetic-response-capture", "native.loopback-response",
                ImpactLevel.SAFE),))

    elif denial.startswith("owner-"):
        changed = [denial == "owner-before"]
        interpreted = []

        def Owner():
            """Return drift initially or after the actual interpretation proposal is composed."""

            return "actor:changed" if changed[0] else OWNER

        options["current_owner_provider"] = Owner

        if denial == "owner-save":
            original_apply = offline.ApplyVerifiedFindings

            def Interpret(*args, **kwargs):
                """Preserve the real composed interpretation and revoke before its Save fence."""

                proposal = original_apply(*args, **kwargs)
                interpreted.append(None)
                changed[0] = True

                return proposal

            monkeypatch.setattr(offline, "ApplyVerifiedFindings", Interpret)

    elif denial == "stale-model":
        options["expected_model_revision"] = model.revision - 1

    elif denial == "stale-workspace":
        options["expected_workspace_revision"] = 0

    elif denial in ("url-exclusion", "ip-exclusion", "expired"):
        store = LocalScopeStore(original.root)
        scope = store.Open("owned-source")

        if denial == "expired":
            scope = replace(scope, authorization=replace(scope.authorization,
                valid_until=(original.now - timedelta(seconds=1)).isoformat()))

        else:
            target = Target(TargetKind.URL, original.url) if denial == "url-exclusion" else (
                Target(TargetKind.IP, "127.0.0.1"))
            scope = replace(scope, exclusions=(target,))

        store.Save(scope)

    else:
        original.receipt = "sha256:" + "0" * 64

    workspace = LocalWorkspaceStore(original.root).Open()

    summary = Apply(offline, original, **options)
    data = summary.ToDict()

    if denial.startswith("stale-"):
        assert (data["state"], data["failure"]) == ("failed", "revision-conflict"), (
            "The selected stale original CAS base must refuse without rebase"
        )

    elif denial == "unknown-receipt":
        assert (data["state"], data["failure"]) == ("failed", "source"), (
            "An unknown original receipt must fail source association"
        )

    else:
        assert (data["state"], data["failure"]) == ("denied", "authorization"), (
            "Missing or changed current analysis authority must produce its actual denial"
        )

    if denial == "owner-save":
        assert interpreted == [None], "The actual interpretation must precede this pre-Save denial"

    AssertNoNewInterpretation(original.root, model, workspace)


@pytest.mark.integration
@pytest.mark.parametrize("boundary", ["policy-deadline", "consent-deadline", "no-consent-expiry",
    "clock-regression", "clock-regression-inside"])
def test_OriginalAdmissionWindowNeverRenewsAfterSynchronousRead(
    original, offline, monkeypatch, boundary,
):
    """A late or regressed original read cannot use an unchanged policy to reach Save."""

    scope_store = LocalScopeStore(original.root)
    scope = scope_store.Open("owned-source")
    expiry = None if boundary == "no-consent-expiry" else (
        original.now + timedelta(seconds=1 if boundary == "consent-deadline" else 60)).isoformat()
    scope_store.Save(replace(scope, authorization=replace(scope.authorization, valid_until=expiry)))
    before = LocalModelStore(original.root).Open()
    workspace = LocalWorkspaceStore(original.root).Open()
    at = [original.now]
    samples = []
    original_read = OwnedResponseEvidenceStore.Read

    def Read(store, reference):
        """Return actual original bytes, then advance only the controlled admission clock."""

        raw = original_read(store, reference)
        if boundary != "clock-regression-inside":
            at[0] = original.now + timedelta(seconds=-1 if boundary == "clock-regression" else 1)

        return raw

    def Clock():
        """Regress after a later decision while every sample remains inside the original window."""

        samples.append(None)

        if boundary == "clock-regression-inside":
            offset = (0, 0.5, 0.25)[min(len(samples) - 1, 2)]

            return original.now + timedelta(seconds=offset)

        return at[0]

    monkeypatch.setattr(OwnedResponseEvidenceStore, "Read", Read)

    seconds = 60 if boundary == "consent-deadline" else 1
    summary = Apply(offline, original, clock=Clock,
        policy_provider=lambda: AnalysisPolicy(seconds))
    assert summary.ToDict()["state"] == "denied", (
        'A late or regressed original read cannot use an unchanged policy to reach Save.'
    )
    assert summary.ToDict()["failure"] == (
        "clock-regression" if boundary.startswith("clock-regression") else "admission-expired"), (
        'A late or regressed original read cannot use an unchanged policy to reach Save.'
    )

    if boundary == "clock-regression-inside":
        assert len(samples) >= 3, "The causal regression must follow the observed later decision"

    AssertNoNewInterpretation(original.root, before, workspace)


@pytest.mark.integration
def test_ExpiryAfterActualModelAckPreservesPartialCommitWithoutReferenceSave(
    original, offline, monkeypatch,
):
    """Expiry cannot erase an acknowledged model transition or authorize a later workspace Save."""

    original_save = LocalModelStore.Save
    calls = {"model": 0, "workspace": 0}
    at = [original.now]
    workspace = LocalWorkspaceStore(original.root).Open()

    def ModelSave(store, state, *, expected_revision):
        """Commit through the actual owner, then reach the original exclusive deadline."""

        calls["model"] += 1
        saved = original_save(store, state, expected_revision=expected_revision)
        at[0] = original.now + timedelta(seconds=1)

        return saved

    def WorkspaceSave(*_args, **_kwargs):
        """Count and reject any unauthorized reference-retention attempt after expiry."""

        calls["workspace"] += 1

        raise AssertionError("Expired offline authority reached workspace Save")

    monkeypatch.setattr(LocalModelStore, "Save", ModelSave)
    monkeypatch.setattr(LocalWorkspaceStore, "Save", WorkspaceSave)
    summary = Apply(offline, original, clock=lambda: at[0],
        policy_provider=lambda: AnalysisPolicy(1)).ToDict()
    assert summary["state"] == "partial" and summary["model_commit"] == "acknowledged", (
        "An actual earlier model ACK must remain truthful on later authority expiry"
    )
    assert summary["workspace_commit"] == "not-attempted" and calls == {
        "model": 1, "workspace": 0}, "Expiry cannot renew the window or retry either owner"
    assert NativeFindingObjects(LocalModelStore(original.root).Open()), (
        "The actual acknowledged model Finding must remain available as partial state"
    )
    assert LocalWorkspaceStore(original.root).Open() == workspace, (
        "Reference retention cannot proceed after exclusive expiry"
    )


@pytest.mark.integration
@pytest.mark.parametrize("damage", ["missing-header", "corrupt-header", "missing-role-retention",
    "foreign-source", "missing-source", "missing-job-retention", "rehashed-foreign-header"])
def test_OriginalSourceDamageCannotBecomeAHeaderFinding(original, offline, damage):
    """Reusing content or labels cannot repair the actual original-role/source/job association."""

    if damage in ("missing-header", "corrupt-header"):
        record = original.source["records"]["owned-response-headers"]
        path = original.root / "evidence" / record.reference.locator

        if damage == "missing-header":
            path.unlink()

        else:
            path.write_bytes(b"X" * record.reference.size_bytes)

    elif damage in ("missing-role-retention", "missing-job-retention"):
        store = LocalWorkspaceStore(original.root)
        state = store.Open()
        state = replace(state, evidence_record_references=tuple(identity for identity in
            state.evidence_record_references if identity != original.source["ids"][
                "owned-response-headers"])) if damage == "missing-role-retention" else (
            replace(state, job_references=()))
        store.Save(state)

    elif damage == "rehashed-foreign-header":
        raw = b"HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\n\r\n"
        digest = hashlib.sha256(raw).hexdigest()
        manifest = original.source["records"]["owned-response-headers"].ToDict()
        manifest["reference"].update(sha256=digest, size_bytes=len(raw),
            locator="blobs/sha256/" + digest)
        encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False).encode()
        forged = "sha256:" + hashlib.sha256(encoded).hexdigest()
        blob = original.root / "evidence/blobs/sha256" / digest
        record = original.root / "evidence/records" / (forged[7:] + ".json")
        blob.write_bytes(raw)
        blob.chmod(0o600)
        record.write_bytes(encoded)
        record.chmod(0o600)
        admitted = OwnedResponseEvidenceStore(original.root / "evidence").Get(forged)
        assert admitted.reference.sha256 == digest, (
            "Controlled foreign part must have coherent bytes/manifest before source refusal"
        )
        store = LocalModelStore(original.root)
        state = store.Open()
        fact = original.source["source"]
        attrs = dict(fact.attributes)
        attrs["original_role_ids"] = dict(attrs["original_role_ids"],
            **{"owned-response-headers": forged})
        facts = tuple(replace(item, attributes=attrs) if item == fact else item
            for item in state.observations)
        store.Save(replace(state, revision=state.revision + 1, observations=facts),
            expected_revision=state.revision)

    else:
        store = LocalModelStore(original.root)
        state = store.Open()
        fact = original.source["source"]
        observations = tuple(item for item in state.observations if item != fact)

        if damage == "foreign-source":
            attrs = dict(fact.attributes)
            attrs["original_job_id"] = "job:foreign"
            observations += (replace(fact, attributes=attrs),)

        store.Save(replace(state, revision=state.revision + 1, observations=observations),
            expected_revision=state.revision)

    model = LocalModelStore(original.root).Open()
    workspace = LocalWorkspaceStore(original.root).Open()

    summary = Apply(offline, original)
    assert summary.ToDict()["state"] == "failed" and summary.ToDict()["failure"] == "source", (
        'Reusing content or labels cannot repair the actual original-role/source/job '
        'association.'
    )

    AssertNoNewInterpretation(original.root, model, workspace)


@pytest.mark.integration
@pytest.mark.parametrize("original", ["refused"], indirect=True)
def test_ActualRefusedCaptureReceiptNeverSubstitutesForSuccessfulOriginals(original, offline):
    """A genuine retained refusal may be inspected but cannot become source custody or a Finding."""

    model = LocalModelStore(original.root).Open()
    workspace = LocalWorkspaceStore(original.root).Open()

    summary = Apply(offline, original)
    assert summary.ToDict()["state"] == "failed" and summary.ToDict()["failure"] == "source", (
        'A genuine retained refusal may be inspected but cannot become source custody or '
        'a Finding.'
    )

    AssertNoNewInterpretation(original.root, model, workspace)


@pytest.mark.integration
@pytest.mark.parametrize("boundary", ["model-before", "model-after", "workspace-before",
    "workspace-after", "model-conflict", "workspace-conflict"])
def test_TwoCasOwnersPreserveActualPartialStateAndNeverInventLostAcks(
    original, offline, monkeypatch, boundary,
):
    """An actual model commit survives later reference failure without retry, rebase or rollback."""

    model_save = LocalModelStore.Save
    workspace_save = LocalWorkspaceStore.Save
    calls = {"model": 0, "workspace": 0}
    observed = {}

    def ModelSave(store, state, *, expected_revision):
        """Inject one actual owning-store refusal, concurrent commit or lost acknowledgement."""

        calls["model"] += 1

        if boundary == "model-before":
            raise OSError("Independent controlled model refusal")

        if boundary == "model-conflict":
            before = store.Open()
            observed["model"] = model_save(store, replace(before, revision=before.revision + 1),
                expected_revision=before.revision)

        result = model_save(store, state, expected_revision=expected_revision)

        if boundary == "model-after":
            raise OSError("Independent controlled lost model ACK")

        return result

    def WorkspaceSave(store, state):
        """Retain the model independently of this second original-basis CAS result."""

        calls["workspace"] += 1

        if boundary == "workspace-before":
            raise OSError("Independent controlled reference refusal")

        if boundary == "workspace-conflict":
            observed["workspace"] = workspace_save(store, store.Open())

        result = workspace_save(store, state)

        if boundary == "workspace-after":
            raise OSError("Independent controlled lost reference ACK")

        return result

    monkeypatch.setattr(LocalModelStore, "Save", ModelSave)
    monkeypatch.setattr(LocalWorkspaceStore, "Save", WorkspaceSave)
    summary = Apply(offline, original)
    data = summary.ToDict()
    assert data["state"] != "completed", (
        'An actual model commit survives later reference failure without retry, rebase or '
        'rollback.'
    )
    assert calls["model"] == 1 and calls["workspace"] <= 1, (
        'An actual model commit survives later reference failure without retry, rebase or '
        'rollback.'
    )
    after = LocalModelStore(original.root).Open()
    workspace = LocalWorkspaceStore(original.root).Open()
    committed = boundary not in ("model-before", "model-conflict")
    expected_commits = {
        "model-before": ("observed-unchanged", "not-attempted"),
        "model-after": ("observed-committed", "not-attempted"),
        "workspace-before": ("acknowledged", "observed-unchanged"),
        "workspace-after": ("acknowledged", "observed-committed"),
        "model-conflict": ("unconfirmed", "not-attempted"),
        "workspace-conflict": ("acknowledged", "unconfirmed"),
    }
    assert (data["model_commit"], data["workspace_commit"]) == expected_commits[boundary], (
        "Each original store owner must report its actual ACK/observed/conflict state separately"
    )
    assert data["state"] == ("partial" if committed else "failed"), (
        "Actual retained model interpretation, rather than an absent ACK, determines partial state"
    )
    assert bool(NativeFindingObjects(after)) is committed, (
        'An actual model commit survives later reference failure without retry, rebase or '
        'rollback.'
    )
    assert any(item.kind == ASSESSMENT for item in after.observations) is committed, (
        'An actual model commit survives later reference failure without retry, rebase or '
        'rollback.'
    )

    if committed:
        fact, = (item for item in after.observations if item.kind == ASSESSMENT)
        assert data["assessment_reference"] == fact.Reference(), (
            "Partial summary must retain the actual observed assessment identity"
        )

    else:
        assert data["assessment_reference"] is None and data["finding_reference"] is None, (
            "A failed original model Save cannot fabricate retained interpretation identities"
        )

    if boundary.endswith("after"):
        key = "model_commit" if boundary.startswith("model") else "workspace_commit"
        assert data[key] == "observed-committed", "Observed commit must never manufacture Save ACK"

    if boundary.startswith("model"):
        assert calls["workspace"] == 0, "Unacknowledged model Save cannot authorize reference Save"

    if boundary in ("workspace-before", "workspace-conflict"):
        assert data["model_commit"] == "acknowledged", (
            'An actual model commit survives later reference failure without retry, '
            'rebase or rollback.'
        )
        assert any(item.Reference() not in workspace.object_references
            for item in NativeFindingObjects(after)), (
            'An actual model commit survives later reference failure without retry, '
            'rebase or rollback.'
        )
        model_before = after
        workspace_before = workspace
        reused = Apply(offline, original)
        assert reused.ToDict()["state"] == "partial", (
            'An actual model commit survives later reference failure without retry, '
            'rebase or rollback.'
        )
        AssertNoNewInterpretation(original.root, model_before, workspace_before)
        assert calls == {"model": 1, "workspace": 1}, "Reuse cannot repair a previous partial Save"
        fact, = (item for item in after.observations if item.kind == ASSESSMENT)

        with pytest.raises(ValueError):
            offline.ReplayOwnedResponseHeaderCheck(original.root, fact.Reference())

    for owner, committed_state in observed.items():
        assert (after if owner == "model" else workspace) == committed_state, (
            'An actual model commit survives later reference failure without retry, '
            'rebase or rollback.'
        )


@pytest.mark.integration
def test_TriageExactReuseAndNewAnalysisPreserveExistingFinding(
    original, offline, monkeypatch,
):
    """Exact reuse performs no Save; later analyses preserve actual operator triage."""

    Apply(offline, original)
    store = LocalModelStore(original.root)
    state = store.Open()
    entity, = NativeFindingObjects(state)
    attrs = dict(entity.attributes)
    attrs.update(status=FindingStatus.CONFIRMED.value, status_reason="Independent operator triage")
    proposed, _delta = state.Apply(objects=(replace(entity, attributes=attrs),))
    triaged = store.Save(proposed, expected_revision=state.revision)
    workspace = LocalWorkspaceStore(original.root).Open()

    def Refuse(*_args, **_kwargs):
        """Reusing the exact analysis must not retry either canonical owner."""

        raise AssertionError("Exact analysis reuse attempted another Save")

    with monkeypatch.context() as context:
        context.setattr(LocalModelStore, "Save", Refuse)
        context.setattr(LocalWorkspaceStore, "Save", Refuse)
        reused = Apply(offline, original)
        assert reused.ToDict()["state"] == "already-applied", (
            'Exact reuse performs no Save; later analyses preserve actual operator '
            'triage.'
        )
        AssertNoNewInterpretation(original.root, triaged, workspace)
        fact = next(item for item in triaged.observations if item.kind == ASSESSMENT)
        replay = offline.ReplayOwnedResponseHeaderCheck(original.root, fact.Reference())
        assert replay.ToDict()["state"] == "verified", (
            "Historical detection verification must allow later valid operator triage"
        )

    Apply(offline, original, "analysis:second-explicit-interpretation")
    after = LocalModelStore(original.root).Open()
    retained, = NativeFindingObjects(after)
    assert retained.attributes["status"] == FindingStatus.CONFIRMED.value, (
        'Exact reuse performs no Save; later analyses preserve actual operator triage.'
    )
    assert retained.attributes["status_reason"] == "Independent operator triage", (
        'Exact reuse performs no Save; later analyses preserve actual operator triage.'
    )
    assert len([item for item in after.observations if item.kind == ASSESSMENT]) == 2, (
        'Exact reuse performs no Save; later analyses preserve actual operator triage.'
    )


@pytest.mark.integration
def test_ConflictingAnalysisOwnerReuseCannotReattributeOrSave(original, offline, monkeypatch):
    """An existing explicit analysis reference cannot silently change its executing attribution."""

    first = Apply(offline, original)
    assert first.ToDict()["state"] == "completed", "The selected original analysis must exist"
    model = LocalModelStore(original.root).Open()
    workspace = LocalWorkspaceStore(original.root).Open()

    def Refuse(*_args, **_kwargs):
        """Reattribution is a refusal, never a second persistence attempt."""

        raise AssertionError("Conflicting analysis owner reached a canonical Save")

    monkeypatch.setattr(LocalModelStore, "Save", Refuse)
    monkeypatch.setattr(LocalWorkspaceStore, "Save", Refuse)
    changed = offline.ApplyOwnedResponseHeaderCheck(original.root, "owned-source", original.receipt,
        Target(TargetKind.URL, original.url), "actor:other-explicit-owner", AnalysisPolicy,
        analysis_reference="analysis:independent-header", expected_model_revision=model.revision,
        expected_workspace_revision=workspace.revision, approve_passive_header_check=True,
        clock=lambda: original.now)
    assert changed.ToDict()["state"] in ("denied", "failed"), (
        "Conflicting reuse must refuse rather than claim existing analysis as the new owner"
    )
    AssertNoNewInterpretation(original.root, model, workspace)


@pytest.mark.integration
@pytest.mark.parametrize("original", ["fixed"], indirect=True)
def test_NegativeAssessmentNeverResolvesControlledExistingOperatorTriage(original, offline):
    """An actual negative source cannot delete or resolve an explicitly seeded earlier Finding."""

    model_store = LocalModelStore(original.root)
    state = model_store.Open()
    attribution = ModelProvenance("operator.seed", "analysis:controlled-earlier-state",
        original.now.isoformat(), "scope:owned-source", Target(TargetKind.URL,
            original.url).Reference(), "1", tuple(item.reference for item in
                original.source["records"].values()))
    seeded = Finding(original.source["source"].subject_reference, CHECK,
        original.url + "#response-header:x-content-type-options",
        "Controlled existing triage; not a claimed native detector result", (attribution,),
        severity=FindingSeverity.LOW, status=FindingStatus.CONFIRMED,
        status_reason="Independent existing operator disposition").ToObject(state.workspace_id)
    proposed, _delta = state.Apply(objects=(seeded,))
    model_store.Save(proposed, expected_revision=state.revision)
    workspace_store = LocalWorkspaceStore(original.root)
    workspace = workspace_store.Open()
    workspace_store.Save(replace(workspace,
        object_references=(*workspace.object_references, seeded.Reference())))
    before = model_store.Open()
    source = dict(original.source, model=before, workspace=workspace_store.Open())
    summary = Apply(offline, original)
    assert summary.ToDict()["state"] == "completed", (
        'An actual negative source cannot delete or resolve an explicitly seeded earlier '
        'Finding.'
    )
    fact, findings = AssertInterpretation(original.root, source,
        "analysis:independent-header", original.url)
    assert fact.attributes["condition_observed"] is False and not findings, (
        'An actual negative source cannot delete or resolve an explicitly seeded earlier '
        'Finding.'
    )
    assert seeded in model_store.Open().objects, (
        'An actual negative source cannot delete or resolve an explicitly seeded earlier '
        'Finding.'
    )
