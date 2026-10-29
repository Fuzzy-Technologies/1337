# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Mocked finite SDK pipeline control flow; no setup, target, SDK, store or runtime acceptance."""

from __future__ import annotations

import json
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from subprocess import CompletedProcess
from types import SimpleNamespace

import pytest

from tests.contract import owned_content_response_sdk_pipeline as pipeline


def Selection(tmp_path, *, case="missing", scenario="positive"):
    """Declare independent synthetic future fixture inputs without creating a product owner."""

    return {"fixture_id": "mock-run-0001", "workspace": str(tmp_path / "original"),
        "relocated_workspace": str(tmp_path / "relocated"),
        "observations": str(tmp_path / "observations"),
        "url": "http://127.0.0.1:15432/research/content", "case": case, "scenario": scenario,
        "consent_valid_from": "2030-01-01T00:00:00+00:00",
        "consent_valid_until": "2030-01-01T00:05:00+00:00"}


def Guard(*, historical=False):
    """Return explicitly mocked tripwire facts; these are never real offline observations."""

    calls = {key: 0 for key in ("socket.audit", "socket.socket", "subprocess.Popen",
        "LocalExecutor.Execute", "GovernedLocalExecutor.Execute", "PolicyEngine.Authorize",
        "LocalEvidenceStore.Put", "LocalEvidenceStore.PublishStoredBytes",
        "OwnedResponseStage.__init__")}

    if historical:
        calls.update({key: 0 for key in (
            "LocalModelStore.Save", "LocalWorkspaceStore.Save", "LocalScopeStore.Open")})

    return {"calls": calls, "audit_probe_seen": True, "saves": []}


class MockSequence:
    """Provide marked mock handoffs and oracle spies without touching any runtime seam."""

    def __init__(self, plan, monkeypatch):
        """Own detached synthetic values and replace only pure assertions for wiring checks."""

        self.plan = plan
        self.calls = []
        self.oracles = []
        self.before = {"workspace": {"workspace_id": plan["workspace_id"], "revision": 1},
            "model": {"workspace_id": plan["workspace_id"], "revision": 2}, "originals": {}}
        self.acquired = deepcopy(self.before)
        self.acquired["workspace"]["revision"] = 2
        self.acquired["model"]["revision"] = 3
        self.interpreted = deepcopy(self.acquired)
        self.summary = {"original_receipt_id": "receipt:mock-only",
            "original_job_id": "job:mock-only", "source_facts": {"mock_only": True}}
        self.identities = {"original_receipt_id": "receipt:mock-only",
            "analysis_reference": plan["analysis_reference"],
            "assessment_reference": "assessment:mock-only", "condition_observed": True,
            "finding_reference": "finding:mock-only" if plan["expected_findings"] else None}
        self.analysis = {"summary": {"state": plan["expected_state"], "failure": "authorization",
            "condition_observed": None, "assessment_reference": None, "finding_reference": None},
            "guard": Guard()}
        self.replay = {"summary": {"mock_replay": True}, "guard": Guard(historical=True)}
        self.relocated = {"original_root_absent": True, "relocated_root_present": True}
        self.scope = {"scope_id": plan["scope_id"], "workspace_id": plan["workspace_id"],
            "authorization": {"state": "granted", "authority_reference": plan[
                "attester_reference"], "record_reference": plan["consent_reference"],
                "valid_from": plan["selection"]["consent_valid_from"],
                "valid_until": plan["selection"]["consent_valid_until"]}}
        self.policies = {role: {"path": f"/mock-only/{role}.json", "document": {
            "mock_policy": role}} for role in ("acquisition", "analysis", "analysis-denied")}

        def CaptureOracle(*args, **kwargs):
            """Observe unmodified SDK-save input wiring; no acquisition is asserted here."""

            assert args == (self.before, self.acquired, self.summary, []), (
                "Capture oracle must receive original before/after states, the actual summary and "
                "Save trace."
            )
            assert kwargs["workspace_id"] == plan["workspace_id"], (
                "Capture oracle must retain the independently selected workspace identity."
            )
            self.oracles.append("capture")

        def PartsOracle(*args, **kwargs):
            """Observe selected original receipt/case wiring without manufacturing any parts."""

            assert args == (plan["selection"]["case"], plan["selection"]["url"],
                "receipt:mock-only", {}, self.summary["source_facts"]), (
                "Parts oracle must receive the exact selected case, URL, receipt and source facts."
            )
            assert kwargs == {"job_id": "job:mock-only"}, (
                "Parts oracle must bind the actual original capture job rather than a guessed job "
                "ID."
            )
            self.oracles.append("parts")

        def HeaderOracle(*args, **kwargs):
            """Observe original state/guard Save wiring and independently selected authority."""

            assert args == (self.acquired, self.interpreted, self.analysis["summary"], []), (
                "Header oracle must receive acquired and interpreted states with the actual "
                "analysis summary."
            )
            assert kwargs["analysis"] == plan["analysis_reference"] and (
                kwargs["authority"]["scope"] is self.scope), (
                "Header oracle must retain the selected analysis reference and original authority "
                "scope object."
            )
            assert kwargs["authority"]["owner_attribution"] == "trusted-reader", (
                "The active analysis oracle must retain trusted-reader owner attribution."
            )
            self.oracles.append("header")

            return self.identities

        def ReplayOracle(*args):
            """Observe the same persisted identities and relocated snapshots, never replay."""

            assert args == (self.interpreted, self.interpreted,
                self.replay["summary"], self.identities), (
                "Replay oracle must receive unchanged interpreted state and the exact original "
                "result identities."
            )
            self.oracles.append("replay")

        monkeypatch.setattr(pipeline, "AssertSdkSaveTransition", CaptureOracle)
        monkeypatch.setattr(pipeline, "AssertContentParts", PartsOracle)
        monkeypatch.setattr(pipeline, "AssertContentHeaderV2", HeaderOracle)
        monkeypatch.setattr(pipeline, "AssertHistoricalContentHeaderReplay", ReplayOracle)

    def Handoff(self, operation, selection, observations):
        """Return marked mock documents; relocation creates only an empty filesystem sentinel."""

        self.calls.append((operation, deepcopy(selection), observations))

        if operation == "fresh-setup":
            return {"state": self.before, "scope": self.scope, "policies": self.policies}

        if operation == "capture":
            return {"summary": self.summary, "store_saves": []}

        if operation == "inspect":
            return {"state": self.acquired if len(self.calls) == 3 else self.interpreted}

        if operation == "analyze-offline":
            return self.analysis

        if operation == "relocate":
            Path(selection["relocated_workspace"]).mkdir()

            return self.relocated

        assert operation == "replay-offline", "The coordinator has no general command dispatch"

        return self.replay


@pytest.mark.parametrize("case,expected", [("missing", 1), ("fixed", 0), ("body-decoy", 1)])
def test_MockedSequenceKeepsIndependentFindingTruthAndRelocatedHeaderReplay(
    tmp_path, monkeypatch, case, expected,
):
    """One fixed operation order preserves actual selections and fresh observation ownership."""

    plan = pipeline.Plan(Selection(tmp_path, case=case))
    mock = MockSequence(plan, monkeypatch)
    result = pipeline.Run(plan, mock.Handoff, enabled=True)
    assert result["state"] == "checked-header-replay" and result["expected_findings"] == expected, (
        "The completed inert pipeline must retain the expected replay state and exact Finding "
        "count."
    )
    assert mock.oracles == ["capture", "parts", "header", "replay"], (
        "The pipeline must invoke capture, parts, header and replay oracles in their original "
        "order."
    )
    assert [item[0] for item in mock.calls] == ["fresh-setup", "capture", "inspect",
        "analyze-offline", "inspect", "relocate", "inspect", "replay-offline", "inspect"], (
        "Product handoffs must preserve setup, capture, analysis, relocation and replay ordering."
    )
    owners = [item[2] for item in mock.calls]
    assert len(set(owners)) == len(owners) and all(owner.parent == tmp_path / "observations"
        for owner in owners), "Every operation has a fresh independent observation owner"
    capture, analyze, replay = [mock.calls[index][1] for index in (1, 3, 7)]
    assert capture["approve_safe_content_response_capture"] is True and capture[
        "retain_response"] is True and analyze["approve_passive_header_check"] is True, (
        "Capture approval, byte retention and analysis approval must remain separate explicit "
        "booleans."
    )
    assert analyze["original_receipt_id"] == mock.summary["original_receipt_id"], (
        "Analysis must use the actual capture receipt rather than a synthesized source reference."
    )
    assert analyze["expected_model_revision"] == 3 and analyze[
        "expected_workspace_revision"] == 2, (
        "Analysis must receive the original acquired model and workspace CAS bases."
    )
    assert replay == {"workspace": str(tmp_path / "relocated"), "kind": "header",
        "reference": mock.identities["assessment_reference"]}, (
        "Historical replay must select the relocated workspace and exact original assessment "
        "reference."
    )


@pytest.mark.parametrize("scenario", pipeline.SCENARIOS[1:])
def test_MockedAuthorityRefusalLeavesOriginalsUnchangedAndStopsBeforeRelocation(
    tmp_path, monkeypatch, scenario,
):
    """Each independently declared authority failure requires no assessment, Save or replay."""

    plan = pipeline.Plan(Selection(tmp_path, scenario=scenario))
    mock = MockSequence(plan, monkeypatch)
    assert pipeline.Run(plan, mock.Handoff, enabled=True) == {
        "state": "checked-authority-refusal", "expected_findings": 0}, (
        "The denied inert pipeline must return only an authority refusal and zero expected "
        "Findings."
    )
    assert mock.oracles == ["capture", "parts"] and len(mock.calls) == 5, (
        "Denied analysis must stop after source oracles and the five required product handoffs."
    )
    selected = mock.calls[3][1]
    assert selected["authority_scenario"] == scenario and selected[
        "approve_passive_header_check"] is (scenario != "approval-denied"), (
        "The authority fixture must preserve its selected scenario and independent analysis "
        "approval."
    )
    assert selected["policy"] == mock.policies["analysis-denied" if scenario == (
        "policy-denied") else "analysis"]["path"], "A denied fixture is an actual typed policy"


@pytest.mark.parametrize("mutation", [None, "zero-basis", "bool-basis", "wrong-state",
    "wrong-failure", "condition", "assessment", "finding", "save", "changed-state",
    "model-ack", "workspace-ack", "changed-revision", "actor-read", "bool-actor-read"])
def test_MockedStaleModelRevisionPreservesActualBasisAndStopsBeforeAdmission(
    tmp_path, monkeypatch, mutation,
):
    """Only an observed positive basis may select one stale revision without a retry or Save."""

    plan = pipeline.Plan(Selection(tmp_path, scenario=pipeline.REVISION_SCENARIO))
    mock = MockSequence(plan, monkeypatch)
    mock.analysis.update(owner_reads=0, authority_scenario="positive")
    summary = mock.analysis["summary"]
    summary.update(failure="revision-conflict", model_commit="not-attempted",
        workspace_commit="not-attempted", model_revision=3, workspace_revision=2)

    if mutation in ("zero-basis", "bool-basis"):
        mock.acquired["model"]["revision"] = 0 if mutation == "zero-basis" else True

    elif mutation == "wrong-state":
        summary["state"] = "denied"

    elif mutation == "wrong-failure":
        summary["failure"] = "authorization"

    elif mutation in ("condition", "assessment", "finding"):
        field = "condition_observed" if mutation == "condition" else mutation + "_reference"
        summary[field] = False if mutation == "condition" else "unexpected:interpretation"

    elif mutation == "save":
        mock.analysis["guard"]["saves"] = [{"owner": "model"}]

    elif mutation == "changed-state":
        mock.interpreted["model"]["revision"] += 1

    elif mutation in ("model-ack", "workspace-ack"):
        summary[mutation.removesuffix("-ack") + "_commit"] = "acknowledged"

    elif mutation == "changed-revision":
        summary["model_revision"] = 2

    elif mutation in ("actor-read", "bool-actor-read"):
        mock.analysis["owner_reads"] = 1 if mutation == "actor-read" else False

    if mutation is not None:
        with pytest.raises(AssertionError):
            pipeline.Run(plan, mock.Handoff, enabled=True)

        assert len(mock.calls) == (3 if mutation in ("zero-basis", "bool-basis") else 5), (
            "A failed original-basis assertion must stop without retry or later stages")

        return

    assert pipeline.Run(plan, mock.Handoff, enabled=True) == {
        "state": "checked-revision-conflict", "expected_findings": 0}, (
            "Only the explicit stale-basis failure may satisfy this mock sequence")
    assert plan["expected_state"] == "failed" and plan["expected_findings"] == 0, (
        "The independent plan must expect conflict without an interpretation")
    assert mock.oracles == ["capture", "parts"] and len(mock.calls) == 5, (
        "Valid acquired originals must precede one analysis attempt and one unchanged inspection")
    selected = mock.calls[3][1]
    assert selected["expected_model_revision"] == mock.acquired["model"]["revision"] - 1, (
        "The explicit CAS input must be exactly the acquired model revision minus one")
    assert selected["expected_workspace_revision"] == mock.acquired["workspace"]["revision"], (
        "The independent workspace CAS input must retain its actual acquired revision")
    assert selected["authority_scenario"] == "positive" and selected[
        "approve_passive_header_check"] is True and selected["policy"] == mock.policies[
            "analysis"]["path"], "Valid selected authority inputs are never claimed to be checked"


@pytest.mark.parametrize("mutation", ["consent", "offline-call", "missing-tripwire",
    "lost-probe", "wrong-finding", "old-root-remains", "relocation-claim",
    "relocation-repairs", "replay-write"])
def test_MockedFailuresStopWithoutRetryOrLaterStages(tmp_path, monkeypatch, mutation):
    """Wrong authority, swallowed offline attempts and incomplete relocation cannot advance."""

    plan = pipeline.Plan(Selection(tmp_path))
    mock = MockSequence(plan, monkeypatch)
    maximum_calls = 5

    if mutation == "consent":
        mock.scope["authorization"]["record_reference"] = "consent:historical"
        maximum_calls = 1

    elif mutation == "offline-call":
        mock.analysis["guard"]["calls"]["socket.audit"] = 1

    elif mutation == "missing-tripwire":
        del mock.analysis["guard"]["calls"]["LocalEvidenceStore.Put"]

    elif mutation == "lost-probe":
        mock.analysis["guard"]["audit_probe_seen"] = False

    elif mutation == "wrong-finding":
        mock.identities["finding_reference"] = None

    elif mutation == "old-root-remains":
        mock.relocated["original_root_absent"] = False
        maximum_calls = 6

    elif mutation == "relocation-claim":
        def Claimed(operation, selection, observations):
            """Preserve an old empty directory despite mocked relocation success metadata."""

            value = mock.Handoff(operation, selection, observations)

            if operation == "relocate":
                Path(selection["workspace"]).mkdir()

            return value

        maximum_calls = 6

    elif mutation == "relocation-repairs":
        mock.interpreted["originals"]["unexpected"] = "repair"

        def Relocated(operation, selection, observations):
            """Return changed relocated documents from an explicitly mocked reader."""

            value = mock.Handoff(operation, selection, observations)

            if len(mock.calls) == 7:
                return {"state": mock.acquired}

            return value

        maximum_calls = 7

    else:
        mock.replay["guard"]["saves"].append({"mock_forbidden_write": True})
        maximum_calls = 8

    selected_handoff = mock.Handoff

    if mutation == "relocation-repairs":
        selected_handoff = Relocated

    elif mutation == "relocation-claim":
        selected_handoff = Claimed

    with pytest.raises(AssertionError):
        pipeline.Run(plan, selected_handoff, enabled=True)

    assert len(mock.calls) <= maximum_calls, "No failing operation may trigger a retry"


@pytest.mark.parametrize("enabled", [False, None, 1, "yes"])
def test_SequenceDefaultDenialPrecedesPlanReadsAndHandoffs(enabled):
    """A truthy flag cannot opt into acquisition, analysis or even fresh fixture setup."""

    with pytest.raises(PermissionError):
        pipeline.Run(None, None, enabled=enabled)


@pytest.mark.parametrize("mutation", ["extra", "identity", "relative", "overlap", "external",
    "query", "case", "scenario", "naive", "backward", "long-window", "identity-separator"])
def test_PlanRejectsAmbiguousTargetsIdentitiesAndConsentWindowsBeforeEffects(tmp_path, mutation):
    """Malformed declarations never rely on product-returned truth or implicit clock renewal."""

    selection = Selection(tmp_path)

    if mutation == "extra":
        selection["implicit_approval"] = "yes"

    else:
        key, value = {"identity": ("fixture_id", "old"),
            "identity-separator": ("fixture_id", "fresh--invalid"),
            "relative": ("workspace", "relative/product"),
            "overlap": ("observations", str(tmp_path / "original" / "observations")),
            "external": ("url", "http://example.com:15432/research/content"),
            "query": ("url", selection["url"] + "?case=missing"), "case": ("case", "catalog"),
            "scenario": ("scenario", "auto"), "naive": (
                "consent_valid_from", "2030-01-01T00:00:00"),
            "backward": ("consent_valid_until", "2029-12-31T23:59:59+00:00"),
            "long-window": ("consent_valid_until", "2030-01-01T01:00:00+00:00")}[mutation]
        selection[key] = value

    with pytest.raises(ValueError):
        pipeline.Plan(selection)


def test_ChangedFrozenExpectationRefusesBeforeAnyHandoff(tmp_path):
    """The selected source truth cannot be changed after the pipeline plan was frozen."""

    plan = pipeline.Plan(Selection(tmp_path))
    plan["expected_findings"] = 0

    with pytest.raises(ValueError):
        pipeline.Run(plan, None, enabled=True)


@pytest.mark.parametrize("existing", ["workspace", "relocated_workspace"])
def test_ExistingProductRootsRefuseBeforeFreshSetup(tmp_path, existing):
    """An existing owner cannot supply historical state or receive an implicit replacement."""

    selection = Selection(tmp_path)
    Path(selection[existing]).mkdir()

    with pytest.raises(ValueError):
        pipeline.Run(pipeline.Plan(selection), None, enabled=True)


def test_CanonicalObservationAliasRefusesBeforeFreshSetup(tmp_path):
    """A lexical sibling alias cannot let observations enter the original product owner."""

    selection = Selection(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(tmp_path, target_is_directory=True)
    selection["observations"] = str(alias / "original" / "observations")

    with pytest.raises(ValueError):
        pipeline.Run(pipeline.Plan(selection), None, enabled=True)


@pytest.mark.parametrize("enabled", [False, None, 1, "yes"])
def test_InstalledRuntimeDefaultDenialPrecedesAnyPrerequisiteOrTransport(enabled):
    """No build identity, target, process or current-time input is consulted by default."""

    with pytest.raises(PermissionError):
        pipeline.RunInstalled(None, None, None, fixture_id=None, case=None, scenario=None,
            enabled=enabled)


@pytest.mark.parametrize("mutation", [None, "helper-hash", "returncode", "capture-original",
    "guard-original", "guard-failure"])
def test_MockedInstalledTransportRetainsOriginalAdaptersAndStopsOnMismatchedFacts(
    tmp_path, monkeypatch, mutation,
):
    """Fake process/source owners exercise transport wiring only; no process, socket or SDK runs."""

    from fuzzy1337.executors import owned_process
    from tests import native_crawl_acceptance_helpers as primitives
    from tests.contract import owned_content_response_product_runner as oracles
    from tests.contract import owned_content_response_sdk_entrypoint as entrypoint
    from tests.contract import owned_content_response_target as targets
    from tests.native_crawl_acceptance_helpers import CanonicalNative, NativeCaseEvidence

    installed = SimpleNamespace(python=Path("/mock-only/environment/bin/python"),
        installation={"identity": {"mock_installation": True}}, commit="1" * 40, tree="2" * 40)
    evidence = NativeCaseEvidence(tmp_path / "originals", tmp_path / "retained")
    calls = []
    origins = []
    monkeypatch.setattr(owned_process, "RequireLinuxOwnership", lambda: None)
    monkeypatch.setattr(primitives, "NativeInstallation", lambda python: installed.installation)

    def Installation(identity, imported, **selected):
        """Observe exact original installed envelope and selected immutable source identities."""

        assert identity is installed.installation["identity"], (
            "Installation validation must receive the exact original installation identity object."
        )
        assert imported["python"] == str(installed.python) and selected == {
            "commit": installed.commit, "tree": installed.tree}, (
            "Installation validation must retain the actual selected interpreter, commit and "
            "source tree."
        )

    def Terminal(process, stdout, stderr, *, argv):
        """Observe the selected fixed isolated command without authenticating fake terminal data."""

        assert argv[1:3] == ("-I", "-B") and argv[-1] == "--execute", (
            "Each installed handoff must use isolated no-bytecode execution with explicit execute "
            "selection."
        )

    monkeypatch.setattr(oracles, "AssertContentInstallation", Installation)
    monkeypatch.setattr(oracles, "AssertOriginalTerminalProcess", Terminal)

    def Process(owner, label, argv, **options):
        """Write marked mocked process facts in the existing owner layout; never launch argv."""

        calls.append(label)
        prefix = owner.NextProcess(label)
        owner.Json(prefix + "/invocation.json", {"schema_version": 1, "argv": list(argv),
            "cwd": str(options["cwd"]), "timeout_seconds": options["timeout"],
            "stdin": "closed-devnull", "state": "not-launched", "returncode": None,
            "terminal_return_observed": False, "installation": options.get("installation")})
        code = 0

        if label == "pipeline-source-status":
            raw = b""

        elif label == "pipeline-checkpoint":
            raw = (installed.commit + "\n" + installed.tree + "\n").encode()

        else:
            operation = argv[4]
            envelope = json.loads(Path(argv[5]).read_bytes())
            observations = Path(envelope["observations"])
            sources, _ = entrypoint.Sources()
            summary = {"mock_summary": operation}
            document = {"operation": operation, "installed_identity": {
                "python": str(installed.python), "prefix": str(installed.python.parents[1])},
                "summary": summary, "consumer_sources": sources}

            if operation in ("fresh-setup", "inspect"):
                extra, _ = entrypoint.ControlSources()
                sources.update(extra)

            if operation == "inspect":
                document["summary"] = {"original_inspection": summary}

            if operation.endswith("-offline"):
                extra, _ = entrypoint.GuardSource()
                sources.update(extra)
                actual = {"guard": {"mock_guard": True}, "owner_reads": 0,
                    "authority_scenario": None}
                document.update(actual)
                observations.mkdir(parents=True)

                if mutation == "guard-original":
                    actual = {**actual, "owner_reads": 1}

                (observations / "offline-guard.json").write_bytes(CanonicalNative(actual))

            if operation == "capture":
                observations.mkdir(parents=True)
                original = {"summary": summary, "exception_type": None,
                    "store_saves": [], "executions": []}

                if mutation == "capture-original":
                    original["summary"] = {"foreign_mock_summary": True}

                (observations / "capture.json").write_bytes(CanonicalNative(original))

            if mutation == "helper-hash":
                sources["owned_content_response_sdk_entrypoint.py"]["sha256"] = "0" * 64

            if mutation == "returncode" or mutation == "guard-failure" and operation.endswith(
                "-offline"):
                code = 1

            raw = CanonicalNative(document)

        owner.Json(prefix + "/process.json", {"cwd": str(options["cwd"]),
            "timeout_seconds": options["timeout"], "installation": options.get("installation"),
            "mock_terminal_only": True})
        owner.Write(prefix + "/stdout.bin", raw)
        owner.Write(prefix + "/stderr.bin", b"")

        return CompletedProcess(argv, code, raw, b"")

    monkeypatch.setattr(primitives, "NativeProcess", Process)

    @contextmanager
    def Target(owner, *, address, case):
        """Yield a fake source identity and retain explicit mock final facts without a listener."""

        assert address == "127.0.0.1", (
            "The owned source fixture must bind only the independently selected IPv4 loopback "
            "address."
        )
        origin = "http://127.0.0.1:" + str(15432 + len(origins))
        origins.append(origin)

        try:
            yield SimpleNamespace(graph=SimpleNamespace(origin=origin,
                Url=lambda path: origin + path))

        finally:
            owner.Json("content-source-final.json", {"mock_origin": origin})

    def Sources(case, url, main, sentinel, *, sentinel_origin):
        """Observe retained fake owner records without authenticating any real source contacts."""

        assert case == "missing" and url == origins[0] + "/research/content", (
            "Source delivery validation must retain the exact missing-header case and selected "
            "concrete URL."
        )
        assert main == {"mock_origin": origins[0]} and sentinel == {"mock_origin": origins[1]}, (
            "Source delivery validation must receive both independently retained original owner "
            "facts."
        )
        assert sentinel_origin == origins[1], (
            "Source delivery validation must retain the distinct independently selected sentinel "
            "origin."
        )

        return "mock-original-delivery"

    monkeypatch.setattr(targets, "OwnedContentResponseTarget", Target)
    monkeypatch.setattr(oracles, "AssertContentSourceFacts", Sources)

    def Run(plan, handoff, *, enabled):
        """Exercise only transport conversions; genuine pipeline/oracle behavior is not run."""

        selected = plan["selection"]
        root = Path(selected["workspace"])
        observations = Path(selected["observations"])
        assert enabled is True and plan["expected_findings"] == 1, (
            "The joined pipeline must be explicitly enabled with the fixed expected positive "
            "Finding count."
        )
        assert handoff("fresh-setup", {"workspace": str(root)}, observations / "setup") == {
            "mock_summary": "fresh-setup"}, (
            "Fresh setup handoff must return the original controlled setup summary."
        )
        root.mkdir()
        assert handoff("inspect", {"workspace": str(root)}, observations / "inspect") == {
            "state": {"mock_summary": "inspect"}}, (
            "Inspect handoff must return the original controlled canonical state."
        )
        assert handoff("capture", {"workspace": str(root)}, observations / "capture")[
            "summary"] == {"mock_summary": "capture"}, (
            "Capture handoff must return its actual controlled capture summary."
        )
        assert handoff("analyze-offline", {"workspace": str(root)}, observations / "analyze")[
            "guard"] == {"mock_guard": True}, (
            "Offline analysis handoff must retain its original guard observations."
        )
        moved = handoff("relocate", {"workspace": str(root), "relocated_workspace": selected[
            "relocated_workspace"]}, observations / "relocate")
        assert moved == {"original_root_absent": True, "relocated_root_present": True}, (
            "Physical relocation must remove the original root and retain the relocated root."
        )
        assert handoff("replay-offline", {"workspace": selected["relocated_workspace"]},
            observations / "replay")["guard"] == {"mock_guard": True}, (
            "Offline replay handoff must preserve the original guard observations after "
            "relocation."
        )

        return {"state": "mock-sequence-only", "expected_findings": 1}

    monkeypatch.setattr(pipeline, "Run", Run)

    if mutation is not None:
        with pytest.raises(AssertionError):
            pipeline.RunInstalled(installed, tmp_path / "runtime", evidence,
                fixture_id="fresh-transport-0001", case="missing", scenario="positive",
                enabled=True)

        assert (evidence.retained / "main-source-final.json").exists(), (
            "A failed pipeline must retain the original main-source final facts for diagnosis."
        )
        assert not (evidence.retained / "pipeline-result.json").exists(), (
            "A failed pipeline must not publish a successful pipeline result artifact."
        )

        if mutation == "guard-failure":
            assert (evidence.retained / "sdk-analyze-offline-guard.json").is_file(), (
                "Original guard observations must survive a nonzero consumer terminal")

        return

    result = pipeline.RunInstalled(installed, tmp_path / "runtime", evidence,
        fixture_id="fresh-transport-0001", case="missing", scenario="positive", enabled=True)
    assert result["source_delivery"] == "mock-original-delivery", (
        "The final result must preserve the independently observed original source-delivery "
        "classification."
    )
    assert calls == ["pipeline-source-status", "pipeline-checkpoint", "sdk-fresh-setup",
        "sdk-inspect", "sdk-capture", "sdk-analyze-offline", "sdk-replay-offline"], (
        "Installed pipeline process records must retain their original source and product-stage "
        "ordering."
    )
    assert (evidence.retained / "physical-relocation.json").exists(), (
        "The installed pipeline must retain its original physical-relocation receipt."
    )


def test_InstalledPrerequisiteFailureStopsBeforeAnyProcessOrTarget(tmp_path, monkeypatch):
    """An unavailable advertised ownership prerequisite is terminal, with no fallback launch."""

    from fuzzy1337.executors import owned_process
    from fuzzy1337.executors.local import LocalExecutionError

    def Unavailable():
        """Expose a deterministic prerequisite failure without probing any real OS feature."""

        raise LocalExecutionError("mock unavailable Linux ownership")

    monkeypatch.setattr(owned_process, "RequireLinuxOwnership", Unavailable)

    with pytest.raises(LocalExecutionError, match="mock unavailable Linux ownership"):
        pipeline.RunInstalled(None, tmp_path / "runtime", None,
            fixture_id="fresh-unavailable-0001", case="missing", scenario="positive", enabled=True)

    assert not (tmp_path / "runtime").exists(), "No fixture or process owner was created"
