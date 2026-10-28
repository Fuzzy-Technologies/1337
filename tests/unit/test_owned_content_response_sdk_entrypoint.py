# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Mocked fixed entrypoint contracts; no actual installed imports, SDK, workers or targets."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from tests.contract import owned_content_response_sdk_entrypoint as entrypoint


@pytest.fixture(scope="module")
def entrypoint_runner():
    """Preinitialize a portable loop before unit guards; SDK calls remain explicit test doubles."""

    with asyncio.Runner() as runner:
        runner.get_loop()
        yield runner


@pytest.mark.parametrize("raw", [b'{"selection":{},"selection":{},"observations":"/owned"}',
    b'{"selection":{"revision":NaN},"observations":"/owned"}',
    b'{"selection":{"revision":1e999},"observations":"/owned"}',
    b'{"selection":{"revision":1.5},"observations":"/owned"}', b"x" * 8193])
def test_BoundedInputRefusesDuplicateNonfiniteAndOversizedOriginals(raw, tmp_path):
    """Invalid input is rejected before any real installed import or SDK work."""

    path = tmp_path / "input.json"
    path.write_bytes(raw)

    with pytest.raises(ValueError):
        entrypoint.ReadInput(path)


@pytest.mark.parametrize("mutation", [None, "outside-prefix", "wrong-suffix", "mixed-root"])
def test_IdentityRequiresNineActualSourceHashesInsideOneSelectedEnvironment(
    mutation, tmp_path, monkeypatch,
):
    """Fake imported modules expose source/path drift without importing any product runtime."""

    prefix = tmp_path / "environment"
    paths = {}
    digests = {}

    for name in entrypoint.SOURCE_MODULES:
        root = prefix / "lib/python3.12/site-packages/fuzzy1337"

        if name == entrypoint.SOURCE_MODULES[0]:
            if mutation == "outside-prefix":
                root = tmp_path / "other/site-packages/fuzzy1337"

            elif mutation == "wrong-suffix":
                root = prefix / "src/fuzzy1337"

            elif mutation == "mixed-root":
                root = prefix / "other/site-packages/fuzzy1337"

        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = ("# mocked module " + name).encode()
        path.write_bytes(raw)
        paths["fuzzy1337." + name[:-3].replace("/", ".")] = path
        digests[name] = hashlib.sha256(raw).hexdigest()

    monkeypatch.setattr(entrypoint.sys, "prefix", str(prefix))
    monkeypatch.setattr(entrypoint.sys, "base_prefix", str(tmp_path / "base"))
    monkeypatch.setattr(entrypoint.importlib.metadata, "version", lambda _name: "0.0.mock")
    monkeypatch.setattr(entrypoint.importlib, "import_module",
        lambda name: SimpleNamespace(__file__=str(paths[name])))

    if mutation is not None:
        with pytest.raises(ValueError):
            entrypoint.Identity()

        return

    observed = entrypoint.Identity()
    assert {name: value["sha256"] for name, value in observed["installed_sources"].items()} == (
        digests), "Each exact fake module file contributes its independently recomputed hash"


@pytest.mark.parametrize("operation", ["identity", "capture", "analyze", "replay"])
def test_FixedDispatchRetainsSelectionResultAndSeparateHelperIdentity(
    operation, tmp_path, monkeypatch, entrypoint_runner,
):
    """Only explicit operation names dispatch to mocked consumer handoffs, without fallback."""

    calls = []
    summary = {"state": "partial", "model_commit": "unconfirmed"}
    selection = {"mock_explicit_selection": True}
    config = tmp_path / "input.json"
    observations = tmp_path / "fresh-observations"
    config.write_text(json.dumps({"selection": selection, "observations": str(observations)}))
    output = io.BytesIO()
    monkeypatch.setattr(entrypoint.sys, "flags", SimpleNamespace(isolated=1, dont_write_bytecode=1))
    monkeypatch.setattr(entrypoint.sys, "stdout", SimpleNamespace(buffer=output))
    monkeypatch.setattr(entrypoint, "Identity", lambda: {"mock_installed_identity": True})
    monkeypatch.setattr(entrypoint, "Sources", lambda: ({"mock_helper_sha256": "a" * 64}, b"mock"))
    monkeypatch.setattr(entrypoint.asyncio, "run", entrypoint_runner.run)

    def Call(kind, selected, owner, *, enabled):
        """Observe exact selection and opt-in while preserving the mocked actual summary."""

        calls.append(kind)
        assert selected == selection and owner == observations and enabled is True, (
            "The fixed entrypoint must not replace selection, observation owner or approvals")

        return summary

    async def Capture(selected, owner, **options):
        """Delegate only to the explicit mocked capture handoff, never a real SDK or worker."""

        return Call("capture", selected, owner, **options)

    consumer = SimpleNamespace(Capture=Capture,
        Analyze=lambda *args, **kwargs: Call("analyze", *args, **kwargs),
        Replay=lambda *args, **kwargs: Call("replay", *args, **kwargs))
    monkeypatch.setattr(entrypoint, "LoadConsumer", lambda _raw: consumer)
    argv = ["identity"] if operation == "identity" else [operation, str(config), "--execute"]
    assert entrypoint.Main(argv) == 0, "A selected mock result remains successful dispatch"
    observed = json.loads(output.getvalue())
    assert observed["consumer_sources"] == {"mock_helper_sha256": "a" * 64}, (
        "Helper identity is separate from observed installed wheel-module identity")
    assert calls == ([] if operation == "identity" else [operation]), "No implicit dispatch follows"


def test_FixedSourceLoaderExecutesOnlyTheExactObservedSiblingBytes(tmp_path, monkeypatch):
    """Changing the sibling after observation cannot substitute a second source read."""

    current = tmp_path / "owned_content_response_sdk_entrypoint.py"
    current.write_bytes(b"# mocked entrypoint")
    sibling = current.with_name("owned_content_response_sdk_consumer.py")
    original = b"observed_source = 'original'\n"
    sibling.write_bytes(original)
    monkeypatch.setattr(entrypoint, "__file__", str(current))
    identities, raw = entrypoint.Sources()
    sibling.write_bytes(b"raise AssertionError('replacement source must not execute')")
    loaded = entrypoint.LoadConsumer(raw)
    assert loaded.observed_source == "original", "Execute the original observed bytes only"
    assert identities[sibling.name]["sha256"] == hashlib.sha256(original).hexdigest(), (
        "The reported helper digest must describe the same bytes that actually execute")


@pytest.mark.parametrize("flags,argv", [
    ((0, 1), ["identity"]), ((1, 0), ["identity"]),
    ((1, 1), ["capture", "input.json"]), ((1, 1), ["arbitrary", "input.json", "--execute"])])
def test_IsolationAndFixedGrammarRefuseBeforeInputOrInstalledImports(flags, argv, monkeypatch):
    """Missing isolation or explicit fixed dispatch cannot reach any input or product import."""

    monkeypatch.setattr(entrypoint.sys, "flags", SimpleNamespace(isolated=flags[0],
        dont_write_bytecode=flags[1]))

    def Unexpected(*args):
        """Fail if early denial performs an input read or installed product observation."""

        raise AssertionError("Invalid entrypoint invocation must refuse before effects")

    monkeypatch.setattr(entrypoint, "ReadInput", Unexpected)
    monkeypatch.setattr(entrypoint, "Identity", Unexpected)

    with pytest.raises(ValueError):
        entrypoint.Main(argv)


@pytest.mark.parametrize("operation", ["setup", "fresh-setup", "inspect"])
def test_FixedSetupInspectionHookReportsAllControlSourcesWithoutCapture(
    operation, tmp_path, monkeypatch,
):
    """Fixed operations reach only their controlled handoff and preserve typed fixture results."""

    config = tmp_path / "input.json"
    selection = {"workspace": str(tmp_path / "workspace")}
    config.write_text(json.dumps({"selection": selection,
        "observations": str(tmp_path / "fresh-observations")}))
    output = io.BytesIO()
    calls = []
    monkeypatch.setattr(entrypoint.sys, "flags", SimpleNamespace(isolated=1, dont_write_bytecode=1))
    monkeypatch.setattr(entrypoint.sys, "stdout", SimpleNamespace(buffer=output))
    monkeypatch.setattr(entrypoint, "Identity", lambda: {"mock_installed_nine": True})
    monkeypatch.setattr(entrypoint, "Sources", lambda: ({"mock_consumer": "a" * 64}, b"unused"))
    monkeypatch.setattr(entrypoint, "ControlSources", lambda: ({"mock_fixed_setup_seed_controls":
        "b" * 64}, b"exact-controls"))

    def Dispatch(selected_operation, selected, observations, *, enabled):
        """Observe one mocked fixed control; never construct SDK stores or policy authorities."""

        calls.append((selected_operation, selected, observations, enabled))

        return {"mock_original_state": "unmodified"}

    def Load(raw):
        """Only the exact observed fixed controls bytes are selected for execution."""

        assert raw == b"exact-controls", "No mutable import-path source may replace observed bytes"

        return SimpleNamespace(Dispatch=Dispatch)

    def Unexpected(_raw):
        """Detect any accidental capture/analysis/replay consumer enrollment by setup or inspect."""

        raise AssertionError("Setup/inspection must not load acquisition consumer")

    monkeypatch.setattr(entrypoint, "LoadControls", Load)
    monkeypatch.setattr(entrypoint, "LoadConsumer", Unexpected)
    assert entrypoint.Main([operation, str(config), "--execute"]) == 0
    assert calls == [(operation, selection, tmp_path / "fresh-observations", True)], (
        "Only the explicit selected control executes")
    observed = json.loads(output.getvalue())
    assert observed["consumer_sources"]["mock_fixed_setup_seed_controls"] == "b" * 64, (
        "Caller independently reconciles control/setup/seed source identities")


@pytest.mark.parametrize("scenario", [
    "positive", "approval-denied", "policy-denied", "owner-drift"])
@pytest.mark.parametrize("failure", [False, True])
def test_OfflineAnalysisUsesGuardAndTrustedActorWithoutChangingConsumerSelection(
    tmp_path, scenario, failure,
):
    """Mock guard observations survive success and exception; no real SDK/guard/store runs."""

    selected = {"workspace": str(tmp_path / "workspace"), "owner_reference": "actor:fresh-only",
        "policy": "/mock-only/denied.json" if scenario == "policy-denied" else "/mock-only/passive",
        "approve_passive_header_check": scenario != "approval-denied",
        "authority_scenario": scenario}
    expected = {key: value for key, value in selected.items() if key != "authority_scenario"}
    record = {"mock_original_guard": True}
    active = []
    actors = []
    summary = {"state": "mock-actual-result"}
    observations = tmp_path / "observations"

    @contextmanager
    def OfflineGuard(*, historical, enabled):
        """Yield original mock telemetry only for the explicitly selected analysis guard."""

        assert historical is False and enabled is True
        active.append(True)

        try:
            yield record

        finally:
            active.pop()

    def Analyze(selection, owner, *, enabled, current_owner_provider):
        """Read actual supplied actor callbacks while the mock guard is active; never call SDK."""

        assert active == [True] and selection == expected and enabled is True
        assert owner == observations / "consumer", "Consumer owns a distinct fresh child attempt"
        actors.extend((current_owner_provider(), current_owner_provider()))

        if failure:
            raise RuntimeError("original mocked analysis failure")

        return summary

    consumer = SimpleNamespace(Analyze=Analyze, MAX_OBSERVATION_BYTES=1024 * 1024)
    guard = SimpleNamespace(OfflineGuard=OfflineGuard, DetachedGuard=lambda actual: actual)

    if failure:
        with pytest.raises(RuntimeError, match="original mocked analysis failure"):
            entrypoint.Offline("analyze-offline", selected, observations, consumer, guard)

    else:
        result = entrypoint.Offline("analyze-offline", selected, observations, consumer, guard)
        assert result["summary"] is summary and result["guard"] is record

    assert actors == [selected["owner_reference"], "actor:explicit-fixture-owner-drift" if (
        scenario == "owner-drift") else selected["owner_reference"]]
    retained = json.loads((observations / "offline-guard.json").read_bytes())
    assert retained == {"guard": record, "owner_reads": 2, "authority_scenario": scenario}
    assert active == [] and selected["authority_scenario"] == scenario, "No caller input mutation"


def test_OfflineReplayHasHistoricalGuardAndNoCurrentActorReader(tmp_path):
    """Historical transport passes only the original selected receipt/assessment and workspace."""

    selection = {"workspace": str(tmp_path / "workspace"), "kind": "header",
        "reference": "assessment:mock-only"}
    record = {"mock_replay_guard": True}
    calls = []

    @contextmanager
    def OfflineGuard(**options):
        """Observe replay-only guard selection without invoking any real tripwire implementation."""

        assert options == {"historical": True, "enabled": True}

        yield record

    def Replay(selected, owner, *, enabled):
        """Accept no actor or policy callback on this mocked historical handoff."""

        calls.append((selected, owner, enabled))

        return {"state": "mock-historical-result"}

    observations = tmp_path / "observations"
    result = entrypoint.Offline("replay-offline", selection, observations,
        SimpleNamespace(Replay=Replay, MAX_OBSERVATION_BYTES=1024 * 1024),
        SimpleNamespace(OfflineGuard=OfflineGuard, DetachedGuard=lambda actual: actual))
    assert calls == [(selection, observations / "consumer", True)]
    assert result["owner_reads"] == 0 and result["authority_scenario"] is None


def test_OfflineGuardLoaderExecutesTheSameBoundedObservedSibling(tmp_path, monkeypatch):
    """A changed sibling after observation cannot replace the exact reviewed guard bytes."""

    current = tmp_path / "owned_content_response_sdk_entrypoint.py"
    current.write_bytes(b"# mock entrypoint")
    sibling = current.with_name("owned_content_response_sdk_offline_guard.py")
    raw = b"observed_guard = 'original mock guard'\n"
    sibling.write_bytes(raw)
    monkeypatch.setattr(entrypoint, "__file__", str(current))
    records, observed = entrypoint.GuardSource()
    sibling.write_bytes(b"raise AssertionError('replacement guard')")
    loaded = entrypoint.LoadGuard(observed)
    assert loaded.observed_guard == "original mock guard"
    assert records[sibling.name]["sha256"] == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("operation", ["analyze-offline", "replay-offline"])
def test_FixedOfflineDispatchRetainsGuardSourcesAndActualDetachedValues(
    tmp_path, monkeypatch, operation,
):
    """Main selects only the reviewed offline wrapper and preserves its original observations."""

    selection = {"mock_explicit_selection": True}
    observations = tmp_path / "observations"
    config = tmp_path / "input.json"
    config.write_text(json.dumps({"selection": selection, "observations": str(observations)}))
    output = io.BytesIO()
    consumer = SimpleNamespace(mock_fixed_consumer=True)
    guard = SimpleNamespace(mock_fixed_guard=True)
    actual = {"summary": {"mock_original_summary": True}, "guard": {"mock_original_saves": []},
        "owner_reads": 2, "authority_scenario": "mock-fixture"}
    monkeypatch.setattr(entrypoint.sys, "flags", SimpleNamespace(isolated=1, dont_write_bytecode=1))
    monkeypatch.setattr(entrypoint.sys, "stdout", SimpleNamespace(buffer=output))
    monkeypatch.setattr(entrypoint, "Identity", lambda: {"mock_installed_identity": True})
    monkeypatch.setattr(entrypoint, "Sources", lambda: (
        {"mock_consumer_source": "a" * 64}, b"mock"))
    monkeypatch.setattr(entrypoint, "LoadConsumer", lambda raw: consumer)
    monkeypatch.setattr(entrypoint, "GuardSource", lambda: (
        {"mock_guard_source": "b" * 64}, b"guard"))
    monkeypatch.setattr(entrypoint, "LoadGuard", lambda raw: guard)

    def Offline(selected_operation, selected, owner, original_consumer, original_guard):
        """Observe fixed source/selection wiring without constructing SDK or guard contexts."""

        assert (selected_operation, selected, owner) == (operation, selection, observations)
        assert original_consumer is consumer and original_guard is guard

        return dict(actual)

    monkeypatch.setattr(entrypoint, "Offline", Offline)
    assert entrypoint.Main([operation, str(config), "--execute"]) == 0
    observed = json.loads(output.getvalue())
    assert all(observed[key] == value for key, value in actual.items())
    assert observed["consumer_sources"] == {"mock_consumer_source": "a" * 64,
        "mock_guard_source": "b" * 64}, "Guard bytes must bind independently of wheel imports"
