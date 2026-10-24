# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Mocked fixed entrypoint contracts; no actual installed imports, SDK, workers or targets."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
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
