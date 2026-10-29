# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure mocked launcher contracts; no process, installed runtime or source fixture execution."""

from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager
from types import SimpleNamespace
from zipfile import ZipFile

import pytest

from tests.contract import owned_content_response_worker_launcher as launcher

COMMIT, TREE = "1" * 40, "2" * 40


class MockEvidence:
    """Write only synthetic test-owned records, with no source or runtime side effects."""

    def __init__(self, local, retained):
        """Keep explicit separate artifact directories and a bounded fake process sequence."""

        self.local, self.retained, self.sequence = local, retained, 0

    def Write(self, name, raw):
        """Retain mocked artifact bytes in both explicitly owned test directories."""

        for root in (self.local, self.retained):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    def Json(self, name, value):
        """Encode only synthetic record data; never claim it came from a real source."""

        self.Write(name, launcher.CanonicalNative(value))


@pytest.mark.parametrize("enabled", [False, None, 0, 1, "yes"])
def test_LauncherRequiresExactOptInBeforeAnyOwnerOrRuntimeAccess(enabled, tmp_path):
    """Truthiness cannot opt into building, fixture construction or worker execution."""

    with pytest.raises(PermissionError):
        launcher.Build(None, None, None, commit=COMMIT, tree=TREE, enabled=enabled)

    with pytest.raises(PermissionError):
        launcher.Run(None, "missing", "127.0.0.1", None, enabled=enabled)

    assert list(tmp_path.iterdir()) == [], "Default denial performs no filesystem work"


@pytest.mark.parametrize("mutation", [None, "dirty-before", "dirty-after", "source-drift",
    "wheel-drift", "foreign-import"])
def test_OfflineBuildCommandsAndExactSourceWheelProbeBindingUseOnlyDoubles(
    mutation, monkeypatch, tmp_path,
):
    """Mocked commands prove offline ordering/binding without a real build, venv or import probe."""

    repository = tmp_path / "repository"
    repository.mkdir()
    modules = {}

    for name in launcher.SOURCE_MODULES:
        path = repository / "src/fuzzy1337" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = ("# synthetic module " + name).encode()
        path.write_bytes(raw)
        modules[name] = raw

    directory = tmp_path / "installation"
    evidence = MockEvidence(tmp_path / "local", tmp_path / "retained")
    calls = []
    monkeypatch.setattr(launcher, "REPOSITORY", repository)
    monkeypatch.setattr(launcher, "NativeEnvironment", lambda _root: {})

    def Process(_evidence, label, argv, **options):
        """Record fake commands and synthesize only the narrow test-owned output artifacts."""

        calls.append((label, argv, options))
        assert options["environment"]["PIP_NO_INDEX"] == "1", "No dependency lookup is allowed"
        stdout = b""

        if label.startswith("source-status"):
            dirty = (mutation == "dirty-before" and label == "source-status") or (
                mutation == "dirty-after" and label == "source-status-final")
            stdout = b" M synthetic\n" if dirty else b""

        elif label.startswith("source-checkpoint"):
            stdout = f"{COMMIT}\n{TREE}\n".encode()

        elif label == "build":
            with ZipFile(directory / "wheel/mock.whl", "w") as archive:
                for name, raw in modules.items():
                    archive.writestr("fuzzy1337/" + name, b"changed" if mutation == (
                        "wheel-drift") and name == launcher.SOURCE_MODULES[0] else raw)

                archive.writestr("1337-0.0.mock.dist-info/METADATA",
                    b"Name: 1337\nVersion: 0.0.mock\n")

        elif label == "import-probe":
            prefix = directory / "environment/lib/python3.12/site-packages/fuzzy1337"

            if mutation == "foreign-import":
                prefix = tmp_path / "other/lib/site-packages/fuzzy1337"

            observed = {"distribution_version": "0.0.mock", "installed_sources": {name: {
                "path": str(prefix / name), "sha256": hashlib.sha256(raw).hexdigest()}
                for name, raw in modules.items()}}
            stdout = launcher.CanonicalNative(observed)

            if mutation == "source-drift":
                (repository / "src/fuzzy1337" / launcher.SOURCE_MODULES[0]).write_bytes(b"changed")

        return SimpleNamespace(returncode=0, stdout=stdout, stderr=b"")

    monkeypatch.setattr(launcher, "NativeProcess", Process)

    if mutation is not None:
        with pytest.raises(AssertionError):
            launcher.Build(repository, directory, evidence, commit=COMMIT, tree=TREE, enabled=True)

        return

    installed = launcher.Build(repository, directory, evidence, commit=COMMIT, tree=TREE,
        enabled=True)
    manifest = (directory / "installation.json").read_bytes()
    assert installed.installation["manifest_sha256"] == hashlib.sha256(manifest).hexdigest(), (
        "The original manifest envelope retains the actual serialized manifest digest")
    commands = {label: argv for label, argv, _options in calls}
    assert "--no-isolation" in commands["build"] and commands["create-interpreter"][-3:-1] == (
        "-m", "venv"), "The build uses its fixed host backend and a clean standard environment"
    assert "--system-site-packages" not in commands["create-interpreter"] and all(flag in (
        commands["install"]) for flag in ("--isolated", "--no-index", "--no-deps")), (
            "No system install or online dependency fallback is enrolled")
    assert commands["import-probe"][1:4] == ("-I", "-B", "-c"), (
        "Actual later probes must isolate the selected installed interpreter")


@pytest.mark.parametrize("failure", [None, "worker", "sentinel-setup"])
def test_WorkerRunRetainsSeparateBothOwnerFinalsBeforePredicatesEvenOnFailure(
    failure, monkeypatch, tmp_path,
):
    """Nested mocked owners settle before assertions; a raised process never loses final facts."""

    evidence = MockEvidence(tmp_path / "local", tmp_path / "retained")
    installation = {"manifest_sha256": "d" * 64, "identity": {"mock": True}}
    installed = launcher.InstalledContentWorker(tmp_path / "environment/bin/python", installation,
        {}, COMMIT, TREE)
    events = []
    monkeypatch.setattr(launcher, "NativeCaseEvidence", MockEvidence)
    monkeypatch.setattr(launcher, "NativeInstallation", lambda _python: installation)
    monkeypatch.setattr(launcher, "NativeEnvironment", lambda _root: {})

    @contextmanager
    def Target(owner, *, address, case):
        """Substitute only a pure owner lifecycle; never construct an actual listener or fixture."""

        label = owner.local.name
        events.append("enter-" + label)

        try:
            if failure == "sentinel-setup" and label == "sentinel":
                raise RuntimeError("mock setup failure")

            origin = "http://127.0.0.1:" + ("15432" if label == "main" else "15433")
            yield SimpleNamespace(graph=SimpleNamespace(origin=origin,
                Url=lambda path: origin + path))

        finally:
            events.append("exit-" + label)
            owner.Json("content-source-final.json", {"mock_original_owner": label})

    def Process(owner, label, argv, **options):
        """Retain synthetic terminal records then either return or raise without launching."""

        assert options["installation"] is installation, "The actual manifest envelope is unchanged"
        owner.sequence += 1
        prefix = f"process-{owner.sequence:03d}-{label}"
        owner.Json(prefix + "/invocation.json", {"mock_original": "invocation"})
        owner.Json(prefix + "/process.json", {"mock_original": "terminal"})

        if failure == "worker":
            raise RuntimeError("mock worker failure")

        return SimpleNamespace(returncode=0, stdout=b"mock", stderr=b"")

    def Predicate(*args, **kwargs):
        """Assert only ordering and retention; original-byte semantics have separate pure tests."""

        assert events[-2:] == ["exit-sentinel", "exit-main"], "Both original owners must exit first"
        assert all((evidence.local / (label + "-source-final.json")).is_file()
            for label in ("main", "sentinel")), "Both separate originals must be retained first"

        return "mock-source-delivery"

    monkeypatch.setattr(launcher, "OwnedContentResponseTarget", Target)
    monkeypatch.setattr(launcher, "NativeProcess", Process)
    monkeypatch.setattr(launcher, "AssertContentLauncherEvidence", Predicate)
    monkeypatch.setattr(launcher, "AssertContentSourceFacts", Predicate)

    if failure is not None:
        with pytest.raises(RuntimeError):
            launcher.Run(installed, "missing", "127.0.0.1", evidence, enabled=True)

    else:
        observed = launcher.Run(installed, "missing", "127.0.0.1", evidence, enabled=True)
        assert observed["source_delivery"] == "mock-source-delivery", "No genuine result is claimed"

    assert events[-2:] == ["exit-sentinel", "exit-main"], "Nested owners settle on every path"
    finals = [json.loads((evidence.local / (label + "-source-final.json")).read_bytes())
        for label in ("main", "sentinel")]
    assert finals == [{"mock_original_owner": "main"}, {"mock_original_owner": "sentinel"}], (
        "Identical source final filenames must never overwrite another owner's original record")
