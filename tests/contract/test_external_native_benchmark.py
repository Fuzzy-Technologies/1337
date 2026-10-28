# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Mocked native transport and hostile bundle contracts, never Docker scanner acceptance."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from tests.functional import external_native_runner as bundle_owner
from tests.functional import external_native_runtime as runtime_owner
from tests.functional import test_external_metrics_diagnostic as diagnostic_owner
from tests.functional import test_external_native_benchmark as functional_owner
from tests.functional.conftest import CommandResult
from tests.functional.external_benchmark import LoadPack
from tests.functional.external_native_runner import ExportBundle, ImportBundle, StrictJson
from tests.functional.external_native_runtime import (
    Attach,
    Enabled,
    NativeBenchmarkRuntime,
    RunnerArguments,
    ValidateRunner,
)

TARGET_ID = "a" * 64
IMAGE_ID = "sha256:" + "b" * 64
RUNNER_ID = "c" * 64


def InspectFixture():
    """Return explicitly synthetic Docker policy data for readback validator tests."""

    return {"image_id": IMAGE_ID, "user": "1337:1337", "mounts": [], "host": {
        "NetworkMode": "container:" + TARGET_ID, "ReadonlyRootfs": True,
        "Privileged": False, "Init": True, "Binds": None, "PortBindings": {}, "CapDrop": ["ALL"],
        "CapAdd": None, "Devices": [], "VolumesFrom": [],
        "SecurityOpt": ["no-new-privileges:true"], "Memory": 268435456,
        "NanoCpus": 1000000000, "PidsLimit": 64,
        "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=64m,uid=1337,gid=1337,mode=0700"},
    }}


def BundleFixture(tmp_path):
    """Build an inert two-file bundle without executing any product or provider."""

    source = tmp_path / "source"
    source.mkdir()
    (source / "original.bin").write_bytes(b"\x00\xff\r\n")
    (source / "record.json").write_text('{"kind":"synthetic-contract-only"}')

    return ExportBundle(source, {"status": "contract-fixture-not-executed"}).encode()


def test_BoundedBundlePreservesExactOriginalBytes(tmp_path):
    """Binary evidence and JSON retain exact bytes and declared hashes after transport."""

    raw = BundleFixture(tmp_path)
    value = ImportBundle(raw, tmp_path / "output")
    assert (tmp_path / "output/original.bin").read_bytes() == b"\x00\xff\r\n"
    assert value["outcome"]["status"] == "contract-fixture-not-executed"
    assert len(value["files"]) == 2


@pytest.mark.parametrize("path", ["../escape", "/escape", "a/../escape", "a//b", "a\\b", "C:x"])
def test_BundleRejectsUnsafePathsBeforeWriting(tmp_path, path):
    """Host reconstruction cannot follow absolute, traversal, alias, or Windows paths."""

    bundle = StrictJson(BundleFixture(tmp_path))
    bundle["files"][0]["path"] = path

    with pytest.raises(ValueError):
        ImportBundle(json.dumps(bundle).encode(), tmp_path / "output")

    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("field,value", [
    ("sha256", "0" * 64), ("size_bytes", 999), ("media_type", "text/html"),
    ("data_base64", "***"), ("unexpected_field", True),
])
def test_BundleRejectsMutatedIdentityAndUnexpectedMetadata(tmp_path, field, value):
    """A copied artifact cannot change bytes, type, size, or contract shape silently."""

    bundle = StrictJson(BundleFixture(tmp_path))
    bundle["files"][0][field] = value

    with pytest.raises(ValueError):
        ImportBundle(json.dumps(bundle).encode(), tmp_path / "output")


def test_BundleCountTotalAndLinksAreBounded(tmp_path, monkeypatch):
    """Count/byte limits and link refusal apply to both exporting and importing."""

    raw = BundleFixture(tmp_path)
    monkeypatch.setattr(bundle_owner, "MAX_FILES", 1)

    with pytest.raises(ValueError, match="count"):
        ImportBundle(raw, tmp_path / "output")

    monkeypatch.setattr(bundle_owner, "MAX_FILES", 128)
    monkeypatch.setattr(bundle_owner, "MAX_BUNDLE_BYTES", 2)

    with pytest.raises(ValueError, match="bounded identity"):
        ImportBundle(raw, tmp_path / "output")

    with pytest.raises(ValueError, match="budget"):
        ExportBundle(tmp_path / "source", {})

    monkeypatch.setattr(bundle_owner, "MAX_BUNDLE_BYTES", 8 * 1024 * 1024)
    (tmp_path / "source/link").symlink_to(tmp_path / "source/original.bin")

    with pytest.raises(ValueError, match="symbolic"):
        ExportBundle(tmp_path / "source", {})


@pytest.mark.parametrize("raw", [
    b'{"x":1,"x":2}', b'{"nested":[{"x":1e999}]}', b'[{"x":-1e999}]',
])
def test_BundleDecoderRejectsAmbiguityAndNumericOverflow(raw):
    """Standalone image transport uses the same strict numerical/key boundary as comparison."""

    with pytest.raises(ValueError):
        StrictJson(raw)


def test_ContainerArgumentsHaveNoHostEscapeOrEnvironmentForwarding():
    """The finite invocation cannot acquire host network, ports, mounts, or credentials."""

    arguments = RunnerArguments("fuzzy-1337-external-123456abcdef-native", TARGET_ID,
                                IMAGE_ID, "/metrics")
    assert arguments[arguments.index("--network") + 1] == "container:" + TARGET_ID
    assert arguments[arguments.index("--user") + 1] == "1337:1337"
    assert "--read-only" in arguments and "--init" in arguments
    assert not {"--privileged", "--volume", "-v", "--mount", "--publish", "-p",
                "--env", "-e", "--env-file", "--pid"} & set(arguments)
    ValidateRunner(InspectFixture(), TARGET_ID, IMAGE_ID)


@pytest.mark.parametrize("field,value", [
    ("NetworkMode", "host"), ("ReadonlyRootfs", False), ("Privileged", True),
    ("Binds", ["/var/run/docker.sock:/var/run/docker.sock"]),
    ("CapAdd", ["SYS_ADMIN"]), ("Memory", 0), ("PidsLimit", 0),
])
def test_DockerReadbackCannotWidenTheApprovedBoundary(field, value):
    """Enforcement must be read back, not inferred only from intended command arguments."""

    inspected = InspectFixture()
    inspected["host"][field] = value

    with pytest.raises(ValueError, match="isolation"):
        ValidateRunner(inspected, TARGET_ID, IMAGE_ID)


def test_DefaultLaneSkipsBeforeDockerDiscovery(monkeypatch):
    """Disabled real execution is SKIP/UNRUN and cannot probe the Docker environment."""

    def Forbidden(command):
        """Prove absent opt-in returns before any provider discovery."""

        raise AssertionError("Disabled execution discovered Docker")

    monkeypatch.delenv("FUZZY1337_EXTERNAL_NATIVE_BENCHMARK", raising=False)
    monkeypatch.setattr(functional_owner.shutil, "which", Forbidden)

    with pytest.raises(pytest.skip.Exception, match="UNRUN"):
        next(functional_owner.external_native_runtime.__wrapped__())


def test_EnabledLaneCannotPromotePlannedMapping(monkeypatch):
    """Source existence and an explicit run request do not accept an unintegrated detector."""

    pack, target = LoadPack()
    pack["scanner_tracks"][0]["implementation"] = "planned"
    monkeypatch.setenv("FUZZY1337_EXTERNAL_NATIVE_BENCHMARK", "juice-shop")
    monkeypatch.setattr(functional_owner, "LoadPack", lambda: (pack, target))

    with pytest.raises(pytest.fail.Exception, match="accepted integrated"):
        next(functional_owner.external_native_runtime.__wrapped__())


def test_EnabledMissingDockerFailsRatherThanSkips(monkeypatch):
    """A required accepted lane cannot claim success when its actual runtime is unavailable."""

    pack, target = LoadPack()
    pack["scanner_tracks"][0]["implementation"] = "available"
    monkeypatch.setenv("FUZZY1337_EXTERNAL_NATIVE_BENCHMARK", "juice-shop")
    monkeypatch.setattr(functional_owner, "LoadPack", lambda: (pack, target))
    monkeypatch.setattr(functional_owner.shutil, "which", lambda command: None)

    with pytest.raises(pytest.fail.Exception, match="requires Docker"):
        next(functional_owner.external_native_runtime.__wrapped__())


def test_UnknownSelectionIsAnError():
    """A typo cannot silently disable required functional acceptance."""

    assert not Enabled(None)

    with pytest.raises(ValueError, match="must be unset"):
        Enabled("juice-shop-candidate")


@pytest.mark.parametrize("path,body", [
    ("/", "<html>OWASP Juice Shop</html>"),
    ("/rest/admin/application-version", '{"version":"20.2.0"}'),
])
def test_CausalControlsAreProbedIndependentlyOfScannerAttempts(tmp_path, path, body):
    """Existing real HTML/JSON control content must be established before scoring absence."""

    pack, target = LoadPack()
    runtime = NativeBenchmarkRuntime(Path(__file__).resolve().parents[2], tmp_path, pack, target)
    lab = SimpleNamespace(Request=lambda selected: SimpleNamespace(status=200, error="", body=body))
    assert runtime.Control({"path": path}, lab) == hashlib.sha256(body.encode()).hexdigest()
    lab.Request = lambda selected: SimpleNamespace(status=200, error="", body="unrelated")

    with pytest.raises((ValueError, RuntimeError)):
        runtime.Control({"path": path}, lab)


def test_SyntheticTransportProducerFitsTheExistingComparisonConsumer(tmp_path):
    """Validate genuine metadata-producing code with inert byte fixtures, never a scanner run."""

    pack, target = LoadPack()
    pack["scanner_tracks"][0]["implementation"] = "available"
    repository = tmp_path / "repository"
    runtime = NativeBenchmarkRuntime(repository, tmp_path / "output", pack, target)
    runtime.source_revision = "d" * 40
    case = pack["cases"][1]
    directory = runtime.output / case["id"]
    scanner = directory / "scanner"
    scanner.mkdir(parents=True)
    runner = repository / "tests/functional/external_native_runner.py"
    runner.parent.mkdir(parents=True)
    runner.write_bytes(b"contract-only source fixture, never executed")
    modules = {}

    for module in bundle_owner.MODULES:
        path = repository / "src/fuzzy1337" / (module.replace(".", "/") + ".py")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"contract-only module fixture, never imported")
        modules[module] = hashlib.sha256(path.read_bytes()).hexdigest()

    wheel = scanner / "1337-0.2.1-py3-none-any.whl"
    wheel.write_bytes(b"inert contract fixture, not a wheel")
    provisioning = {"source_revision": runtime.source_revision,
        "runner_sha256": hashlib.sha256(runner.read_bytes()).hexdigest(),
        "python_sha256": "e" * 64, "module_sha256": modules,
        "wheel": {"filename": wheel.name, "size_bytes": wheel.stat().st_size,
                  "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()}}
    url = "http://127.0.0.1:3000" + case["path"]
    control_hash = hashlib.sha256(b'{"version":"20.2.0"}').hexdigest()
    invocation = {"argv": ["contract-only-not-executed"], "scanner_id": "native.web-check",
        "scanner_version": "contract-fixture", "scanner_sha256": "e" * 64,
        "rule_sha256": modules["adapters.prometheus_exposition"],
        "product_revision": runtime.source_revision, "effective_budget": pack["requested_budget"]}

    for name, value in (("provisioning.json", provisioning), ("invocation.json", invocation),
                        ("findings.json", []), ("worker-stdout.json", {"url": url,
                         "check_id": "native.prometheus-exposition", "status": 200,
                         "matched": False, "body_sha256": control_hash})):
        (scanner / name).write_text(json.dumps(value))

    (scanner / "worker-stderr.json").write_bytes(b"")
    lab = SimpleNamespace(observations=[], provenance={"container_id": TARGET_ID,
        "platform_manifest_digest": target["platform_digests"]["linux/amd64"]})
    (repository / "labs/external").mkdir(parents=True)
    (repository / "labs/external/compose.yaml").write_bytes(b"contract-only-compose")
    outcome = {"status": "completed", "exit_code": 0, "duration_seconds": 0.1, "target_url": url}
    observation = runtime.Observation(case, directory, lab, outcome, control_sha256=control_hash)
    runtime_owner.ValidateObservation(pack, target, observation, runtime.output)
    accounting = json.loads((directory / "attempt-provenance.json").read_text())
    assert accounting["independent_server_contact_count"] is None
    assert accounting["approved_attempt_count"] == 1
    provisioning["wheel"]["filename"] = "../outside.whl"
    (scanner / "provisioning.json").write_text(json.dumps(provisioning))

    with pytest.raises(RuntimeError, match="unknown wheel"):
        runtime.Observation(case, directory, lab, outcome, control_sha256=control_hash)


@pytest.mark.parametrize("timed_out", [False, True])
def test_DockerAttachmentRetainsOriginalBytesAndExit(tmp_path, monkeypatch, timed_out):
    """Malformed UTF-8 or partial timeout streams remain byte-exact even in readable logs."""

    def Execute(argv, **options):
        """Return synthetic binary streams without starting Docker or any scanner."""

        assert options["shell"] is False

        if timed_out:
            raise subprocess.TimeoutExpired(argv, 40, output=b"\xff\r\n", stderr=b"\xfe\r\n")

        return SimpleNamespace(stdout=b"\xff\r\n", stderr=b"\xfe\r\n", returncode=4)

    monkeypatch.setattr(runtime_owner.subprocess, "run", Execute)
    records = []
    lab = SimpleNamespace(repository_root=tmp_path, WriteEvidence=records.append)
    result, raw = Attach(lab, RUNNER_ID, tmp_path)
    assert raw == (tmp_path / "docker.stdout").read_bytes() == b"\xff\r\n"
    assert (tmp_path / "docker.stderr").read_bytes() == b"\xfe\r\n"
    assert result.returncode == (124 if timed_out else 4) and result.timed_out is timed_out
    assert records == [result]


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_FailedScannerExportStillRemovesRunnerAndTarget(tmp_path, monkeypatch, cleanup_fails):
    """A malformed child export cannot skip either resource owner's cleanup path."""

    pack, target = LoadPack()
    runtime = NativeBenchmarkRuntime(Path(__file__).resolve().parents[2], tmp_path, pack, target)
    runtime.image_id = IMAGE_ID
    operations = []

    class Lab:
        """Supply synthetic lifecycle records only, never a target or scanner."""

        project_name = "fuzzy-1337-external-123456abcdef"
        provenance = {"container_id": TARGET_ID}

        def __init__(self, *arguments):
            """Ignore fixture construction arguments without creating resources."""

        def Start(self):
            """Enter the actual generator owner without starting a real target."""

            operations.append(("synthetic-target-start",))

        def Stop(self):
            """Expose the actual generator owner's unconditional teardown."""

            operations.append(("synthetic-target-cleanup",))

        def Run(self, *argv, timeout_seconds):
            """Record the requested finite lifecycle operation with fixed synthetic output."""

            operations.append(argv)
            stdout = RUNNER_ID if argv[1] == "create" else (
                json.dumps(InspectFixture()) if argv[1] == "inspect" else "")

            code = 1 if cleanup_fails and argv[1] == "rm" else 0
            error = "synthetic cleanup failure" if code else ""

            return CommandResult(tuple(argv), code, stdout, error)

        @staticmethod
        def RequireSuccess(result, operation):
            """Keep the actual finite helper's failure behavior for source-only testing."""

            runtime_owner.ComposeLab.RequireSuccess(result, operation)

    monkeypatch.setattr(runtime_owner, "ExternalTargetLab", Lab)
    monkeypatch.setattr(runtime_owner, "Attach", lambda *arguments: (
        CommandResult(("docker", "start"), 4, "not-json", "synthetic-failure"), b"not-json"))

    with pytest.raises(RuntimeError if cleanup_fails else ValueError):
        runtime.RunCase(pack["cases"][0])

    assert any(argv[:2] == ("docker", "rm") for argv in operations)
    assert operations[0] == ("synthetic-target-start",)
    assert operations[-1] == ("synthetic-target-cleanup",)


def test_ActualTargetGeneratorOwnerCleansUpAfterStartupFailure(tmp_path, monkeypatch):
    """The native caller adapts the fixture generator and retains its pre-yield teardown."""

    pack, target = LoadPack()
    runtime = NativeBenchmarkRuntime(Path(__file__).resolve().parents[2], tmp_path, pack, target)
    operations = []

    class Lab:
        """Fail before yielding a synthetic lifecycle while retaining the real owner."""

        def __init__(self, *arguments):
            """Ignore construction arguments without acquiring resources."""

        def Start(self):
            """Represent a bounded startup refusal before any scanner can start."""

            operations.append("start")

            raise RuntimeError("synthetic startup refusal")

        def Stop(self):
            """Prove the existing generator finalizer runs after startup refusal."""

            operations.append("cleanup")

    monkeypatch.setattr(runtime_owner, "ExternalTargetLab", Lab)

    with pytest.raises(RuntimeError, match="startup refusal"):
        runtime.RunCase(pack["cases"][0])

    assert operations == ["start", "cleanup"]


def test_DraftNativeCheckpointRunsOnlyItsGenuineLaneBeforeTheFinalGate():
    """One explicit draft marker exercises native cases without repeating the full matrix."""

    root = Path(__file__).resolve().parents[2]
    workflow = yaml.safe_load((root / ".github/workflows/python-quality.yml").read_text())
    jobs = workflow["jobs"]
    marker = "[native-external-checkpoint]"
    final = ("github.event_name == 'push' || (github.event_name == 'pull_request' "
             "&& github.event.pull_request.draft == false)")
    checkpoint = (final + " || (github.event_name == 'pull_request' "
                  "&& github.event.pull_request.draft == true "
                  "&& contains(github.event.pull_request.body, '" + marker + "'))")
    lane = jobs["external-targets"]
    assert " ".join(lane["if"].split()) == checkpoint
    assert lane["env"]["FUZZY1337_EXTERNAL_NATIVE_BENCHMARK"] == "juice-shop"
    assert lane.get("continue-on-error", False) is False
    assert all(marker not in job.get("if", "") for name, job in jobs.items()
               if name != "external-targets")
    steps = {step["name"]: step for step in lane["steps"]}
    assert " ".join(steps["Execute pinned target through pytest"]["if"].split()) == final
    native = steps["Execute installed native scanner against three fresh pinned targets"]
    assert "tests/functional/test_external_native_benchmark.py" in native["run"]
    assert "--no-cov -n 0" in native["run"] and "--junitxml=" in native["run"]
    assert native["timeout-minutes"] == 15 and lane["timeout-minutes"] == 20
    diagnostic_marker = "[native-external-metrics-diagnostic]"
    assert " ".join(native["if"].split()) == (
        "github.event_name != 'pull_request' || github.event.pull_request.draft == false "
        "|| !contains(github.event.pull_request.body, '" + diagnostic_marker + "')"
    )
    diagnostic = steps["Capture one separate fresh-target metrics diagnostic"]
    assert " ".join(diagnostic["if"].split()) == (
        "github.event_name == 'pull_request' && github.event.pull_request.draft == true "
        "&& contains(github.event.pull_request.body, '" + diagnostic_marker + "')"
    )
    assert diagnostic["env"] == {"FUZZY1337_EXTERNAL_METRICS_DIAGNOSTIC": "juice-shop"}
    assert "tests/functional/test_external_metrics_diagnostic.py" in diagnostic["run"]
    assert "test_external_native_benchmark.py" not in diagnostic["run"]
    assert "--no-cov -n 0" in diagnostic["run"] and diagnostic["timeout-minutes"] == 3
    upload = steps["Preserve external target evidence"]
    assert upload["if"] == "always()" and (
        "functional-evidence/external-native-benchmark/" in upload["with"]["path"]
    )
    container = next(step["run"] for step in jobs["container-quality"]["steps"]
                     if step.get("name") == "Run container quality gate")
    assert "--suite-timeout 900" in container


def test_SeparateDiagnosticSkipsBeforeAnyTargetIsCreated(monkeypatch):
    """Ordinary collection cannot acquire a target for the separately authorized diagnostic."""

    monkeypatch.delenv("FUZZY1337_EXTERNAL_METRICS_DIAGNOSTIC", raising=False)

    def Forbidden(name):
        """Fail if a disabled diagnostic attempts even fixture discovery."""

        raise AssertionError("Disabled diagnostic created a target")

    with pytest.raises(pytest.skip.Exception, match="UNRUN"):
        diagnostic_owner.test_OneFreshTargetMetricsDiagnostic(
            SimpleNamespace(getfixturevalue=Forbidden))


@pytest.mark.parametrize("mutation", [None, "length", "limit", "base64"])
def test_DiagnosticCapturePreservesNewRawBytesAndRefusesInvalidLengths(tmp_path, mutation):
    """Binary fixture bytes stay exact and explicitly separate from the earlier scanner body."""

    body = b"\x00\xff\r\n"
    payload = {"status": 200, "headers": [["Content-Type", "text/plain"]],
        "body_base64": base64.b64encode(body).decode("ascii"),
        "body_bytes": len(body), "error": ""}

    if mutation == "length":
        payload["body_bytes"] -= 1

    elif mutation == "limit":
        payload["body_bytes"] = diagnostic_owner.MAX_BODY_BYTES + 1

    elif mutation == "base64":
        payload["body_base64"] = "***"

    def Compose(*arguments, timeout_seconds):
        """Return an inert JSON/base64 producer without Node, Docker or HTTP execution."""

        assert arguments[:5] == ("exec", "-T", "external-juice-shop", "/nodejs/bin/node", "-e")
        assert timeout_seconds == 3

        return CommandResult(("contract-fixture-not-executed",), 0, json.dumps(payload), "")

    lab = SimpleNamespace(repository_root=Path(__file__).resolve().parents[2],
        target=SimpleNamespace(Service="external-juice-shop"),
        provenance={"fixture": "synthetic-contract-only"}, Compose=Compose,
        RequireSuccess=runtime_owner.ComposeLab.RequireSuccess)

    if mutation is not None:
        with pytest.raises(ValueError):
            diagnostic_owner.CaptureDiagnostic(lab, tmp_path)

        assert not (tmp_path / "response.body.bin").exists()

        return

    receipt = diagnostic_owner.CaptureDiagnostic(lab, tmp_path)
    assert (tmp_path / "response.body.bin").read_bytes() == body
    assert receipt["body_sha256"] == hashlib.sha256(body).hexdigest()
    assert receipt["purpose"] == "independent-fresh-target-metrics-diagnostic"
    assert receipt["original_scan_response"] is False
