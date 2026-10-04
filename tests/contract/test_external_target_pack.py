# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Offline isolation, provenance, lifecycle, and localhost external-pack contracts."""

from __future__ import annotations

import copy
import json
import subprocess
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, ValidationError

from tests.functional.conftest import CommandResult, ComposeLab
from tests.functional.conftest import external_target_lab as ExternalTargetFixture
from tests.functional.external_http_probe import Main, ReadResponse
from tests.functional.external_targets import (
    ExternalTarget,
    ExternalTargetLab,
    HttpObservation,
    IsPackEnabled,
    LoadTarget,
    OwnExternalTarget,
    ValidateCompose,
)
from tests.functional.test_external_targets import ProbeExternalTarget

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def ComposeDefinition() -> dict[str, Any]:
    """Read the same JSON-subset Compose definition consumed by Docker."""

    return json.loads((REPOSITORY_ROOT / "labs/external/compose.yaml").read_text(encoding="utf-8"))


def ObservedComposeDefinition() -> dict[str, Any]:
    """Load actual Compose v2.38.2 output preserved by CI run 37198612357."""

    path = Path(__file__).parent / "fixtures" / "external-compose-config.v1.json"

    return json.loads(path.read_text(encoding="utf-8"))


class FakeDockerLab(ExternalTargetLab):
    """Provide deterministic Docker outputs while retaining actual harness evidence."""

    def __init__(self, evidence_directory: Path) -> None:
        """Use the real declared target and synthetic bounded Docker responses."""

        super().__init__(REPOSITORY_ROOT, evidence_directory, LoadTarget(REPOSITORY_ROOT))
        self.failure = ""
        self.remaining = ""
        self.version: object = self.target.manifest["version"]
        self.container_changes: dict[str, Any] = {}
        self.image_changes: dict[str, Any] = {}
        self.index_changes: dict[str, Any] = {}
        self.http_error = ""
        self.http_timed_out = False

    def Run(self, *arguments: str, timeout_seconds: int) -> CommandResult:
        """Map exact Docker operations to independently inspectable fake records."""

        del timeout_seconds
        stdout = ""
        returncode = 0
        operation = arguments[1]

        if operation == "compose":
            operation = arguments[arguments.index("--profile") + 2]

            if operation == "config":
                stdout = json.dumps(ObservedComposeDefinition())

            elif operation == "ps":
                stdout = self.remaining if "--all" in arguments else "a" * 64

            elif operation == "port":
                stdout = "127.0.0.1:49123"

        elif operation == "inspect":
            stdout = json.dumps({
                "image_ref": self.target.ImageReference, "image_id": "sha256:" + "a" * 64,
                "running": True, **self.container_changes,
            })

        elif operation == "image":
            stdout = json.dumps({
                "id": "sha256:" + "a" * 64, "os": "linux", "architecture": "amd64",
                "repo_digests": [
                    self.target.manifest["repository"] + "@" + self.target.manifest["index_digest"],
                ], **self.image_changes,
            })

        elif operation == "manifest":
            stdout = json.dumps({
                "manifests": [
                    {"digest": digest, "platform": {
                        "os": platform.split("/")[0], "architecture": platform.split("/")[1],
                    }} for platform, digest in self.target.manifest["platform_digests"].items()
                ], **self.index_changes,
            })

        if operation == self.failure:
            returncode = 1

        if operation == "logs" and self.failure == "diagnostic-exception":
            raise OSError("injected diagnostic exception")

        result = CommandResult(
            tuple(arguments), returncode, stdout,
            "injected lifecycle failure" if returncode else "", duration_seconds=0.125,
        )
        self.WriteEvidence(result)

        return result

    def Request(self, path: str, timeout_seconds: float | None = None) -> HttpObservation:
        """Return independent version/root/search payloads without a network connection."""

        del timeout_seconds
        body = (
            json.dumps({"version": self.version})
            if path == "/rest/admin/application-version" else
            "<title>OWASP Juice Shop</title>" if path == "/" else
            json.dumps({"data": []})
        )
        result = HttpObservation(
            "127.0.0.1", self.port, path, 200, (), body, self.http_error,
            self.http_timed_out, 0.01,
        )
        self.observations.append(result)

        return result


@pytest.fixture
def fake_lab(tmp_path: Path) -> FakeDockerLab:
    """Provide a fresh project and isolated evidence directory for each contract."""

    return FakeDockerLab(tmp_path)


def test_ExternalManifestAndComposeUseTheSameImmutablePin() -> None:
    """Validate declarative metadata and its offline-consumed isolation definition."""

    target = LoadTarget(REPOSITORY_ROOT)
    ValidateCompose(ComposeDefinition(), target)

    assert target.manifest["tag"] == "v20.2.0", "External pack release tag must be explicit."
    assert target.manifest["source_revision"] == "5658473cf8814459bf89000ce373b20ed0b4eb37", (
        "External pack must retain the exact annotated upstream release source revision."
    )
    assert "@sha256:" in target.ImageReference, "External pack cannot pull a mutable-only tag."


def test_ActualNormalizedComposeOutputPreservesThePinnedBoundary() -> None:
    """Accept producer-added null defaults and exact decimal resource representation."""

    configuration = ObservedComposeDefinition()
    service = configuration["services"]["external-juice-shop"]
    ValidateCompose(configuration, LoadTarget(REPOSITORY_ROOT))

    assert service["command"] is None and service["entrypoint"] is None, (
        "Actual Compose normalization must preserve the image's command and entrypoint."
    )
    assert service["mem_limit"] == "805306368", (
        "The observed decimal string must retain the exact configured 768 MiB memory bound."
    )


@pytest.mark.parametrize("selection", [None, ""])
def test_ExternalPackIsDisabledWithoutExplicitOptIn(selection: str | None) -> None:
    """Leave ordinary test runs offline without probing Docker availability."""

    assert not IsPackEnabled(selection), "Unset selection must not permit external image pulls."


def test_DisabledExternalFixtureSkipsBeforeCheckingDocker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prove ordinary tests avoid even Docker discovery when the pack is disabled."""

    def ForbiddenDockerDiscovery(command: str) -> None:
        """Reject Docker discovery to prove disabled selection has no lifecycle effect."""

        del command

        raise AssertionError("Disabled external pack must not discover Docker")

    monkeypatch.delenv("FUZZY1337_EXTERNAL_TARGETS", raising=False)
    monkeypatch.setattr("tests.functional.conftest.shutil.which", ForbiddenDockerDiscovery)

    with pytest.raises(pytest.skip.Exception, match="External targets require"):
        next(ExternalTargetFixture.__wrapped__())


def test_EnabledExternalFixtureFailsWhenDockerIsMissing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prove the required enabled smoke cannot turn unavailable Docker into a skipped PASS."""

    monkeypatch.setenv("FUZZY1337_EXTERNAL_TARGETS", "juice-shop")
    monkeypatch.setattr("tests.functional.conftest.shutil.which", lambda command: None)

    with pytest.raises(pytest.fail.Exception, match="requires Docker Compose"):
        next(ExternalTargetFixture.__wrapped__())


@pytest.mark.parametrize("selection", ["all", "latest", "Juice-Shop", " juice-shop", "../target"])
def test_ExternalPackRejectsUnknownSelection(selection: str) -> None:
    """Reject accidental broadening or an unreviewed target selection."""

    with pytest.raises(ValueError, match="exactly 'juice-shop'"):
        IsPackEnabled(selection)

    assert IsPackEnabled("juice-shop"), "Only the known exact pack value may enable execution."


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", 2), ("oracle_complete", True), ("index_digest", "latest"),
        ("source_revision", "main"), ("http_port", 8080), ("unexpected", True),
    ],
)
def test_ExternalManifestRejectsUnsupportedOrUnattributableState(field: str, value: object) -> None:
    """Fail before I/O on unsupported schemas, mutable provenance, and false oracle claims."""

    schema = json.loads((REPOSITORY_ROOT / "labs/external/target.schema.json").read_text())
    manifest = copy.deepcopy(LoadTarget(REPOSITORY_ROOT).manifest)
    manifest[field] = value

    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(manifest)


@pytest.mark.parametrize(
    "field,value",
    [
        ("image", "bkimminich/juice-shop:latest"), ("privileged", True),
        ("volumes", ["/:/host"]), ("network_mode", "host"), ("cap_drop", []),
        ("security_opt", []), ("mem_limit", 0), ("pids_limit", 0), ("cpus", 4),
        ("pull_policy", "always"), ("environment", {"SECRET": "synthetic-value"}),
        ("cap_add", ["SYS_ADMIN"]), ("entrypoint", ["unreviewed"]),
        ("command", ["unreviewed"]), ("command", []), ("command", ""),
        ("command", False), ("entrypoint", []), ("entrypoint", ""), ("entrypoint", False),
        ("cpus", True),
        ("healthcheck", {"test": ["CMD", "unreviewed"]}),
        ("ports", [{"target": 3000, "published": "3000", "host_ip": "0.0.0.0"}]),
    ],
)
def test_ExternalComposeRejectsWidenedIsolation(field: str, value: object) -> None:
    """Reject host exposure, mounts, capability increases, and unbounded resources."""

    configuration = ObservedComposeDefinition()
    configuration["services"]["external-juice-shop"][field] = value

    with pytest.raises(RuntimeError, match="isolation"):
        ValidateCompose(configuration, LoadTarget(REPOSITORY_ROOT))


@pytest.mark.parametrize(
    "value", [
        True, False, 805306368.0, "768m", "805306369", "+805306368", "0805306368",
        "805306368.0", "NaN",
    ],
)
def test_NormalizedComposeMemoryRejectsDifferentOrAmbiguousRepresentations(value: object) -> None:
    """Accept only the exact bounded integer or its observed canonical decimal string."""

    configuration = ObservedComposeDefinition()
    configuration["services"]["external-juice-shop"]["mem_limit"] = value

    with pytest.raises(RuntimeError, match="resources"):
        ValidateCompose(configuration, LoadTarget(REPOSITORY_ROOT))


def test_ExternalComposeRejectsNonInternalOrAdditionalNetworks() -> None:
    """Require exactly one no-egress network and no additional target service."""

    configuration = ComposeDefinition()
    configuration["networks"]["external-targets"]["internal"] = False

    with pytest.raises(RuntimeError, match="isolation"):
        ValidateCompose(configuration, LoadTarget(REPOSITORY_ROOT))

    configuration = ComposeDefinition()
    configuration["services"]["unreviewed"] = {}

    with pytest.raises(RuntimeError, match="exactly"):
        ValidateCompose(configuration, LoadTarget(REPOSITORY_ROOT))


def test_ExternalLifecycleAttributesTheRunningPlatformAndCleansUp(fake_lab: FakeDockerLab) -> None:
    """Exercise producer/consumer lifecycle and raw evidence with exact fake Docker outputs."""

    with contextmanager(OwnExternalTarget)(fake_lab) as lab:
        assert lab.port == 49123, "Only the loopback published port may reach consumers."
        assert lab.provenance["platform"] == "linux/amd64", (
            "Provenance must record the actual inspected running-image platform."
        )
        assert lab.provenance["platform_manifest_digest"] == (
            lab.target.manifest["platform_digests"]["linux/amd64"]
        ), "Running platform manifest must match the pinned OCI index inventory."

    assert any("down" in command.argv for command in fake_lab.commands), (
        "Fixture teardown must execute after successful consumption."
    )
    evidence = json.loads((fake_lab.evidence_directory / "command-01.json").read_text())

    assert evidence["duration_seconds"] == 0.125, "Raw lifecycle evidence must retain duration."
    assert evidence["argv"][:2] == ["docker", "compose"], (
        "Lifecycle evidence must retain exact argv rather than a reconstructed shell string."
    )


@pytest.mark.parametrize(
    "failure", ["config", "pull", "up", "inspect", "image", "manifest", "port"],
)
def test_ExternalStartupFailuresAlwaysAttemptTeardown(
    fake_lab: FakeDockerLab, failure: str,
) -> None:
    """Ensure every partial startup failure enters bounded cleanup."""

    fake_lab.failure = failure

    with pytest.raises(RuntimeError, match="failed"):
        with contextmanager(OwnExternalTarget)(fake_lab):
            raise AssertionError("Startup failures must never yield the lab to a consumer")

    assert any("down" in command.argv for command in fake_lab.commands), (
        "A failed startup may have created state and must attempt fixture-owned teardown."
    )


def test_ExternalConsumerExceptionStillCleansUp(fake_lab: FakeDockerLab) -> None:
    """Remove resources when a functional assertion or consumer operation raises."""

    with pytest.raises(ValueError, match="consumer failed"):
        with contextmanager(OwnExternalTarget)(fake_lab):
            raise ValueError("consumer failed")

    assert any("down" in command.argv for command in fake_lab.commands), (
        "Consumer exceptions must not bypass target cleanup."
    )


def test_ExternalDiagnosticExceptionStillRemovesAndVerifiesContainers(
    fake_lab: FakeDockerLab,
) -> None:
    """A failed log/evidence diagnostic must never prevent resource cleanup."""

    fake_lab.failure = "diagnostic-exception"

    with pytest.raises(OSError, match="diagnostic exception"):
        with contextmanager(OwnExternalTarget)(fake_lab):
            pass

    assert any("down" in command.argv for command in fake_lab.commands), (
        "Diagnostic collection exceptions must still execute bounded Compose down."
    )
    assert "--all" in fake_lab.commands[-1].argv, (
        "Diagnostic collection exceptions must still verify no project container remains."
    )


@pytest.mark.parametrize("failure,remaining", [("down", ""), ("", "container-left-over")])
def test_ExternalCleanupFailureCannotBeReportedAsSuccess(
    fake_lab: FakeDockerLab, failure: str, remaining: str,
) -> None:
    """Treat failed removal and surviving containers as real lifecycle failures."""

    fake_lab.failure = failure
    fake_lab.remaining = remaining

    with pytest.raises(RuntimeError, match="cleanup"):
        with contextmanager(OwnExternalTarget)(fake_lab):
            pass


@pytest.mark.parametrize(
    "changes",
    [{"image_ref": "mutable:latest"}, {"image_id": "other-image"}, {"running": False}],
)
def test_ExternalProvenanceRejectsWrongRunningContainer(
    fake_lab: FakeDockerLab, changes: dict[str, Any],
) -> None:
    """Reject a different configured image, image object, or stopped container."""

    fake_lab.container_changes = changes

    with pytest.raises(RuntimeError, match="provenance"):
        fake_lab.CaptureProvenance()


@pytest.mark.parametrize(
    "changes",
    [{"architecture": "unreviewed"}, {"repo_digests": []}, {"os": "windows"}],
)
def test_ExternalProvenanceRejectsUnpinnedPlatform(
    fake_lab: FakeDockerLab, changes: dict[str, Any],
) -> None:
    """Do not infer provenance from a tag when the actual platform or digest differs."""

    fake_lab.image_changes = changes

    with pytest.raises(RuntimeError, match="provenance"):
        fake_lab.CaptureProvenance()


def test_ExternalProvenanceRejectsChangedRegistryPlatform(fake_lab: FakeDockerLab) -> None:
    """Require the pinned platform child to exist exactly once in the fetched index."""

    fake_lab.index_changes = {"manifests": []}

    with pytest.raises(RuntimeError, match="provenance"):
        fake_lab.CaptureProvenance()


@pytest.mark.parametrize("version", ["wrong-release", None, []])
def test_ExternalReadinessRejectsUnrelatedSuccessfulHttp(
    fake_lab: FakeDockerLab, version: object,
) -> None:
    """An HTTP 200 is insufficient without the exact application release contract."""

    fake_lab.version = version

    with pytest.raises(RuntimeError, match="version"):
        fake_lab.WaitUntilReady()


def test_ExternalReadinessBudgetExpiresWithoutFalseSuccess(
    fake_lab: FakeDockerLab, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use a deterministic clock to exercise failed readiness without blocking tests."""

    ticks = iter((0.0, 61.0))
    monkeypatch.setattr("tests.functional.external_targets.time.monotonic", lambda: next(ticks))

    with pytest.raises(RuntimeError, match="readiness"):
        fake_lab.WaitUntilReady()


def test_ExternalReportPreservesEvidenceAndWithholdsAccuracy(fake_lab: FakeDockerLab) -> None:
    """Run the real report builder from actual harness outputs without fabricating an oracle."""

    fake_lab.Start()
    report = ProbeExternalTarget(fake_lab)
    scored = report["runs"][0]

    assert set(scored["run"]["detected_checks"]) == {
        "application.version", "catalog.search", "web.root",
    }, "Qualitative observations must derive from the actual probe responses."
    assert scored["metrics"]["accuracy_reason"] == "incomplete-oracle", (
        "External target reports must identify their incomplete oracle explicitly."
    )
    assert scored["metrics"]["tp"] is None, "Realistic target smoke cannot invent positives."
    assert scored["metrics"]["accuracy"] is None, "Realistic target smoke cannot claim accuracy."
    evidence = {record["role"]: record["content"] for record in scored["run"]["evidence"]}

    assert json.loads(evidence["invocation"])[0] == list(fake_lab.commands[0].argv), (
        "Reports must preserve the original invocation rather than a rendered approximation."
    )
    assert (fake_lab.evidence_directory / "matrix.html").is_file(), (
        "The actual report consumer must write the readable matrix artifact."
    )


def test_ExternalReportKeepsRecoveredStartupHistorySeparateFromAssessment(
    fake_lab: FakeDockerLab,
) -> None:
    """Preserve prior readiness failures without misclassifying a later successful probe."""

    fake_lab.observations.append(HttpObservation(
        "127.0.0.1", 49123, "/rest/admin/application-version", None, (), "",
        "recovered startup transport failure", True, 0.1,
    ))
    report = ProbeExternalTarget(fake_lab)

    assert report["runs"][0]["run"]["status"] == "completed", (
        "Completed assessment status must derive from its own requests after recovered readiness."
    )
    evidence = {entry["role"]: entry["content"] for entry in report["runs"][0]["run"]["evidence"]}

    assert "recovered startup transport failure" in evidence["http"], (
        "Recovered startup failures must remain in raw evidence rather than being discarded."
    )


@pytest.mark.parametrize("timed_out,expected", [(True, "timed-out"), (False, "crashed")])
def test_ExternalReportRetainsFailedRequestTerminalState(
    fake_lab: FakeDockerLab, timed_out: bool, expected: str,
) -> None:
    """Prevent transport errors and timeouts from becoming completed smoke assessments."""

    fake_lab.http_error = "injected transport failure"
    fake_lab.http_timed_out = timed_out
    report = ProbeExternalTarget(fake_lab)

    assert report["runs"][0]["run"]["status"] == expected, (
        "A failed request must remain a failed functional run in preserved evidence."
    )


class LocalHttpHandler(BaseHTTPRequestHandler):
    """Serve deterministic local responses including redirect, overflow, and slow bodies."""

    def do_GET(self) -> None:
        """Provide localhost-only failure boundaries for the real child-process probe."""

        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "https://example.com/never-requested")
            self.end_headers()

            return

        body = (
            b"x" * 65537 if self.path == "/overflow" else
            b"ab" if self.path == "/slow" else
            b'{"version":"20.2.0"}'
        )
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

        if self.path == "/slow":
            self.wfile.write(body[:1])
            self.wfile.flush()
            getattr(self.server, "stop_event").wait(2)

            return

        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        """Keep deterministic fixture responses out of the test runner's stderr."""

        del format, args


@pytest.fixture
def local_http_server() -> Iterator[ThreadingHTTPServer]:
    """Own an ephemeral loopback server and join its thread after each test."""

    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalHttpHandler)
    server.daemon_threads = True
    stop_event = threading.Event()
    setattr(server, "stop_event", stop_event)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        yield server

    finally:
        stop_event.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

        assert not thread.is_alive(), (
            "The localhost probe fixture must join its owned server thread."
        )


def HttpLab(tmp_path: Path, server: ThreadingHTTPServer) -> ExternalTargetLab:
    """Connect a real bounded child-process probe to the fixture-owned loopback service."""

    manifest = copy.deepcopy(LoadTarget(REPOSITORY_ROOT).manifest)
    lab = ExternalTargetLab(REPOSITORY_ROOT, tmp_path, ExternalTarget(manifest))
    lab.port = server.server_address[1]

    return lab


def test_ExternalHttpProbeUsesRealLoopbackVersionAndRawEvidence(
    tmp_path: Path, local_http_server: ThreadingHTTPServer,
) -> None:
    """Exercise the actual child process, HTTP response, readiness, and evidence writer."""

    lab = HttpLab(tmp_path, local_http_server)
    lab.WaitUntilReady()
    observation = lab.observations[0]
    command = json.loads((tmp_path / "command-01.json").read_text())

    assert observation.status == 200 and not observation.error, (
        "The real loopback HTTP probe must satisfy the application version contract."
    )
    assert json.loads(observation.body)["version"] == "20.2.0", (
        "Raw HTTP body must preserve the actual fixture release."
    )
    assert command["returncode"] == 0 and command["duration_seconds"] >= 0, (
        "The shared command evidence writer must retain actual process outcome and duration."
    )


def test_ExternalHttpProbeNeverFollowsRedirects(
    tmp_path: Path, local_http_server: ThreadingHTTPServer,
) -> None:
    """Preserve a redirect response without contacting its external Location destination."""

    observation = HttpLab(tmp_path, local_http_server).Request("/redirect")

    assert observation.status == 302, (
        "Redirect responses must remain observations, never new targets."
    )


def test_ExternalHttpProbeRejectsOversizedResponse(
    tmp_path: Path, local_http_server: ThreadingHTTPServer,
) -> None:
    """Retain bounded response bytes and record an explicit overflow failure."""

    observation = HttpLab(tmp_path, local_http_server).Request("/overflow")

    assert len(observation.body) == 65537 and "body budget" in observation.error, (
        "HTTP probe must detect overflow after only one byte beyond its declared body limit."
    )


def test_ExternalHttpProbeEnforcesWallClockTimeoutAndPreservesOutcome(
    tmp_path: Path, local_http_server: ThreadingHTTPServer,
) -> None:
    """Kill a slow streamed-body probe even when individual socket reads would succeed."""

    lab = HttpLab(tmp_path, local_http_server)
    lab.target.manifest["budgets_seconds"]["request"] = 1
    observation = lab.Request("/slow")
    command = json.loads((tmp_path / "command-01.json").read_text())

    assert observation.timed_out and "wall-clock budget" in observation.error, (
        "An incomplete slowly streamed body must remain a timed-out HTTP observation."
    )
    assert command["timed_out"] and command["returncode"] == 124, (
        "Raw command evidence must preserve timeout state and its bounded-process exit code."
    )
    assert 0 <= command["duration_seconds"] < 2, (
        "A one-second request budget must actually bound I/O."
    )


@pytest.mark.parametrize(
    "port,path", [(0, "/"), (65536, "/"), (1, "https://remote"), (1, "//remote")],
)
def test_ExternalHttpProbeRejectsUnverifiedDestinations(port: int, path: str) -> None:
    """Reject invalid ports and nonlocal paths before opening a connection."""

    with pytest.raises(ValueError, match="loopback port"):
        ReadResponse(port, path)

    with pytest.raises(ValueError, match="exactly"):
        Main(())


def test_SharedCommandTimeoutPreservesPartialOutputAndDuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise timeout evidence normalization for inherited lifecycle execution."""

    def Timeout(*arguments: object, **options: object) -> None:
        """Simulate a subprocess timeout carrying actual partial binary output."""

        del arguments, options

        raise subprocess.TimeoutExpired(("fixture",), 1, output=b"partial", stderr=b"diagnostic")

    monkeypatch.setattr(subprocess, "run", Timeout)
    result = ComposeLab(REPOSITORY_ROOT, tmp_path).Run("fixture", timeout_seconds=1)

    assert result.stdout == "partial" and result.stderr == "diagnostic", (
        "A timed-out process must preserve its partial raw outputs in JSON-compatible text."
    )
    assert result.timed_out and result.duration_seconds >= 0, (
        "Raw timeout evidence must carry terminal state and measured duration."
    )
