"""Pytest-owned lifecycle fixtures for repository-defined functional targets."""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path

import pytest

from .scenarios import WEBMICROTARGETCONTRACT, WEBSAFEHEALTH, FunctionalScenario


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Preserve one raw container-lifecycle command result as functional evidence."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timedOut: bool = False


class ComposeLab:
    """Own the lifecycle and raw evidence for the isolated synthetic lab."""

    def __init__(self, repositoryRoot: Path, evidenceDirectory: Path) -> None:
        """Provide deterministic test support for   init  ."""

        self.repositoryRoot = repositoryRoot
        self.evidenceDirectory = evidenceDirectory
        self.commandIndex = 0

    def Start(self, scenario: FunctionalScenario) -> None:
        """Start the target and prove its health contract before exposing it to tests."""

        self.RequireSuccess(
            self.Compose(
                "--profile",
                "lab",
                "up",
                "--build",
                "--wait",
                scenario.target.composeService,
            ),
            "Synthetic lab startup",
        )
        health = self.Execute(
            scenario.target.composeService,
            "python",
            "-c",
            (
                "from urllib.request import urlopen; import json; "
                "response = urlopen('http://127.0.0.1:8080/health', timeout=1); "
                "print(json.dumps(json.load(response), sort_keys=True))"
            ),
            timeoutSeconds=scenario.timeoutSeconds,
        )
        self.RequireSuccess(health, "Synthetic lab health check")

        expectedPayload = {"status": "ok", "target": scenario.target.identifier}
        if json.loads(health.stdout) != expectedPayload:
            raise RuntimeError("Synthetic lab health check returned an unexpected payload")

    def Stop(self) -> CommandResult:
        """Stop and remove the lab even if a functional assertion has failed."""

        return self.Compose("--profile", "lab", "down", "--volumes", "--remove-orphans")

    def Compose(self, *arguments: str, timeoutSeconds: int = 60) -> CommandResult:
        """Run one Compose command and preserve its raw output."""

        return self.Run("docker", "compose", *arguments, timeoutSeconds=timeoutSeconds)

    def Execute(
        self,
        service: str,
        *arguments: str,
        timeoutSeconds: int,
    ) -> CommandResult:
        """Run a bounded command inside one declared synthetic target service."""

        return self.Compose("exec", "-T", service, *arguments, timeoutSeconds=timeoutSeconds)

    def Run(self, *arguments: str, timeoutSeconds: int) -> CommandResult:
        """Execute an argv list without a shell and write its raw evidence record."""

        try:
            completed = subprocess.run(
                arguments,
                cwd=self.repositoryRoot,
                capture_output=True,
                check=False,
                shell=False,
                text=True,
                timeout=timeoutSeconds,
            )
            result = CommandResult(
                argv=tuple(arguments),
                returncode=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
            )

        except subprocess.TimeoutExpired as error:
            result = CommandResult(
                argv=tuple(arguments),
                returncode=124,
                stdout=DecodeOutput(error.stdout),
                stderr=DecodeOutput(error.stderr),
                timedOut=True,
            )

        self.WriteEvidence(result)
        return result

    def WriteEvidence(self, result: CommandResult) -> None:
        """Write one deterministic, local-only evidence record for diagnosis."""

        self.evidenceDirectory.mkdir(parents=True, exist_ok=True)
        self.commandIndex += 1
        record = self.evidenceDirectory / f"command-{self.commandIndex:02d}.json"
        record.write_text(json.dumps(asdict(result), indent=2, sort_keys=True), encoding="utf-8")

    @staticmethod
    def RequireSuccess(result: CommandResult, action: str) -> None:
        """Fail with preserved command output instead of reporting a partial lifecycle as ready."""

        if result.returncode:
            detail = result.stderr.strip() or result.stdout.strip() or "no process output"
            raise RuntimeError(f"{action} failed with exit code {result.returncode}: {detail}")


@pytest.fixture(scope="session", name="functionalLab")
def FunctionalLab() -> Iterator[ComposeLab]:
    """Provide the health-checked lab and guarantee cleanup after the test session."""

    yield from StartFunctionalLab(WEBSAFEHEALTH)


@pytest.fixture(scope="session", name="microTargetLab")
def MicroTargetLab() -> Iterator[ComposeLab]:
    """Provide the health-checked known-answer target and guarantee cleanup."""

    yield from StartFunctionalLab(WEBMICROTARGETCONTRACT)


def StartFunctionalLab(scenario: FunctionalScenario) -> Iterator[ComposeLab]:
    """Start one declared target through the shared fixture-owned lifecycle."""

    if not DockerComposeAvailable():
        pytest.skip("Docker Compose is required for repository functional tests")

    repositoryRoot = Path(__file__).resolve().parents[2]
    lab = ComposeLab(repositoryRoot, repositoryRoot / "functional-evidence")
    try:
        lab.Start(scenario)

    except RuntimeError as error:
        lab.Stop()
        pytest.fail(str(error))

    try:
        yield lab

    finally:
        teardown = lab.Stop()
        if teardown.returncode:
            pytest.fail(f"Synthetic lab cleanup failed with exit code {teardown.returncode}")


def DockerComposeAvailable() -> bool:
    """Return whether Docker Compose can be used in the current local or CI environment."""

    if platform.system() != "Linux":
        return False

    if shutil.which("docker") is None:
        return False

    result = subprocess.run(
        ("docker", "compose", "version"),
        capture_output=True,
        check=False,
        shell=False,
        text=True,
    )
    return result.returncode == 0


def DecodeOutput(output: str | bytes | None) -> str:
    """Normalize timeout output so it remains valid JSON evidence."""

    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode(errors="replace")
    return output
