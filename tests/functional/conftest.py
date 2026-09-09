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

from .scenarios import WEB_SAFE_HEALTH


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Preserve one raw container-lifecycle command result as functional evidence."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


class ComposeLab:
    """Own the lifecycle and raw evidence for the isolated synthetic lab."""

    def __init__(self, repository_root: Path, evidence_directory: Path) -> None:
        self._repository_root = repository_root
        self._evidence_directory = evidence_directory
        self._command_index = 0

    def start(self) -> None:
        """Start the target and prove its health contract before exposing it to tests."""
        self._require_success(
            self.compose("--profile", "lab", "up", "--build", "--wait", WEB_SAFE_HEALTH.target.compose_service),
            "Synthetic lab startup",
        )
        health = self.execute(
            WEB_SAFE_HEALTH.target.compose_service,
            "python",
            "-c",
            (
                "from urllib.request import urlopen; import json; "
                "response = urlopen('http://127.0.0.1:8080/health', timeout=1); "
                "print(json.dumps(json.load(response), sort_keys=True))"
            ),
            timeout_seconds=WEB_SAFE_HEALTH.timeout_seconds,
        )
        self._require_success(health, "Synthetic lab health check")

        if json.loads(health.stdout) != {"status": "ok", "target": "web-safe"}:
            raise RuntimeError("Synthetic lab health check returned an unexpected payload")

    def stop(self) -> CommandResult:
        """Stop and remove the lab even if a functional assertion has failed."""
        return self.compose("--profile", "lab", "down", "--volumes", "--remove-orphans")

    def compose(self, *arguments: str, timeout_seconds: int = 60) -> CommandResult:
        """Run one Compose command and preserve its raw output."""
        return self._run("docker", "compose", *arguments, timeout_seconds=timeout_seconds)

    def execute(
        self,
        service: str,
        *arguments: str,
        timeout_seconds: int,
    ) -> CommandResult:
        """Run a bounded command inside one declared synthetic target service."""
        return self.compose("exec", "-T", service, *arguments, timeout_seconds=timeout_seconds)

    def _run(self, *arguments: str, timeout_seconds: int) -> CommandResult:
        """Execute an argv list without a shell and write its raw evidence record."""
        try:
            completed = subprocess.run(
                arguments,
                cwd=self._repository_root,
                capture_output=True,
                check=False,
                shell=False,
                text=True,
                timeout=timeout_seconds,
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
                stdout=_decode_output(error.stdout),
                stderr=_decode_output(error.stderr),
                timed_out=True,
            )

        self._write_evidence(result)
        return result

    def _write_evidence(self, result: CommandResult) -> None:
        """Write one deterministic, local-only evidence record for diagnosis."""
        self._evidence_directory.mkdir(parents=True, exist_ok=True)
        self._command_index += 1
        record = self._evidence_directory / f"command-{self._command_index:02d}.json"
        record.write_text(json.dumps(asdict(result), indent=2, sort_keys=True), encoding="utf-8")

    @staticmethod
    def _require_success(result: CommandResult, action: str) -> None:
        """Fail with preserved command output instead of reporting a partial lifecycle as ready."""
        if result.returncode:
            detail = result.stderr.strip() or result.stdout.strip() or "no process output"
            raise RuntimeError(f"{action} failed with exit code {result.returncode}: {detail}")


@pytest.fixture(scope="session")
def functional_lab() -> Iterator[ComposeLab]:
    """Provide the health-checked lab and guarantee cleanup after the test session."""
    if not _docker_compose_available():
        pytest.skip("Docker Compose is required for repository functional tests")

    repository_root = Path(__file__).resolve().parents[2]
    lab = ComposeLab(repository_root, repository_root / "functional-evidence")
    try:
        lab.start()
    except RuntimeError as error:
        lab.stop()
        pytest.fail(str(error))

    try:
        yield lab
    finally:
        teardown = lab.stop()
        if teardown.returncode:
            pytest.fail(f"Synthetic lab cleanup failed with exit code {teardown.returncode}")


def _docker_compose_available() -> bool:
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


def _decode_output(output: str | bytes | None) -> str:
    """Normalize timeout output so it remains valid JSON evidence."""
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode(errors="replace")
    return output
