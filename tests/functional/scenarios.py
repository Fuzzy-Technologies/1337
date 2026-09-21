"""Machine-readable contracts for repository-owned functional scenarios."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TargetReference:
    """Identify the exact repository-owned target used by a functional scenario."""

    identifier: str
    provenance: str
    version: str
    compose_service: str


@dataclass(frozen=True, slots=True)
class ExpectedObservation:
    """Describe one deterministic observation required by a scenario."""

    name: str
    value: str


@dataclass(frozen=True, slots=True)
class FunctionalScenario:
    """Declare setup, assessment, oracle, and cleanup requirements for one scenario."""

    identifier: str
    target: TargetReference
    required_capabilities: tuple[str, ...]
    setup: tuple[str, ...]
    health_check: str
    assessment_command: tuple[str, ...]
    assessment_profile: str
    expected_observations: tuple[ExpectedObservation, ...]
    expected_findings: tuple[str, ...]
    timeout_seconds: int
    cleanup: tuple[str, ...]


WEB_SAFE_HEALTH = FunctionalScenario(
    identifier="web-safe.health",
    target=TargetReference(
        identifier="web-safe",
        provenance="first-party:labs/targets/web-safe",
        version="1",
        compose_service="lab-web-safe",
    ),
    required_capabilities=("docker.compose", "http.get"),
    setup=("docker compose --profile lab up --build --wait lab-web-safe",),
    health_check="GET /health returns the deterministic web-safe health payload.",
    assessment_command=("GET", "/health"),
    assessment_profile="safe",
    expected_observations=(
        ExpectedObservation(name="status", value="ok"),
        ExpectedObservation(name="target", value="web-safe"),
    ),
    expected_findings=(),
    timeout_seconds=60,
    cleanup=("docker compose --profile lab down --volumes --remove-orphans",),
)

WEB_MICRO_TARGET_CONTRACT = FunctionalScenario(
    identifier="web-micro.contract",
    target=TargetReference(
        identifier="web-micro",
        provenance="first-party:labs/targets/web-micro",
        version="1",
        compose_service="lab-web-micro",
    ),
    required_capabilities=("docker.compose", "http.get", "http.post"),
    setup=("docker compose --profile lab up --build --wait lab-web-micro",),
    health_check="GET /health returns the deterministic web-micro health payload.",
    assessment_command=("GET", "/", "/redirect", "/form", "/canary/command-execution"),
    assessment_profile="safe",
    expected_observations=(
        ExpectedObservation(name="route.discovery", value="/catalog"),
        ExpectedObservation(name="route.catalog", value="GET /catalog"),
        ExpectedObservation(name="route.redirect", value="/redirect -> /catalog"),
        ExpectedObservation(name="route.form", value="POST /submit"),
        ExpectedObservation(name="header.lab", value="X-1337-Lab: web-micro"),
        ExpectedObservation(name="input.json", value="POST /json"),
        ExpectedObservation(name="input.upload", value="POST /upload"),
        ExpectedObservation(name="status.matrix", value="GET /status/{400,401,403,404,500}"),
    ),
    expected_findings=(
        "simulated.command-execution",
        "simulated.file-inclusion",
        "simulated.ssrf",
        "simulated.upload-validation",
    ),
    timeout_seconds=60,
    cleanup=("docker compose --profile lab down --volumes --remove-orphans",),
)
