"""Machine-readable contracts for repository-owned functional scenarios."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TargetReference:
    """Identify the exact repository-owned target used by a functional scenario."""

    identifier: str
    provenance: str
    version: str
    composeService: str


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
    requiredCapabilities: tuple[str, ...]
    setup: tuple[str, ...]
    healthCheck: str
    assessmentCommand: tuple[str, ...]
    assessmentProfile: str
    expectedObservations: tuple[ExpectedObservation, ...]
    expectedFindings: tuple[str, ...]
    timeoutSeconds: int
    cleanup: tuple[str, ...]


WEBSAFEHEALTH = FunctionalScenario(
    identifier="web-safe.health",
    target=TargetReference(
        identifier="web-safe",
        provenance="first-party:labs/targets/web-safe",
        version="1",
        composeService="lab-web-safe",
    ),
    requiredCapabilities=("docker.compose", "http.get"),
    setup=("docker compose --profile lab up --build --wait lab-web-safe",),
    healthCheck="GET /health returns the deterministic web-safe health payload.",
    assessmentCommand=("GET", "/health"),
    assessmentProfile="safe",
    expectedObservations=(
        ExpectedObservation(name="status", value="ok"),
        ExpectedObservation(name="target", value="web-safe"),
    ),
    expectedFindings=(),
    timeoutSeconds=60,
    cleanup=("docker compose --profile lab down --volumes --remove-orphans",),
)

WEBMICROTARGETCONTRACT = FunctionalScenario(
    identifier="web-micro.contract",
    target=TargetReference(
        identifier="web-micro",
        provenance="first-party:labs/targets/web-micro",
        version="1",
        composeService="lab-web-micro",
    ),
    requiredCapabilities=("docker.compose", "http.get", "http.post"),
    setup=("docker compose --profile lab up --build --wait lab-web-micro",),
    healthCheck="GET /health returns the deterministic web-micro health payload.",
    assessmentCommand=("GET", "/", "/redirect", "/form", "/canary/command-execution"),
    assessmentProfile="safe",
    expectedObservations=(
        ExpectedObservation(name="route.discovery", value="/catalog"),
        ExpectedObservation(name="route.catalog", value="GET /catalog"),
        ExpectedObservation(name="route.redirect", value="/redirect -> /catalog"),
        ExpectedObservation(name="route.form", value="POST /submit"),
        ExpectedObservation(name="header.lab", value="X-1337-Lab: web-micro"),
        ExpectedObservation(name="input.json", value="POST /json"),
        ExpectedObservation(name="input.upload", value="POST /upload"),
        ExpectedObservation(name="status.matrix", value="GET /status/{400,401,403,404,500}"),
    ),
    expectedFindings=(
        "simulated.command-execution",
        "simulated.file-inclusion",
        "simulated.ssrf",
        "simulated.upload-validation",
    ),
    timeoutSeconds=60,
    cleanup=("docker compose --profile lab down --volumes --remove-orphans",),
)
