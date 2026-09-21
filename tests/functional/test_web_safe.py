"""Black-box functional contract for the first repository-owned target."""

from __future__ import annotations

import json

import pytest

from . import conftest
from .conftest import ComposeLab
from .scenarios import WEB_SAFE_HEALTH

pytestmark = pytest.mark.serial


def test_WebSafeScenarioDeclaresACompleteContract():
    """Keep the M1 scenario metadata complete before scanner scenarios are added."""

    scenario = WEB_SAFE_HEALTH

    assert scenario.identifier == "web-safe.health", (
        "web safe scenario declares a complete contract invariant failed."
    )
    assert scenario.target.provenance == "first-party:labs/targets/web-safe", (
        "web safe scenario declares a complete contract invariant failed."
    )
    assert scenario.target.version == "1", (
        "web safe scenario declares a complete contract invariant failed."
    )
    assert scenario.required_capabilities == ("docker.compose", "http.get"), (
        "web safe scenario declares a complete contract invariant failed."
    )
    assert scenario.setup, "web safe scenario declares a complete contract invariant failed."
    assert scenario.health_check, "web safe scenario declares a complete contract invariant failed."
    assert scenario.assessment_command == ("GET", "/health"), (
        "web safe scenario declares a complete contract invariant failed."
    )
    assert scenario.assessment_profile == "safe", (
        "web safe scenario declares a complete contract invariant failed."
    )
    assert scenario.expected_observations, (
        "web safe scenario declares a complete contract invariant failed."
    )
    assert scenario.expected_findings == (), (
        "web safe scenario declares a complete contract invariant failed."
    )
    assert scenario.timeout_seconds > 0, (
        "web safe scenario declares a complete contract invariant failed."
    )
    assert scenario.cleanup, "web safe scenario declares a complete contract invariant failed."


def test_WebSafeHealthContract(functional_lab: ComposeLab):
    """Exercise the target through the fixture-owned isolated container lifecycle."""

    result = functional_lab.Execute(
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

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"status": "ok", "target": "web-safe"}, (
        "web safe health contract invariant failed."
    )


def test_NonLinuxRunnerDoesNotAdvertiseContainerTestCapability(monkeypatch):
    """Keep the Linux-only target from running on unsupported CI runners."""

    monkeypatch.setattr(conftest.platform, "system", lambda: "Windows")

    assert not conftest.DockerComposeAvailable(), (
        "non linux runner does not advertise container test capability invariant failed."
    )
