"""Black-box functional contract for the first repository-owned target."""

from __future__ import annotations

import json

from . import conftest
from .conftest import ComposeLab
from .scenarios import WEB_SAFE_HEALTH


def test_web_safe_scenario_declares_a_complete_contract():
    """Keep the M1 scenario metadata complete before scanner scenarios are added."""
    scenario = WEB_SAFE_HEALTH

    assert scenario.identifier == "web-safe.health"
    assert scenario.target.provenance == "first-party:labs/targets/web-safe"
    assert scenario.target.version == "1"
    assert scenario.required_capabilities == ("docker.compose", "http.get")
    assert scenario.setup
    assert scenario.health_check
    assert scenario.assessment_command == ("GET", "/health")
    assert scenario.assessment_profile == "safe"
    assert scenario.expected_observations
    assert scenario.expected_findings == ()
    assert scenario.timeout_seconds > 0
    assert scenario.cleanup


def test_web_safe_health_contract(functional_lab: ComposeLab):
    """Exercise the target through the fixture-owned isolated container lifecycle."""
    result = functional_lab.execute(
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
    assert json.loads(result.stdout) == {"status": "ok", "target": "web-safe"}


def test_non_linux_runner_does_not_advertise_container_test_capability(monkeypatch):
    """Keep the Linux-only target from running on unsupported CI runners."""
    monkeypatch.setattr(conftest.platform, "system", lambda: "Windows")

    assert not conftest._docker_compose_available()
