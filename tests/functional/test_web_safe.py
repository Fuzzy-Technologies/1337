"""Black-box functional contract for the first repository-owned target."""

from __future__ import annotations

import json

import pytest

from . import conftest
from .conftest import ComposeLab
from .scenarios import WEBSAFEHEALTH

pytestmark = pytest.mark.serial


def test_WebSafeScenarioDeclaresACompleteContract():
    """Keep the M1 scenario metadata complete before scanner scenarios are added."""

    scenario = WEBSAFEHEALTH

    assert scenario.identifier == "web-safe.health", (
        "web safe scenario declares a complete contract invariant failed."
    )
    assert scenario.target.provenance == "first-party:labs/targets/web-safe", (
        "web safe scenario declares a complete contract invariant failed."
    )
    assert scenario.target.version == "1", (
        "web safe scenario declares a complete contract invariant failed."
    )
    assert scenario.requiredCapabilities == ("docker.compose", "http.get"), (
        "web safe scenario declares a complete contract invariant failed."
    )
    assert scenario.setup, "web safe scenario declares a complete contract invariant failed."
    assert scenario.healthCheck, "web safe scenario declares a complete contract invariant failed."
    assert scenario.assessmentCommand == ("GET", "/health"), (
        "web safe scenario declares a complete contract invariant failed."
    )
    assert scenario.assessmentProfile == "safe", (
        "web safe scenario declares a complete contract invariant failed."
    )
    assert scenario.expectedObservations, (
        "web safe scenario declares a complete contract invariant failed."
    )
    assert scenario.expectedFindings == (), (
        "web safe scenario declares a complete contract invariant failed."
    )
    assert scenario.timeoutSeconds > 0, (
        "web safe scenario declares a complete contract invariant failed."
    )
    assert scenario.cleanup, "web safe scenario declares a complete contract invariant failed."


def test_WebSafeHealthContract(functionalLab: ComposeLab):
    """Exercise the target through the fixture-owned isolated container lifecycle."""

    result = functionalLab.Execute(
        WEBSAFEHEALTH.target.composeService,
        "python",
        "-c",
        (
            "from urllib.request import urlopen; import json; "
            "response = urlopen('http://127.0.0.1:8080/health', timeout=1); "
            "print(json.dumps(json.load(response), sort_keys=True))"
        ),
        timeoutSeconds=WEBSAFEHEALTH.timeoutSeconds,
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
