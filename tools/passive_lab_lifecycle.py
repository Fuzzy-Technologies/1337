# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify only isolated safe-target startup, health and complete project teardown."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any

HEALTH_COMMAND = (
    "import json; from urllib.request import urlopen; "
    "response = urlopen('http://127.0.0.1:8080/health', timeout=1); "
    "assert response.status == 200; "
    "assert json.load(response) == {'status': 'ok', 'target': 'web-safe'}"
)


def VerifyLifecycle(project: str, receipt: Path) -> None:
    """Start one safe service, verify its actual isolation and health, then require its absence.

    Args:
        project: Unique dedicated Compose project owning this one benign service lifecycle.
        receipt: Explicit destination for original command outcomes and observed cleanup proof.

    Raises:
        ValueError: Project ownership, service isolation, health or resource absence differs.
        RuntimeError: A required Docker lifecycle command returns a nonzero exit status.
        subprocess.TimeoutExpired: An actual bounded lifecycle command does not finish in time.
    """

    if re.fullmatch(r"passive-health-[a-z0-9-]{1,64}", project) is None:
        raise ValueError("A dedicated passive-health project name is required")

    compose = ["docker", "compose", "--project-name", project, "--file", "compose.yaml"]
    evidence: dict[str, Any] = {"project": project, "status": "failed", "commands": []}
    receipt.parent.mkdir(parents=True, exist_ok=True)

    def Command(arguments: list[str]) -> str:
        """Retain bounded command outcomes and refuse every nonzero exit."""

        result = subprocess.run(arguments, capture_output=True, text=True, timeout=240, check=False)
        evidence["commands"].append({"argv": arguments, "exit_code": result.returncode})

        if result.returncode:
            raise RuntimeError("A passive lifecycle command failed")

        return result.stdout.strip()

    try:
        # The unique Compose project owns both cleanup and the network under inspection.
        Command([*compose, "--profile", "lab", "up", "--build", "--wait", "lab-web-safe"])
        container = Command([*compose, "ps", "--quiet", "lab-web-safe"])

        if re.fullmatch(r"[a-f0-9]{64}", container) is None:
            raise ValueError("Require exactly one safe-target container")

        details, = json.loads(Command(["docker", "inspect", container]))
        configuration = details["HostConfig"]

        if not (
            details["State"]["Running"] is True
            and details["State"]["Health"]["Status"] == "healthy"
            and details["Config"]["Labels"]["com.docker.compose.project"] == project
            and details["Config"]["Labels"]["com.docker.compose.service"] == "lab-web-safe"
            and configuration["ReadonlyRootfs"] is True
            and configuration["Privileged"] is False
            and "ALL" in configuration["CapDrop"]
            and not configuration["PortBindings"]
        ):
            raise ValueError("The safe target must be healthy, read-only and unexposed")

        networks = details["NetworkSettings"]["Networks"]

        if len(networks) != 1:
            raise ValueError("Require one isolated synthetic network")

        network, = json.loads(Command(["docker", "network", "inspect", next(iter(networks))]))

        if network["Internal"] is not True:
            raise ValueError("The safe target network must be internal")

        Command([*compose, "exec", "-T", "lab-web-safe", "python", "-c", HEALTH_COMMAND])
        evidence.update({"container_id": container, "healthy": True, "isolated": True})

    finally:
        try:
            Command([*compose, "--profile", "lab", "down", "--volumes", "--remove-orphans"])
            containers = Command([
                "docker", "ps", "--all", "--quiet", "--filter",
                f"label=com.docker.compose.project={project}",
            ])
            networks = Command([
                "docker", "network", "ls", "--quiet", "--filter",
                f"label=com.docker.compose.project={project}",
            ])

            if containers or networks:
                raise ValueError("Passive lifecycle teardown left project resources")

            evidence["cleanup_verified"] = True

            if evidence.get("healthy") is True:
                evidence["status"] = "completed"

        finally:
            receipt.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")


def Main() -> None:
    """Require an explicit project owner and evidence path for one benign lifecycle."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--receipt", required=True, type=Path)
    arguments = parser.parse_args()
    VerifyLifecycle(arguments.project, arguments.receipt)


if __name__ == "__main__":
    Main()
