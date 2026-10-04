# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bounded, opt-in lifecycle and provenance for the pinned external target pack."""

from __future__ import annotations

import json
import re
import sys
import time
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from jsonschema import Draft202012Validator

from .conftest import CommandResult, ComposeLab

IMAGE_METADATA_FORMAT = (
    '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}},'
    '"repo_digests":{{json .RepoDigests}}}'
)
CONTAINER_METADATA_FORMAT = (
    '{"image_ref":{{json .Config.Image}},"image_id":{{json .Image}},'
    '"running":{{json .State.Running}}}'
)
ALLOWED_SERVICE_FIELDS = {
    "image", "profiles", "pull_policy", "init", "user", "restart", "cpus", "mem_limit",
    "pids_limit", "cap_drop", "security_opt", "ports", "networks", "healthcheck",
}
NEUTRAL_COMPOSE_DEFAULTS = {"command": None, "entrypoint": None}


@dataclass(frozen=True, slots=True)
class ExternalTarget:
    """Expose only validated pinned target metadata and bounded lifecycle budgets."""

    manifest: dict[str, Any]

    @property
    def ImageReference(self) -> str:
        """Return the readable tag coupled to its immutable registry index digest."""

        return (
            f"{self.manifest['repository']}:{self.manifest['tag']}"
            f"@{self.manifest['index_digest']}"
        )

    @property
    def Service(self) -> str:
        """Return the declared service in the standalone external Compose definition."""

        return self.manifest["compose_service"]

    def Budget(self, operation: str) -> int:
        """Return the validated timeout in seconds for one lifecycle operation."""

        return self.manifest["budgets_seconds"][operation]


@dataclass(frozen=True, slots=True)
class HttpObservation:
    """Retain the exact bounded loopback response or transport failure."""

    host: str
    port: int
    path: str
    status: int | None
    headers: tuple[tuple[str, str], ...]
    body: str
    error: str
    timed_out: bool
    duration_seconds: float


def LoadTarget(repository_root: Path) -> ExternalTarget:
    """Validate the external pack schema before any Docker operation occurs."""

    pack_directory = repository_root / "labs" / "external"
    schema = json.loads((pack_directory / "target.schema.json").read_text(encoding="utf-8"))
    manifest = json.loads((pack_directory / "juice-shop.v1.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(manifest)

    if (
        manifest["tag"] != "v" + manifest["version"]
        or not manifest["release_url"].endswith("/" + manifest["tag"])
        or not manifest["registry_url"].endswith("/" + manifest["tag"])
    ):
        raise ValueError("External release, registry provenance, tag, and version must agree")

    return ExternalTarget(manifest)


def IsPackEnabled(selection: str | None) -> bool:
    """Accept only the explicit known pack, leaving ordinary tests fully offline."""

    if selection is None or selection == "":
        return False

    if selection != "juice-shop":
        raise ValueError("FUZZY1337_EXTERNAL_TARGETS must be unset or exactly 'juice-shop'")

    return True


def ValidateCompose(configuration: dict[str, Any], target: ExternalTarget) -> None:
    """Reject any widened target isolation or mismatch with the pinned manifest.

    Accept only observed neutral Compose defaults: null command/entrypoint and
    an exact decimal-string memory limit. Other overrides remain fail-closed.
    """

    services = configuration.get("services", {})
    networks = configuration.get("networks", {})

    if set(services) != {target.Service} or set(networks) != {"external-targets"}:
        raise RuntimeError("External pack must contain exactly its declared service and network")

    service = services[target.Service]
    network = networks["external-targets"]
    limits = target.manifest["resource_limits"]
    expected_memory_bytes = limits["memory_mib"] * 1024 * 1024
    memory_limit = service.get("mem_limit")
    memory_limit_valid = (
        type(memory_limit) in (int, str)
        and memory_limit in (expected_memory_bytes, str(expected_memory_bytes))
    )
    ports = service.get("ports", [])
    expected_port = {
        "target": target.manifest["http_port"],
        "published": "0",
        "host_ip": "127.0.0.1",
        "protocol": "tcp",
    }
    port_valid = (
        len(ports) == 1
        and all(ports[0].get(key) == value for key, value in expected_port.items())
    )
    expected_health_test = [
        "CMD", "/nodejs/bin/node", "-e",
        "fetch('http://127.0.0.1:3000/rest/admin/application-version').then(async r => { "
        "const b = await r.json(); process.exit(r.status === 200 && b.version === '"
        + target.manifest["version"] + "' ? 0 : 1); }).catch(() => process.exit(1))",
    ]
    normalized_defaults_valid = all(
        field in NEUTRAL_COMPOSE_DEFAULTS and service[field] is NEUTRAL_COMPOSE_DEFAULTS[field]
        for field in set(service) - ALLOWED_SERVICE_FIELDS
    )
    valid = (
        service.get("image") == target.ImageReference
        and service.get("profiles") == [target.manifest["compose_profile"]]
        and service.get("pull_policy") == "never"
        and service.get("init") is True
        and service.get("user") == "65532:0"
        and service.get("restart") == "no"
        and not service.get("privileged", False)
        and service.get("cap_drop") == ["ALL"]
        and service.get("security_opt") == ["no-new-privileges:true"]
        and set(service.get("networks", {})) == {"external-targets"}
        and network.get("internal") is True
        and not network.get("external", False)
        and network.get("driver") == "bridge"
        and type(service.get("cpus")) in (int, float)
        and service.get("cpus") == limits["cpus"]
        and memory_limit_valid
        and service.get("pids_limit") == limits["pids"]
        and service.get("healthcheck", {}).get("test") == expected_health_test
        and normalized_defaults_valid
        and port_valid
    )

    if not valid:
        raise RuntimeError("External pack isolation, resources, health, or image pin changed")


class ExternalTargetLab(ComposeLab):
    """Reuse raw Compose evidence while owning one isolated external project."""

    def __init__(
        self,
        repository_root: Path,
        evidence_directory: Path,
        target: ExternalTarget,
    ) -> None:
        """Create a unique project without starting Docker or contacting a target."""

        super().__init__(repository_root, evidence_directory)
        self.target = target
        self.repository_root = repository_root
        self.evidence_directory = evidence_directory
        self.project_name = f"fuzzy-1337-external-{uuid4().hex[:12]}"
        self.port = 0
        self.commands: list[CommandResult] = []
        self.observations: list[HttpObservation] = []
        self.provenance: dict[str, Any] = {}

    def Compose(self, *arguments: str, timeout_seconds: int | None = None) -> CommandResult:
        """Address only this fixture's explicit Compose file, profile, and project."""

        return self.Run(
            "docker", "compose", "--file", str(self.repository_root / "labs/external/compose.yaml"),
            "--project-name", self.project_name,
            "--profile", self.target.manifest["compose_profile"],
            *arguments, timeout_seconds=(
                self.target.Budget("command") if timeout_seconds is None else timeout_seconds
            ),
        )

    def WriteEvidence(self, result: CommandResult) -> None:
        """Preserve each inherited raw command record and retain it for the report."""

        super().WriteEvidence(result)
        self.commands.append(result)

    def Start(self) -> None:
        """Validate, pull, start, attribute, and health-check the pinned application."""

        configuration = self.Compose("config", "--format", "json")
        self.RequireSuccess(configuration, "External Compose configuration")
        ValidateCompose(json.loads(configuration.stdout), self.target)
        self.RequireSuccess(
            self.Compose(
                "pull", "--policy", "always", self.target.Service,
                timeout_seconds=self.target.Budget("pull"),
            ),
            "Pinned external image pull",
        )
        self.RequireSuccess(
            self.Compose(
                "up", "--wait", "--wait-timeout", str(self.target.Budget("startup")),
                "--no-build", "--pull", "never", self.target.Service,
                timeout_seconds=self.target.Budget("startup") + 10,
            ),
            "External target startup",
        )
        self.CaptureProvenance()
        published = self.Compose(
            "port", self.target.Service, str(self.target.manifest["http_port"]),
        )
        self.RequireSuccess(published, "External loopback port lookup")
        match = re.fullmatch(r"127\.0\.0\.1:([0-9]+)", published.stdout.strip())

        if match is None or not 1 <= int(match.group(1)) <= 65535:
            raise RuntimeError("External target port is not an ephemeral IPv4 loopback binding")

        self.port = int(match.group(1))
        self.WaitUntilReady()

    def CaptureProvenance(self) -> None:
        """Cross-check the running image and actual platform against the pinned OCI index."""

        container = self.Compose("ps", "--quiet", self.target.Service)
        self.RequireSuccess(container, "External container lookup")
        container_id = container.stdout.strip()

        if re.fullmatch(r"[a-f0-9]{12,64}", container_id) is None:
            raise RuntimeError("External target must resolve to exactly one container ID")

        command_budget = self.target.Budget("command")
        running = self.Run(
            "docker", "inspect", "--format", CONTAINER_METADATA_FORMAT, container_id,
            timeout_seconds=command_budget,
        )
        image = self.Run(
            "docker", "image", "inspect", "--format", IMAGE_METADATA_FORMAT,
            self.target.ImageReference, timeout_seconds=command_budget,
        )
        index = self.Run(
            "docker", "manifest", "inspect", self.target.ImageReference,
            timeout_seconds=command_budget,
        )

        for result in (running, image, index):
            self.RequireSuccess(result, "External image provenance lookup")

        running_data = json.loads(running.stdout)
        image_data = json.loads(image.stdout)
        index_data = json.loads(index.stdout)
        platform = f"{image_data.get('os')}/{image_data.get('architecture')}"
        digest = self.target.manifest["platform_digests"].get(platform)
        matches = [
            manifest["digest"] for manifest in index_data.get("manifests", [])
            if manifest.get("platform", {}).get("os") == image_data.get("os")
            and manifest.get("platform", {}).get("architecture") == image_data.get("architecture")
        ]
        accepted_digests = {self.target.manifest["index_digest"], digest}
        repository = self.target.manifest["repository"]
        repo_digests = image_data.get("repo_digests") or []
        attributable = any(
            reference == f"{repository}@{accepted}" for reference in repo_digests
            for accepted in accepted_digests if accepted is not None
        )

        if (
            running_data.get("running") is not True
            or running_data.get("image_ref") != self.target.ImageReference
            or running_data.get("image_id") != image_data.get("id")
            or digest is None or matches != [digest] or not attributable
        ):
            raise RuntimeError(
                "Running external image provenance does not match its pinned platform"
            )

        self.provenance = {
            "target": self.target.manifest,
            "project_name": self.project_name,
            "container_id": container_id,
            "container": running_data,
            "image": image_data,
            "platform": platform,
            "platform_manifest_digest": digest,
            "registry_index": index_data,
        }
        self.evidence_directory.mkdir(parents=True, exist_ok=True)
        (self.evidence_directory / "provenance.json").write_text(
            json.dumps(self.provenance, indent=2, sort_keys=True), encoding="utf-8",
        )

    def Request(self, path: str, timeout_seconds: float | None = None) -> HttpObservation:
        """Read a bounded response from the verified loopback port without redirects."""

        if not self.port or not path.startswith("/") or path.startswith("//"):
            raise ValueError("External HTTP probes require a verified loopback port and local path")

        budget = float(self.target.Budget("request"))

        if timeout_seconds is not None:
            budget = min(budget, timeout_seconds)

        if budget <= 0:
            raise ValueError("External HTTP probe must have a positive wall-clock budget")

        result = self.Run(
            sys.executable, str(self.repository_root / "tests/functional/external_http_probe.py"),
            str(self.port), path, timeout_seconds=budget,
        )
        status = None
        headers: tuple[tuple[str, str], ...] = ()
        body = ""
        error = result.stderr if result.returncode else ""

        if result.timed_out:
            error = "HTTP request exceeded its subprocess wall-clock budget"

        elif result.returncode == 0:
            payload = json.loads(result.stdout)
            status = payload["status"]
            headers = tuple(tuple(pair) for pair in payload["headers"])
            body = payload["body"]
            error = payload["error"]

        observation = HttpObservation(
            "127.0.0.1", self.port, path, status, headers, body, error,
            result.timed_out, result.duration_seconds,
        )
        self.observations.append(observation)
        self.evidence_directory.mkdir(parents=True, exist_ok=True)
        (self.evidence_directory / f"request-{len(self.observations):03d}.json").write_text(
            json.dumps(asdict(observation), indent=2, sort_keys=True), encoding="utf-8",
        )

        return observation

    def WaitUntilReady(self) -> None:
        """Require the exact release JSON, failing wrong versions without retrying them."""

        deadline = time.monotonic() + self.target.Budget("health")

        remaining = deadline - time.monotonic()

        while remaining > 0:
            observation = self.Request("/rest/admin/application-version", timeout_seconds=remaining)

            if observation.status == 200 and not observation.error:
                try:
                    payload = json.loads(observation.body)

                except json.JSONDecodeError as error:
                    raise RuntimeError("External version endpoint returned invalid JSON") from error

                if (
                    not isinstance(payload, dict)
                    or payload.get("version") != self.target.manifest["version"]
                ):
                    raise RuntimeError(
                        "External application version does not match its pinned release"
                    )

                return

            remaining = deadline - time.monotonic()

            if remaining > 0:
                time.sleep(min(0.25, remaining))

            remaining = deadline - time.monotonic()

        raise RuntimeError("External target did not satisfy its bounded HTTP readiness contract")

    def Stop(self, profile: str = "") -> CommandResult:
        """Bound cleanup and verify that no container remains in this unique project."""

        del profile
        try:
            self.Compose("logs", "--no-color", "--tail", "200", timeout_seconds=15)

        finally:
            try:
                result = self.Compose(
                    "down", "--volumes", "--remove-orphans", "--timeout", "10",
                    timeout_seconds=self.target.Budget("cleanup"),
                )
                self.RequireSuccess(result, "External target cleanup")

            finally:
                remaining = self.Compose("ps", "--all", "--quiet")
                self.RequireSuccess(remaining, "External cleanup verification")

                if remaining.stdout.strip():
                    raise RuntimeError(
                        "External cleanup left containers in its fixture-owned project"
                    )

        return result


def OwnExternalTarget(lab: ExternalTargetLab) -> Iterator[ExternalTargetLab]:
    """Guarantee bounded teardown after startup failure and consumer exceptions."""

    try:
        lab.Start()

        yield lab

    finally:
        lab.Stop()
