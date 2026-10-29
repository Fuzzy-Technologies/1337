# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Own six fresh finite application cases after genuine immutable-image no-HOME prerequisites."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path

from .conftest import CommandResult
from .external_benchmark import BuildComparison, ValidateObservation
from .external_native_runner import StrictJson, WriteJson
from .external_nuclei_application import CaseSelection
from .external_nuclei_host import (
    OWNER_LABEL,
    AdmitContainer,
    AdmitTermination,
    Canonical,
    ContainerProjection,
    PrerequisiteHost,
)
from .external_nuclei_image import PrerequisiteArguments
from .external_nuclei_observation import BindApplicationBundle, Observation
from .external_nuclei_runner import PATHS, TRACKS
from .external_targets import ExternalTargetLab, LoadTarget, OwnExternalTarget

SELECTION = "FUZZY1337_EXTERNAL_NUCLEI_BENCHMARK"


def Enabled(selection: str | None) -> bool:
    """Require the finite Juice Shop selection before discovering host tooling or target state."""

    if selection is None or selection == "":
        return False

    if selection != "juice-shop":
        raise ValueError("Nuclei comparison requires the explicit juice-shop selection")

    return True


def ApplicationCommand(track: str, path: str, target: str, owner: str) -> tuple[str, ...]:
    """Construct the only admitted image application selection without arbitrary URLs or flags."""

    CaseSelection(track, path, target, owner)

    return ("--track", track, "--path", path, "--target-instance", target, "--owner-token", owner)


def ApplicationArguments(name: str, image: str, target: str, track: str, path: str,
                         owner: str) -> tuple[str, ...]:
    """Reuse every prerequisite isolation flag and change only owned name/network/finite mode."""

    index = TRACKS.index(track) * len(PATHS) + PATHS.index(path)

    if name != "fuzzy-1337-nuclei-case-" + owner[:12] + "-" + str(index):
        raise ValueError("Nuclei comparison requires its exact unique owned case name")

    arguments = list(PrerequisiteArguments("fuzzy-1337-nuclei-preflight-" + owner[:12], image))
    arguments[arguments.index("--name") + 1] = name
    arguments[arguments.index("--network") + 1] = "container:" + target

    return (*arguments[:-1], *ApplicationCommand(track, path, target, owner))


def ApplicationProjection(raw: dict) -> dict:
    """Require shared-netns Docker readback without inventing an independent network endpoint."""

    if re.fullmatch("container:[a-f0-9]{64}", raw["HostConfig"]["NetworkMode"]) is None or (
        raw["NetworkSettings"]["Networks"] != {}
    ):
        raise ValueError("Application runner must share exactly one existing target namespace")

    normalized = {**raw, "NetworkSettings": {**raw["NetworkSettings"], "Networks": {"none": {
        "IPAddress": "", "GlobalIPv6Address": "", "Gateway": "", "IPv6Gateway": ""}}}}

    return ContainerProjection(normalized)


def AdmitApplicationContainer(value: dict, image: dict, owner: str, revision: str,
                              name: str, target: str, command: tuple[str, ...]) -> None:
    """Admit the exact changed selection, then reuse all unchanged strict prerequisite guards."""

    if value["name"] != "/" + name or value["cmd"] != list(command) or (
        value["host"]["network"] != "container:" + target
    ):
        raise ValueError("Nuclei application changed its exact name/mode/target namespace")

    normalized = {**value, "name": "/fuzzy-1337-nuclei-preflight-" + owner[:12],
        "cmd": ["--prerequisites"], "host": {**value["host"], "network": "none"}}
    AdmitContainer(normalized, image, owner, revision)


async def Shielded(operation):
    """Finish bounded cleanup despite repeated caller cancellation, then propagate it."""

    task = asyncio.create_task(operation)
    cancellation = None

    while not task.done():
        try:
            await asyncio.shield(task)

        except asyncio.CancelledError as error:
            cancellation = error

    result = task.result()

    if cancellation is not None:
        raise cancellation

    return result


class ComparisonTargetLab(ExternalTargetLab):
    """Reuse the unchanged target lifecycle through the new owner's fixed local Docker authority."""

    def __init__(self, host, directory):
        """Keep one fresh existing target fixture and its independent raw command evidence."""

        super().__init__(host.repository, directory, LoadTarget(host.repository))
        self.host = host
        self.target_absent = False

    def Run(self, *arguments, timeout_seconds):
        """Capture owned original bytes before the inherited readable projection."""

        if not arguments or arguments[0] != "docker":
            raise ValueError("Comparison target lifecycle may invoke only fixed local Docker")

        result, raw = asyncio.run(self.host.Command("target", tuple(arguments[1:]),
            seconds=int(timeout_seconds), limit=2 * 1024 * 1024, stderr=256 * 1024, require=False))
        directory = Path(self.host.receipt["commands"][-1]["directory"])
        stderr = (directory / "stderr.raw").read_bytes()
        readable = CommandResult(tuple(result["argv"]), result["exit_code"],
            raw.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace"),
            result["timed_out"], result["duration_seconds"])
        self.WriteEvidence(readable)

        return readable

    def Stop(self, profile=""):
        """Retain inherited bounded project teardown and independently confirm network absence."""

        result = super().Stop(profile)
        remaining = self.Run("docker", "network", "ls", "--quiet", "--no-trunc", "--filter",
            "label=com.docker.compose.project=" + self.project_name, timeout_seconds=15)
        self.RequireSuccess(remaining, "Comparison target network absence")

        if remaining.stdout.strip():
            raise ValueError("Comparison target network remains after owned teardown")

        self.target_absent = True

        return result


class NucleiComparisonHost(PrerequisiteHost):
    """Share one inspected image while owning a fresh unchanged target for every track/case pair."""

    def __init__(self, repository: Path, pack: dict, target: dict):
        """Construct bookkeeping only; no source, Docker or target is discovered here."""

        super().__init__(governed_no_home=True)
        self.repository = repository
        self.pack, self.target = pack, target
        self.observations = []
        self.targets = set()
        self.initialized = False
        self.receipt["kind"] = "finite-nuclei-application-comparison"

    async def Provision(self):
        """Establish genuine no-HOME Go compatibility before creating any application target."""

        self.Initialize()
        self.initialized = True

        try:
            self.source, self.runner, self.image = await self.Prepare()
            await self.RunPrepared(self.source, self.runner, self.image,
                                   self.root / "governed-prerequisite")
            manifest_path = self.root / "governed-prerequisite/image-provisioning.json"
            self.manifest_raw = manifest_path.read_bytes()
            self.receipt["status"] = "prepared-comparison"

        finally:
            await Shielded(self.CloseContainer())

    def AdmitTarget(self, lab):
        """Inspect the actual pinned target and internal network before sharing its namespace."""

        target_id = lab.provenance["container_id"]

        if re.fullmatch("[a-f0-9]{64}", target_id) is None or target_id in self.targets or (
            lab.provenance["platform"] != "linux/amd64"
        ):
            raise ValueError("Comparison requires a fresh exact native amd64 target instance")

        raw = asyncio.run(self.Inspect("container", target_id, "target-original-inspect"))
        networks = raw["NetworkSettings"]["Networks"]
        host = raw["HostConfig"]

        if raw["Id"] != target_id or raw["Image"] != lab.provenance["image"]["id"] or (
            raw["Config"]["Image"] != lab.target.ImageReference
            or raw["State"]["Running"] is not True or raw["Config"]["User"] != "65532:0"
            or raw["Mounts"] != [] or host["Binds"] not in (None, [])
            or host["PortBindings"] not in (None, {}) or host["PublishAllPorts"] is not False
            or host["Privileged"] is not False or host["CapDrop"] != ["ALL"]
            or host["Init"] is not True
            or host["SecurityOpt"] != ["no-new-privileges:true"]
            or host["Memory"] != self.target["resource_limits"]["memory_mib"] * 1024 * 1024
            or host["NanoCpus"] != int(self.target["resource_limits"]["cpus"] * 1000000000)
            or host["PidsLimit"] != self.target["resource_limits"]["pids"]
            or host["CapAdd"] not in (None, []) or len(networks) != 1
            or set(networks) != {lab.project_name + "_external-targets"}
        ):
            raise ValueError("Comparison target widened its identity, mounts, ports or network")

        network_id = next(iter(networks.values()))["NetworkID"]
        _, original = asyncio.run(self.Command("target-network-inspect", (
            "network", "inspect", "--format", "{{json .}}", network_id)))
        network = StrictJson(original)

        if network["Id"] != network_id or network["Internal"] is not True or (
            network["Driver"] != "bridge" or set(network["Containers"]) != {target_id}
        ):
            raise ValueError("Actual comparison namespace is not the one isolated internal target")

        self.targets.add(target_id)

        return target_id

    @contextmanager
    def OwnApplication(self):
        """Remove the owned runner before the target's namespace and network teardown."""

        try:
            yield

        finally:
            asyncio.run(Shielded(self.CloseContainer()))

    def RunCase(self, track: str, case: dict) -> dict:
        """Retain original provider and host failures, with unconditional independent cleanup."""

        if track not in TRACKS or case not in self.pack["cases"]:
            raise ValueError("Comparison requires one exact unchanged declared track/case")

        if self.receipt["governed_no_home_compatibility"] != "established":
            raise ValueError("Application targets require genuine no-HOME prerequisites")

        index = TRACKS.index(track) * len(PATHS) + PATHS.index(case["path"])
        directory = self.root / ("case-" + str(index) + "-" + track + "-" + case["id"])
        directory.mkdir(mode=0o700)
        lab = ComparisonTargetLab(self, directory / "target")
        observation, failure, attached, start_record = None, None, False, None
        target_id = ""
        self.name = "fuzzy-1337-nuclei-case-" + self.owner[:12] + "-" + str(index)
        before_cleanup = len(self.receipt["cleanup"])

        try:
            if asyncio.run(self.Source("case-before")) != (self.revision, self.tree):
                raise ValueError("Comparison source changed before target startup")

            with contextmanager(OwnExternalTarget)(lab), self.OwnApplication():
                target_id = self.AdmitTarget(lab)
                reset = {"target": self.target, "compose_sha256": hashlib.sha256(
                    (self.repository / "labs/external/compose.yaml").read_bytes()).hexdigest()}
                provenance = directory / "target-provenance.json"
                WriteJson(provenance, {"source_revision": self.target["source_revision"],
                    "image_index_digest": self.target["index_digest"],
                    "platform_digest": lab.provenance["platform_manifest_digest"],
                    "target_url": "http://127.0.0.1:3000" + case["path"],
                    "target_instance": target_id,
                    "reset_contract_sha256": hashlib.sha256(json.dumps(
                        reset, sort_keys=True).encode()).hexdigest(),
                    "network_internal": True, "published_ports": 0,
                    "fixture_http_probes": [asdict(item) for item in lab.observations],
                    "scanner_image_id": self.image["id"], "scanner_source_revision": self.revision})
                arguments = ApplicationArguments(self.name, self.image["id"], target_id,
                                                track, case["path"], self.owner)
                image_position = arguments.index(self.image["id"])
                create = (*arguments[1:image_position], "--label", OWNER_LABEL + "=" + self.owner,
                          *arguments[image_position:])
                self.created = True
                _, raw = asyncio.run(self.Command("case-create", create, seconds=20))
                identifier = raw.decode("ascii").strip()

                if re.fullmatch("[a-f0-9]{64}", identifier) is None:
                    raise ValueError("Application create omitted one exact immutable container ID")

                self.container = identifier
                before = asyncio.run(self.Inspect("container", self.container, "case-before"))
                self.OwnedContainer(before, self.container)
                projection = ApplicationProjection(before)
                AdmitApplicationContainer(projection, self.image, self.owner, self.revision,
                    self.name, target_id, ApplicationCommand(
                        track, case["path"], target_id, self.owner))
                attached = True

                try:
                    attachment, raw = asyncio.run(self.Command("case-attach", (
                        "container", "start", "--attach", self.container),
                        seconds=40, limit=12 * 1024 * 1024, stderr=65536, require=False))

                finally:
                    start_record = self.receipt["commands"][-1]

                after = asyncio.run(self.Inspect("container", self.container, "case-after"))
                self.OwnedContainer(after, self.container)
                final = ApplicationProjection(after)

                if Canonical({key: value for key, value in final.items()
                    if key not in {"state", "restart_count"}}) != Canonical({
                    key: value for key, value in projection.items()
                    if key not in {"state", "restart_count"}}):
                    raise ValueError("Application container changed configuration during execution")

                bundle = BindApplicationBundle(raw, directory / "scanner", self.manifest_raw,
                    self.revision, track, case["path"], target_id, self.owner)
                observation = Observation(self.pack, self.target, case, track, self.root,
                    directory / "scanner", provenance, bundle["outcome"])

                if type(attachment["exit_code"]) is not int or attachment["exit_code"] != 0:
                    raise ValueError("Nuclei application attachment did not terminate successfully")

                AdmitTermination(after["State"], after["RestartCount"])

        except BaseException as error:
            failure = error
            WriteJson(directory / "case-failure.json", {"exception_type": type(error).__name__,
                "start_attempted": attached, "scanner_completion_claimed": False})

        finally:
            try:
                if self.created or self.container is not None:
                    asyncio.run(Shielded(self.CloseContainer()))

            except BaseException as error:
                if failure is None:
                    failure = error

            cleanup = {"container_absent": True if self.container is None and not (
                self.created) else None,
                "target_absent": lab.target_absent,
                "original_cleanup_records": self.receipt["cleanup"][before_cleanup:]}
            WriteJson(directory / "cleanup.json", cleanup)

        if observation is None:
            observation = {"schema_version": 2, "pack_id": self.pack["pack_id"],
                "case_id": case["id"], "scanner_track": track, "status": "prerequisite-failed",
                "reason": "Provider custody unavailable; original host evidence retained",
                "execution": None}

            if attached and start_record is not None:
                observation = self.FailedAttempt(case, track, target_id, directory, start_record,
                                                 cleanup, failure)

        elif failure is not None:
            observation.update(status="failed",
                               reason="Provider facts retained; host execution or cleanup failed")

        ValidateObservation(self.pack, self.target, observation, self.root)
        self.observations.append(observation)
        WriteJson(directory / "observation.json", observation)
        WriteJson(self.root / "comparison.json", BuildComparison(
            self.pack, self.target, self.observations, self.root))

        return observation

    def FailedAttempt(self, case, track, target_id, directory, start, cleanup, failure):
        """Retain a source-bound original start attempt when provider records cannot be trusted."""

        command = Path(start["directory"])
        original = {"source_revision": self.revision, "source_tree": self.tree,
            "case_id": case["id"], "scanner_track": track, "target_instance": target_id,
            "start_attempted": True, "start_argv": start["argv"],
            "runner_container_id": start["argv"][-1]}
        WriteJson(directory / "host-attempt.json", original)
        attempt = {key: original[key] for key in ("source_revision", "case_id", "scanner_track",
                                                  "target_instance", "start_attempted")}
        attempt["evidence"] = []

        for role, path in (("host-attempt", directory / "host-attempt.json"),
            ("host-start-stdout", command / "stdout.raw"),
            ("host-start-stderr", command / "stderr.raw"),
            ("host-start-command", command / "command.json"),
            ("host-cleanup", directory / "cleanup.json"),
            ("target-provenance", directory / "target-provenance.json"),
            ("source-provenance", self.root / "context-inventory.json")):
            raw = path.read_bytes()
            relative = path.relative_to(self.root).as_posix()
            attempt["evidence"].append({"role": role, "path": relative,
                "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)})

        return {"schema_version": 2, "pack_id": self.pack["pack_id"], "case_id": case["id"],
            "scanner_track": track, "status": "cancelled" if isinstance(failure, (
                asyncio.CancelledError, KeyboardInterrupt)) else "failed",
            "reason": "Original host start attempted; provider custody unavailable and unscored",
            "execution": None, "host_attempt": attempt}

    async def Close(self):
        """Remove image/context owners and preserve the final comparison's independent cleanup."""

        if not self.initialized:
            return

        try:
            await super().Close()

            if await self.Source("comparison-after") != (self.revision, self.tree):
                raise ValueError("Comparison source changed during application execution")

            self.receipt["status"] = "completed-comparison" if len(self.observations) == 6 and all(
                item["status"] in {"completed", "unproven"} for item in self.observations
            ) else "failed"

        except BaseException:
            self.receipt["status"] = "failed"

            raise

        finally:
            WriteJson(self.root / "host.json", self.receipt)
