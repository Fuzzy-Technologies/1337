# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Own the finite installed native scanner image and its exact external target namespace."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
from dataclasses import asdict
from pathlib import Path
from uuid import uuid4

from .conftest import CommandResult, ComposeLab
from .external_benchmark import BuildComparison, ReadJson, ValidateObservation
from .external_native_runner import MODULES, REQUEST_BASIS, ImportBundle, StrictJson
from .external_targets import ExternalTargetLab, LoadTarget, OwnExternalTarget

IMAGE_FORMAT = ('{"id":{{json .Id}},"user":{{json .Config.User}},'
                '"labels":{{json .Config.Labels}},"layers":{{json .RootFS.Layers}}}')
RUNNER_FORMAT = ('{"image_id":{{json .Image}},"user":{{json .Config.User}},'
                 '"host":{{json .HostConfig}},"mounts":{{json .Mounts}}}')
SOURCE_REVISION_LABEL = "org.opencontainers.image.revision"
RUNNER_TIMEOUT = 40


def Enabled(selection: str | None) -> bool:
    """Permit only explicit accepted-lane selection; ordinary collection stays offline."""

    if selection is None or selection == "":
        return False

    if selection != "juice-shop":
        raise ValueError("FUZZY1337_EXTERNAL_NATIVE_BENCHMARK must be unset or 'juice-shop'")

    return True


def RunnerArguments(name: str, target_id: str, image_id: str, path: str) -> tuple[str, ...]:
    """Build only the finite nonroot, mount-free, read-only target-netns invocation."""

    if re.fullmatch("[a-f0-9]{64}", target_id) is None or (
        re.fullmatch("sha256:[a-f0-9]{64}", image_id) is None
        or re.fullmatch("fuzzy-1337-external-[a-f0-9]{12}-native", name) is None
        or path not in {"/metrics", "/rest/admin/application-version", "/"}
    ):
        raise ValueError("Native runner requires exact owned container/image identities and case")

    return ("docker", "create", "--name", name, "--user", "1337:1337", "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m,uid=1337,gid=1337,mode=0700",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--cpus", "1",
            "--memory", "256m", "--pids-limit", "64", "--init", "--stop-timeout", "5",
            "--network", "container:" + target_id, image_id, "--path", path)


def ValidateRunner(value: dict, target_id: str, image_id: str) -> None:
    """Read back Docker enforcement without accepting widened network or host resources."""

    host = value.get("host", {})
    mounts = value.get("mounts") or []
    mounts_valid = all(item.get("Type") == "tmpfs" and item.get("Destination") == "/tmp"
                       and not item.get("Source") for item in mounts)

    if value.get("image_id") != image_id or value.get("user") != "1337:1337" or (
        host.get("NetworkMode") != "container:" + target_id
        or host.get("ReadonlyRootfs") is not True or host.get("Privileged") is not False
        or host.get("Init") is not True
        or host.get("Binds") not in (None, []) or host.get("PortBindings") not in (None, {})
        or not mounts_valid or len(mounts) > 1
        or host.get("CapDrop") != ["ALL"]
        or host.get("CapAdd") not in (None, []) or host.get("Devices") not in (None, [])
        or host.get("VolumesFrom") not in (None, [])
        or host.get("SecurityOpt") != ["no-new-privileges:true"]
        or host.get("Memory") != 268435456 or host.get("NanoCpus") != 1000000000
        or host.get("PidsLimit") != 64 or set(host.get("Tmpfs", {})) != {"/tmp"}
        or host["Tmpfs"]["/tmp"]
        != "rw,noexec,nosuid,nodev,size=64m,uid=1337,gid=1337,mode=0700"
    ):
        raise ValueError("Native runner isolation readback differs from its approved profile")


def Attach(lab: ExternalTargetLab, runner_id: str, directory: Path) -> tuple[CommandResult, bytes]:
    """Keep original Docker attachment bytes separately from their human-readable log view."""

    argv = ("docker", "start", "--attach", runner_id)
    started = time.monotonic()
    timed_out = False

    try:
        process = subprocess.run(argv, cwd=lab.repository_root, capture_output=True,
                                 check=False, shell=False, timeout=RUNNER_TIMEOUT)
        stdout, stderr, returncode = process.stdout, process.stderr, process.returncode

    except subprocess.TimeoutExpired as error:
        stdout, stderr, returncode = error.stdout or b"", error.stderr or b"", 124
        timed_out = True

    result = CommandResult(argv, returncode, stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"), timed_out, time.monotonic() - started)
    lab.WriteEvidence(result)
    (directory / "docker.stdout").write_bytes(stdout)
    (directory / "docker.stderr").write_bytes(stderr)
    (directory / "docker-exit.json").write_text(json.dumps({
        "argv": argv, "returncode": returncode, "timed_out": timed_out,
        "duration_seconds": result.duration_seconds,
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
    }, indent=2))

    return result, stdout


class NativeBenchmarkRuntime(ComposeLab):
    """Build the current installed wheel once and run exactly one fresh target per native case."""

    def __init__(self, repository_root: Path, evidence_directory: Path, pack: dict, target: dict):
        """Prepare local bookkeeping without Docker discovery, builds, or target access."""

        self.output = evidence_directory / ("run-" + uuid4().hex[:12])
        super().__init__(repository_root, self.output / "provisioning")
        self.repository_root = repository_root
        self.pack = pack
        self.target = target
        self.images = []
        self.image_id = ""
        self.source_revision = ""
        self.observations = []

    def Build(self) -> None:
        """Provision actual current-source images before any isolated target is started."""

        track = next(item for item in self.pack["scanner_tracks"] if item["id"] == "native-engine")

        if track["implementation"] != "available":
            raise RuntimeError("Native benchmark requires accepted integrated detector mapping")

        self.output.mkdir(parents=True, exist_ok=True)
        revision = self.Run("git", "rev-parse", "HEAD", timeout_seconds=5)
        self.RequireSuccess(revision, "Native benchmark source identity")
        self.source_revision = revision.stdout.strip()

        if re.fullmatch("[a-f0-9]{40}", self.source_revision) is None:
            raise RuntimeError("Native benchmark requires an exact Git source revision")

        clean = self.Run("git", "diff", "--exit-code", "HEAD", timeout_seconds=5)
        self.RequireSuccess(clean, "Native benchmark clean tracked source")
        untracked = self.Run("git", "ls-files", "--others", "--exclude-standard", timeout_seconds=5)
        self.RequireSuccess(untracked, "Native benchmark source inventory")

        if untracked.stdout.strip():
            raise RuntimeError("Native benchmark image build requires clean committed source")
        unique = uuid4().hex[:12]
        base_name = "fuzzy1337-native-base-" + unique
        runner_name = "fuzzy1337-native-runner-" + unique
        self.images.extend((runner_name, base_name))
        base_id_file = self.output / "base-image.id"
        runner_id_file = self.output / "runner-image.id"
        self.RequireSuccess(self.Run("docker", "build", "--target", "development", "--iidfile",
            str(base_id_file), "--tag", base_name, "--label",
            SOURCE_REVISION_LABEL + "=" + self.source_revision, str(self.repository_root),
            timeout_seconds=300), "Current product development image build")
        base_id = base_id_file.read_text().strip()

        if re.fullmatch("sha256:[a-f0-9]{64}", base_id) is None:
            raise RuntimeError("Native base build did not produce an immutable image ID")

        base_metadata = self.Run("docker", "image", "inspect", "--format", IMAGE_FORMAT,
                                 base_id, timeout_seconds=15)
        self.RequireSuccess(base_metadata, "Native base image provenance")
        base = StrictJson(base_metadata.stdout.encode())
        (self.output / "base-image.json").write_text(base_metadata.stdout)

        if base.get("id") != base_id or not base.get("layers"):
            raise RuntimeError("Native base image content identity is missing")

        self.RequireSuccess(self.Run("docker", "build", "--file",
            str(self.repository_root / "labs/external/benchmark/native-runner.Dockerfile"),
            "--build-arg", "WORKBENCH_IMAGE=" + base_name, "--build-arg",
            "SOURCE_REVISION=" + self.source_revision, "--iidfile", str(runner_id_file),
            "--tag", runner_name, str(self.repository_root), timeout_seconds=180),
            "Clean installed-wheel native runner image build")
        self.image_id = runner_id_file.read_text().strip()
        metadata = self.Run("docker", "image", "inspect", "--format", IMAGE_FORMAT,
                            self.image_id, timeout_seconds=15)
        self.RequireSuccess(metadata, "Native scanner image provenance")
        value = StrictJson(metadata.stdout.encode())

        if value.get("id") != self.image_id or value.get("user") != "1337:1337" or (
            value.get("labels", {}).get(SOURCE_REVISION_LABEL) != self.source_revision
            or value.get("layers", [])[:len(base["layers"])] != base["layers"]
        ):
            raise RuntimeError("Native runner image identity/user/source attribution changed")

        (self.output / "scanner-image.json").write_text(metadata.stdout)

    def Close(self) -> None:
        """Remove unique owned first-party image tags and preserve every raw outcome."""

        for image in self.images:
            result = self.Run("docker", "image", "rm", image, timeout_seconds=30)

            if result.returncode and "No such image" not in result.stderr:
                self.RequireSuccess(result, "Owned native image cleanup")

    def RunCase(self, case: dict) -> dict:
        """Execute a genuine installed scanner with cleanup after every acquisition failure."""

        directory = self.output / case["id"]
        directory.mkdir(parents=True, exist_ok=True)
        lab = ExternalTargetLab(self.repository_root, directory / "target",
                                LoadTarget(self.repository_root))

        with OwnExternalTarget(lab) as target_lab:
            control_sha256 = self.Control(case, target_lab)
            target_id = target_lab.provenance["container_id"]
            name = target_lab.project_name + "-native"
            runner_id = ""

            try:
                created = lab.Run(*RunnerArguments(name, target_id, self.image_id, case["path"]),
                                  timeout_seconds=20)
                lab.RequireSuccess(created, "Restricted native scanner container creation")
                runner_id = created.stdout.strip()

                if re.fullmatch("[a-f0-9]{64}", runner_id) is None:
                    raise RuntimeError("Native scanner creation returned no exact container ID")

                inspected = lab.Run("docker", "inspect", "--format", RUNNER_FORMAT,
                                    runner_id, timeout_seconds=15)
                lab.RequireSuccess(inspected, "Native scanner isolation readback")
                ValidateRunner(StrictJson(inspected.stdout.encode()), target_id, self.image_id)
                result, raw_stdout = Attach(lab, runner_id, directory)
                imported = ImportBundle(raw_stdout, directory / "scanner")
                (directory / "bundle-manifest.json").write_text(json.dumps({
                    "schema_version": imported["schema_version"], "outcome": imported["outcome"],
                    "files": [{key: value for key, value in record.items() if key != "data_base64"}
                              for record in imported["files"]],
                }, indent=2))
                lab.RequireSuccess(result, "Actual installed native scanner execution")
                observation = self.Observation(case, directory, target_lab, imported["outcome"],
                                               control_sha256=control_sha256)
                ValidateObservation(self.pack, self.target, observation, self.output)
                self.observations.append(observation)
                report = BuildComparison(self.pack, self.target, self.observations, self.output)
                (self.output / "report.json").write_text(json.dumps(report, indent=2))

                return observation

            except Exception as error:
                (directory / "case-failure.json").write_text(json.dumps({
                    "exception_type": type(error).__name__,
                    "state": "failed-unscored", "scanner_completion_claimed": False,
                }, indent=2))

                raise

            finally:
                removed = lab.Run("docker", "rm", "--force", "--volumes", runner_id or name,
                                  timeout_seconds=20)
                lab.RequireSuccess(removed, "Native scanner container cleanup")

    def Control(self, case: dict, lab: ExternalTargetLab) -> str | None:
        """Verify actual JSON/HTML control content outside scanner attempt accounting."""

        if case["path"] == "/metrics":
            return None

        response = lab.Request(case["path"])
        valid = response.status == 200 and not response.error

        if case["path"] == "/rest/admin/application-version":
            valid = valid and StrictJson(response.body.encode()) == {
                "version": self.target["version"]}

        elif case["path"] == "/":
            valid = valid and "OWASP Juice Shop" in response.body

        else:
            valid = False

        if not valid:
            raise RuntimeError("Pinned negative control no longer serves its real JSON/HTML body")

        return hashlib.sha256(response.body.encode("utf-8")).hexdigest()

    def Observation(
        self, case: dict, directory: Path, lab: ExternalTargetLab, outcome: dict,
        *, control_sha256: str | None = None,
    ) -> dict:
        """Bind actual acquired records while labeling attempts separately from server contacts."""

        scanner = directory / "scanner"
        provisioning = ReadJson(scanner / "provisioning.json")
        invocation = ReadJson(scanner / "invocation.json")
        worker = ReadJson(scanner / "worker-stdout.json")
        findings = StrictJson((scanner / "findings.json").read_bytes())
        target_url = "http://127.0.0.1:3000" + case["path"]

        if not isinstance(provisioning.get("wheel"), dict) or (
            type(provisioning["wheel"].get("filename")) is not str
            or re.fullmatch(r"1337-[A-Za-z0-9_.+-]+\.whl",
                            provisioning["wheel"]["filename"]) is None
            or not isinstance(provisioning.get("module_sha256"), dict)
            or set(provisioning["module_sha256"]) != set(MODULES)
        ):
            raise RuntimeError("Installed source receipt has unknown wheel or module identities")

        wheel = scanner / provisioning["wheel"]["filename"]

        if outcome.get("status") != "completed" or outcome.get("exit_code") != 0 or (
            outcome.get("target_url") != target_url or worker.get("url") != target_url
            or worker.get("check_id") != "native.prometheus-exposition" or "error" in worker
            or type(worker.get("matched")) is not bool
            or worker.get("status") != 200
            or (control_sha256 is not None and worker.get("body_sha256") != control_sha256)
            or provisioning["source_revision"] != self.source_revision
            or bool(findings) != worker["matched"]
            or provisioning["runner_sha256"] != hashlib.sha256((self.repository_root
                / "tests/functional/external_native_runner.py").read_bytes()).hexdigest()
            or hashlib.sha256(wheel.read_bytes()).hexdigest() != provisioning["wheel"]["sha256"]
            or wheel.stat().st_size != provisioning["wheel"]["size_bytes"]
            or invocation["scanner_sha256"] != provisioning["python_sha256"]
            or invocation["rule_sha256"]
            != provisioning["module_sha256"]["adapters.prometheus_exposition"]
        ):
            raise RuntimeError("Native summary, worker record, Findings, or source disagreed")

        for module, digest in provisioning["module_sha256"].items():
            relative = module.replace(".", "/") + ".py"
            module_path = self.repository_root / "src/fuzzy1337" / relative

            if hashlib.sha256(module_path.read_bytes()).hexdigest() != digest:
                raise RuntimeError("Installed native module differs from exact committed source")

        reset = {"target": self.target, "compose_sha256": hashlib.sha256(
            (self.repository_root / "labs/external/compose.yaml").read_bytes()).hexdigest()}
        reset_hash = hashlib.sha256(json.dumps(reset, sort_keys=True).encode()).hexdigest()
        execution = {**invocation, "source_revision": self.target["source_revision"],
            "image_index_digest": self.target["index_digest"],
            "platform_digest": lab.provenance["platform_manifest_digest"],
            "target_url": target_url, "target_instance": lab.provenance["container_id"],
            "reset_contract_sha256": reset_hash,
            "network_internal": True, "published_ports": 0, "exit_code": outcome["exit_code"],
            "duration_seconds": outcome["duration_seconds"], "request_count": 1,
            "findings": findings, "evidence": []}
        provenance_keys = ("source_revision", "image_index_digest", "platform_digest", "target_url",
                           "target_instance", "reset_contract_sha256", "network_internal",
                           "published_ports")
        normalized = directory / "target-provenance.json"
        normalized.write_text(json.dumps({key: execution[key] for key in provenance_keys}))
        requests = directory / "approved-attempts.json"
        requests.write_text(json.dumps([{"method": "GET", "url": target_url}]))
        accounting = directory / "attempt-provenance.json"
        accounting.write_text(json.dumps({"basis": REQUEST_BASIS, "approved_attempt_count": 1,
            "independent_server_contact_count": None,
            "fixture_http_probes": [asdict(item) for item in lab.observations],
            "docker_healthchecks": "Pinned Compose healthchecks; not scanner attempts",
            "scanner_image_id": self.image_id, "scanner_source_revision": self.source_revision}))

        for role, path in (
            ("stdout", scanner / "worker-stdout.json"),
            ("stderr", scanner / "worker-stderr.json"),
            ("invocation", scanner / "invocation.json"), ("findings", scanner / "findings.json"),
            ("target-provenance", normalized), ("requests", requests),
            ("attempt-provenance", accounting),
            ("installed-wheel", scanner / provisioning["wheel"]["filename"]),
            ("installed-source", scanner / "provisioning.json"),
        ):
            raw = path.read_bytes()
            relative = path.relative_to(self.output).as_posix()
            execution["evidence"].append({"role": role, "path": relative,
                "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)})

        return {"schema_version": 1, "pack_id": self.pack["pack_id"], "case_id": case["id"],
                "scanner_track": "native-engine", "status": "completed",
                "reason": "Actual installed native job; attempts are not server-contact telemetry",
                "execution": execution}
