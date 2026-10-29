# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Inert finite application selection, failed-attempt custody and cancellation contracts."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import stat
from pathlib import Path

import pytest
from jsonschema.exceptions import ValidationError

from tests.contract.test_external_benchmark import (
    ContractNucleiObservation,
    WriteNucleiContractEvidence,
)
from tests.contract.test_external_nuclei_benchmark import (
    CONTAINER_CONFIGURATION,
    CONTAINER_EXECUTABLE,
    CONTAINER_TEMPLATE,
    DeclareInertBinaryModes,
    InertProcess,
    Match,
    StandaloneArguments,
    StandaloneMaterial,
    WholeMaterial,
)
from tests.contract.test_external_nuclei_host import OWNER, REVISION, Container, Images
from tests.functional import external_nuclei_comparison as lifecycle
from tests.functional import external_nuclei_observation as originals
from tests.functional.external_benchmark import BuildComparison, LoadPack, ValidateObservation
from tests.functional.external_native_runner import ExportBundle, WriteJson
from tests.functional.external_nuclei_application import CaseSelection
from tests.functional.external_nuclei_comparison import (
    AdmitApplicationContainer,
    ApplicationArguments,
    ApplicationCommand,
    ApplicationProjection,
    Shielded,
)
from tests.functional.external_nuclei_runner import ProfileDocument, RunStandalone
from tests.functional.external_nuclei_runtime import RunWhole1337


@pytest.mark.parametrize("track", ["whole1337", "external-nuclei"])
@pytest.mark.parametrize("path", ["/metrics", "/rest/admin/application-version", "/"])
def test_FiniteApplicationArgumentsPreserveEveryIsolationLimit(track, path):
    """All six selected slots retain exact inputs, provider image and target-netns isolation."""

    paths = ("/metrics", "/rest/admin/application-version", "/")
    index = (0 if track == "whole1337" else 3) + paths.index(path)
    name = "fuzzy-1337-nuclei-case-" + OWNER[:12] + "-" + str(index)
    target = "d" * 64
    _, image = Images()
    arguments = ApplicationArguments(name, image["id"], target, track, path, OWNER)
    assert arguments[arguments.index("--network") + 1] == "container:" + target and (
        arguments[arguments.index(image["id"]) + 1:] == ApplicationCommand(
            track, path, target, OWNER)
    ), "The image mode may receive only its exact finite target/track/path/owner binding"
    assert all(flag in arguments for flag in ("--read-only", "--cap-drop", "--init")) and (
        arguments[arguments.index("--memory") + 1] == "256m"
        and arguments[arguments.index("--pids-limit") + 1] == "64"
        and "--publish" not in arguments and "--volume" not in arguments
    ), "Application cases must retain nonroot read-only bounded mount-free container enforcement"
    value = Container()
    value.update(name="/" + name, cmd=list(ApplicationCommand(track, path, target, OWNER)))
    value["host"]["network"] = "container:" + target
    before = copy.deepcopy(value)
    AdmitApplicationContainer(value, image, OWNER, REVISION, name, target,
                              ApplicationCommand(track, path, target, OWNER))
    assert value == before, "Admission must not rewrite the independently retained original inspect"


@pytest.mark.parametrize("widened", [False, True])
def test_SharedNamespaceProjectionRefusesAnIndependentNetworkEndpoint(widened):
    """Shared-netns endpoint inventory stays distinct from offline none networking."""

    from tests.contract.test_external_nuclei_host import RawContainer

    raw = RawContainer()
    raw["HostConfig"]["NetworkMode"] = "container:" + "d" * 64
    raw["NetworkSettings"]["Networks"] = {"arbitrary": {}} if widened else {}

    if widened:
        with pytest.raises(ValueError, match="namespace"):
            ApplicationProjection(raw)

    else:
        before = copy.deepcopy(raw)
        projection = ApplicationProjection(raw)
        assert raw == before and projection["host"]["network"] == "container:" + "d" * 64, (
            "Projection must preserve the original shared namespace and source bytes"
        )


@pytest.mark.parametrize("field,value", [("track", "arbitrary"), ("path", "/admin"),
    ("target", "short"), ("owner", "unowned")])
def test_ApplicationSelectionRefusesScopeExpansionBeforeRuntime(field, value):
    """Selection construction cannot infer a target, another case or an arbitrary image command."""

    selection = {"track": "whole1337", "path": "/metrics", "target": "d" * 64, "owner": OWNER}
    selection[field] = value

    with pytest.raises(ValueError):
        CaseSelection(selection["track"], selection["path"],
                      selection["target"], selection["owner"])


def HostFailureFixture(root):
    """Write explicit synthetic original-shaped host attempt files; no command ever executes."""

    pack, target = LoadPack()
    original = {"source_revision": REVISION, "source_tree": "c" * 40,
        "case_id": "metrics.exposed", "scanner_track": "whole1337", "target_instance": "d" * 64,
        "start_attempted": True, "runner_container_id": "e" * 64,
        "start_argv": ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "--config",
            "/owned/run/docker-config", "container", "start", "--attach", "e" * 64]}
    documents = {"host-attempt": original, "host-start-stdout": b"original failed host stdout\n",
        "host-start-stderr": b"original failure diagnostic\n",
        "host-start-command": {"argv": original["start_argv"], "exit_code": None},
        "host-cleanup": {"container_absent": True, "target_absent": True},
        "source-provenance": {"revision": REVISION, "tree": "c" * 40},
        "target-provenance": {"target_instance": "d" * 64,
            "target_url": "http://127.0.0.1:3000/metrics",
            "source_revision": target["source_revision"],
            "image_index_digest": target["index_digest"],
            "platform_digest": target["platform_digests"]["linux/amd64"],
            "network_internal": True, "published_ports": 0}}
    documents["host-start-command"].update(
        cleanup_confirmed=True, streams_complete=True, timed_out=False, launch_error=None,
        capture_error=None, interrupted=None, duration_seconds=0.01,
        **{role: {"size_bytes": len(documents["host-start-" + role]),
                  "sha256": hashlib.sha256(documents["host-start-" + role]).hexdigest()}
           for role in ("stdout", "stderr")})
    attempt = {key: original[key] for key in ("source_revision", "case_id", "scanner_track",
                                             "target_instance", "start_attempted")}
    attempt["evidence"] = []

    return pack, target, documents, {"schema_version": 2, "pack_id": pack["pack_id"],
        "case_id": "metrics.exposed", "scanner_track": "whole1337", "status": "failed",
        "reason": "Synthetic host start failed; no provider facts or server contacts established",
        "execution": None, "host_attempt": attempt}


@pytest.mark.parametrize("mutation", [None, "wrong-case", "wrong-source", "wrong-target",
    "wrong-url", "no-start", "missing-capture", "wrong-command", "unknown-cleanup"])
def test_FailedNullProviderRowsRequireOriginalHostAttemptBinding(tmp_path, mutation):
    """Consistent file hashes cannot forge a cross-case, wrong-source or missing-start attempt."""

    pack, target, documents, observation = HostFailureFixture(tmp_path)

    if mutation == "wrong-case":
        observation["case_id"] = "metrics.json-control"

    elif mutation == "wrong-source":
        documents["source-provenance"]["revision"] = "0" * 40

    elif mutation == "wrong-target":
        documents["target-provenance"]["target_instance"] = "0" * 64

    elif mutation == "wrong-url":
        documents["target-provenance"]["target_url"] = "http://127.0.0.1:3000/"

    elif mutation == "no-start":
        documents["host-attempt"]["start_attempted"] = False

    elif mutation == "missing-capture":
        del documents["host-start-stderr"]

    elif mutation == "wrong-command":
        documents["host-start-command"]["argv"] = ["docker", "version"]

    elif mutation == "unknown-cleanup":
        documents["host-cleanup"].update(container_absent=None, target_absent=False)

    for role, value in documents.items():
        raw = value if isinstance(value, bytes) else json.dumps(value).encode()
        (tmp_path / role).write_bytes(raw)
        observation["host_attempt"]["evidence"].append({"role": role, "path": role,
            "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)})

    if mutation in {None, "unknown-cleanup"}:
        report = BuildComparison(pack, target, [observation], tmp_path)
        counts = report["finite_completed_case_counts"]["whole1337"]
        assert all(counts[key] == 0 for key in ("tp", "fp", "tn", "fn")) and (
            next(row for row in report["cells"] if row["case_id"] == "metrics.exposed"
                 and row["scanner_track"] == "whole1337")["status"] == "failed"
        ), "Proven failed host attempts must remain failed and unscored even with unknown cleanup"

    else:
        with pytest.raises((ValueError, KeyError, ValidationError)):
            ValidateObservation(pack, target, observation, tmp_path)


@pytest.mark.parametrize("status", ["failed", "crashed", "timed-out", "cancelled",
                                   "completed", "unproven"])
def test_OnlyFailedFamilyCanRetainNullObservedProviderExit(tmp_path, status):
    """A missing observed terminal code never becomes successful invocation or absence credit."""

    pack, target = LoadPack()

    for track in pack["scanner_tracks"]:
        track["implementation"] = "available"

    observation = ContractNucleiObservation(pack, target, tmp_path)
    observation["status"] = status
    observation["execution"]["exit_code"] = None
    WriteNucleiContractEvidence(observation, tmp_path)

    if status in {"completed", "unproven"}:
        with pytest.raises(ValueError):
            ValidateObservation(pack, target, observation, tmp_path)

    else:
        report = BuildComparison(pack, target, [observation], tmp_path)
        assert report["finite_completed_case_counts"]["external-nuclei"]["unscored"] == 3, (
            "Nullable failure facts cannot invent a response verdict or metric denominator"
        )


def test_CancellationCannotInterruptIndependentCleanup():
    """Repeated caller cancellation propagates only after the bounded cleanup task finishes."""

    async def Scenario():
        """Use events and no external process to prove the actual asynchronous cleanup boundary."""

        entered, release = asyncio.Event(), asyncio.Event()
        finished = []

        async def Cleanup():
            """Retain independent cleanup completion after the explicit release point."""

            entered.set()
            await release.wait()
            finished.append(True)

        task = asyncio.create_task(Shielded(Cleanup()))
        await entered.wait()
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        release.set()

        with pytest.raises(asyncio.CancelledError):
            await task

        assert finished == [True], "Caller cancellation must not silently abandon owned cleanup"

    asyncio.run(Scenario())


def ProducedBundle(tmp_path, monkeypatch, track, *, empty=False, container_paths=False):
    """Run actual lab producers with labeled inert execution, keeping actual saved core custody."""

    source = tmp_path / "source"
    source.mkdir()
    DeclareInertBinaryModes(source, monkeypatch)
    root = tmp_path / "original"
    root.mkdir()
    scan = root / "scan"
    arguments = list(WholeMaterial(source, monkeypatch, mode="empty" if empty else "match",
                                  container_paths=container_paths, run_root=scan)[0]) if (
        track == "whole1337") else list(StandaloneMaterial(source, run_root=scan))

    def ExpectedContainerArguments(executable, path, template, configuration):
        """Bind only declared fixture artifact slots to an independent fixed Linux argv oracle."""

        expected_files = (arguments[2], scan / "prometheus-exposition.yaml",
                          scan / "operator-config.yaml")

        if (executable, template, configuration) != expected_files or path != "/metrics":
            raise ValueError("Inert application argv requires exact selected fixture paths")

        expected = list(StandaloneArguments(CONTAINER_EXECUTABLE, path,
            CONTAINER_TEMPLATE, CONTAINER_CONFIGURATION))

        if track == "whole1337":
            expected[0], expected[-1], expected[4] = map(str, expected_files)

        return tuple(expected)

    if os.name == "nt" or container_paths:
        monkeypatch.setattr(originals, "StandaloneArguments", ExpectedContainerArguments)

    selected = CaseSelection(track, "/metrics", "d" * 64, OWNER)
    arguments[7] = selected["authorization"]

    if track == "whole1337":
        outcome = RunWhole1337(*arguments)

    else:
        InertProcess(monkeypatch, stdout=b"" if empty else Match(), container_paths=container_paths)
        outcome = RunStandalone(*arguments)

    assert outcome["status"] == ("unproven" if empty else "completed"), (
        "The source fixture must first exercise actual producer behavior with inert execution "
        f"only; observed status={outcome['status']}: {outcome['reason']}"
    )
    inventory = originals.Json(root, "scan/installed-inventory.json") if (
        track == "whole1337") else {}
    runtime_hash = inventory.pop("whole1337_runtime_sha256", "f" * 64)
    manifest = {"source_revision": "a" * 40, "installed": {"installed": inventory},
        "support_sha256": {"external_nuclei_runtime.py": runtime_hash},
        "material": {"executable": {"path": str(arguments[2]), "sha256": arguments[5]},
                     "profile": ProfileDocument(arguments[3], arguments[4])}}
    manifest_raw = json.dumps(manifest).encode()
    (root / "image-provisioning.json").write_bytes(manifest_raw)
    WriteJson(root / "case-selection.json", selected)
    WriteJson(root / "outcome.json", outcome)
    monkeypatch.setattr(originals, "SCAN", root / "scan")

    return root, manifest_raw, outcome


@pytest.mark.parametrize("track", ["whole1337", "external-nuclei"])
@pytest.mark.parametrize("container_paths", [False, True], ids=["host-spelling", "linux-container"])
def test_NestedInertProducerDeclaresOnlySelectedExecutableMode(
    tmp_path, monkeypatch, track, container_paths,
):
    """Nested material models POSIX bits even when the host exposes no execute permissions."""

    binary = tmp_path / "source/inert-never-executed"
    original = Path.lstat

    def NonExecutableView(path):
        """Simulate the actual Windows mode limit only for the explicit never-executed binary."""

        metadata = original(path)

        if path == binary and stat.S_ISREG(metadata.st_mode):
            return os.stat_result((metadata.st_mode & ~0o111, *metadata[1:]))

        return metadata

    monkeypatch.setattr(Path, "lstat", NonExecutableView)
    _, _, outcome = ProducedBundle(tmp_path, monkeypatch, track, container_paths=container_paths)
    native, projected = NonExecutableView(binary), binary.lstat()
    assert outcome["status"] == "completed" and native.st_mode & 0o111 == 0 and (
        stat.S_IMODE(projected.st_mode) == 0o700
    ), "Only the explicit inert declaration may add modeled execute bits to nested material."
    assert tuple(native)[1:] == tuple(projected)[1:] and (
        stat.S_IFMT(native.st_mode) == stat.S_IFMT(projected.st_mode)
    ), "Nested mode projection must preserve real file kind, link count, size and identity."


@pytest.mark.parametrize("track", ["whole1337", "external-nuclei"])
@pytest.mark.parametrize("empty", [False, True], ids=["matching", "empty-unproven"])
@pytest.mark.parametrize("container_paths", [False, True], ids=["host-spelling", "linux-container"])
def test_ActualProducerOriginalsBindThroughV2WithoutInvocationRewriting(
    tmp_path, monkeypatch, track, empty, container_paths
):
    """Real producer/model/evidence paths preserve originals under inert execution."""

    root, manifest_raw, outcome = ProducedBundle(tmp_path, monkeypatch, track, empty=empty,
                                                container_paths=container_paths)
    original = (root / "scan/invocation.json").read_bytes()
    imported = tmp_path / "imported"
    bundle = originals.BindApplicationBundle(ExportBundle(root, outcome).encode(), imported,
        manifest_raw, "a" * 40, track, "/metrics", "d" * 64, OWNER)
    assert (imported / "scan/invocation.json").read_bytes() == original, (
        "The v2 assembler must consume unchanged original producer invocation bytes"
    )
    pack, target = LoadPack()

    for selected in pack["scanner_tracks"]:
        selected["implementation"] = "available"

    provenance = tmp_path / "target-provenance.json"
    WriteJson(provenance, {"source_revision": target["source_revision"],
        "image_index_digest": target["index_digest"], "platform_digest": target[
            "platform_digests"]["linux/amd64"], "target_url": "http://127.0.0.1:3000/metrics",
        "target_instance": "d" * 64, "reset_contract_sha256": "f" * 64,
        "network_internal": True, "published_ports": 0})
    observation = originals.Observation(pack, target, pack["cases"][0], track, tmp_path,
                                        imported, provenance, bundle["outcome"])
    report = BuildComparison(pack, target, [observation], tmp_path)
    counts = report["finite_completed_case_counts"][track]
    assert counts["tp"] == int(not empty) and counts["tn"] == counts["fn"] == 0, (
        "Only original exact mapped matches may score; exit-zero empty output gets no TN/FN"
    )


@pytest.mark.parametrize("mutation", ["kind", "budget", "raw", "source", "flag", "template-path"])
@pytest.mark.parametrize("container_paths", [False, True], ids=["host-spelling", "linux-container"])
def test_OriginalAssemblyRejectsConsistentlyRehashedButContradictoryClaims(
    tmp_path, monkeypatch, mutation, container_paths
):
    """Valid transport hashes cannot replace exact case/source/flags or original raw identities."""

    root, manifest_raw, outcome = ProducedBundle(tmp_path, monkeypatch, "external-nuclei",
                                                container_paths=container_paths)

    if mutation == "kind":
        selected = originals.Json(root, "case-selection.json")
        selected["scanner_track"] = "whole1337"
        WriteJson(root / "case-selection.json", selected)

    elif mutation == "budget":
        invocation = originals.Json(root, "scan/invocation.json")
        invocation["effective_budget"]["max_response_bytes"] = 262144
        WriteJson(root / "scan/invocation.json", invocation)

    elif mutation == "raw":
        (root / "scan/stdout.raw").write_bytes(b"")

    elif mutation == "source":
        manifest = json.loads(manifest_raw)
        manifest["source_revision"] = "0" * 40
        (root / "image-provisioning.json").write_text(json.dumps(manifest))

    elif mutation in {"flag", "template-path"}:
        invocation = originals.Json(root, "scan/invocation.json")
        argv = invocation["argv"]

        if mutation == "flag":
            argv[argv.index("-rl") + 1] = "2"

        else:
            argv[argv.index("-t") + 1] += ".wrong"

        WriteJson(root / "scan/invocation.json", invocation)

    with pytest.raises(ValueError):
        originals.BindApplicationBundle(ExportBundle(root, outcome).encode(), tmp_path / "imported",
            manifest_raw, "a" * 40, "external-nuclei", "/metrics", "d" * 64, OWNER)


def InertApplicationHost(tmp_path, monkeypatch, fault=None):
    """Replace external boundaries while exercising the actual case lifecycle."""

    from tests.contract.test_external_nuclei_host import RawContainer, Termination

    pack, target = LoadPack()

    for track in pack["scanner_tracks"]:
        track["implementation"] = "available"

    host = lifecycle.NucleiComparisonHost(tmp_path, pack, target)
    host.root = tmp_path / "run"
    host.root.mkdir()
    host.owner, host.revision, host.tree = OWNER, REVISION, "c" * 40
    host.source, host.manifest_raw = {}, b"inert original material manifest"
    _, host.image = Images()
    host.images[host.tags[1]] = host.image["id"]
    host.receipt["governed_no_home_compatibility"] = "established"
    WriteJson(host.root / "context-inventory.json", {"revision": REVISION, "tree": host.tree})
    events, present, active = [], [False], [None]

    class Target:
        """Labeled synthetic fresh target lifecycle; no Docker or HTTP operation is available."""

        def __init__(self, owner, directory):
            """Assign a new explicit target ID without discovering any actual service."""

            self.target_absent = False
            self.project_name = "inert-target"
            self.observations = []
            self.provenance = {"container_id": f"{len(owner.targets) + 1:064x}",
                "platform_manifest_digest": target["platform_digests"]["linux/amd64"]}
            active[0] = self

        def Start(self):
            """Record synthetic startup without launching or contacting a target."""

            events.append("target-start")

        def Stop(self):
            """Require scanner removal first, reflecting actual target namespace teardown order."""

            assert not present[0], "Runner must be removed before target namespace teardown"
            self.target_absent = True
            events.append("target-stop")

    async def Source(role):
        """Supply clearly substituted committed source facts without invoking Git."""

        return REVISION, host.tree

    def AdmitTarget(lab):
        """Admit only this fixture's unique synthetic ID without claiming kernel enforcement."""

        identifier = lab.provenance["container_id"]
        assert identifier not in host.targets, "Every configured case must get a fresh target"
        host.targets.add(identifier)

        return identifier

    async def Inspect(kind, identifier, role):
        """Return explicit synthetic original-shaped state for the actual strict projections."""

        raw = RawContainer()
        raw["Name"] = "/" + host.name
        raw["HostConfig"]["NetworkMode"] = "container:" + active[0].provenance["container_id"]
        raw["NetworkSettings"]["Networks"] = {}
        case = next(item for item in pack["cases"] if item["path"] == active[0].path)
        raw["Config"]["Cmd"] = list(ApplicationCommand(active[0].track, case["path"],
            active[0].provenance["container_id"], OWNER))

        if role != "case-before":
            raw["State"] = Termination()

        if fault == "image" and role == "case-before":
            raw["Image"] = "sha256:" + "0" * 64

        return raw

    async def Command(role, arguments, **options):
        """Retain inert original command files while simulating only owned daemon transitions."""

        events.append(role)
        directory = host.root / ("command-" + str(len(host.receipt["commands"])))
        directory.mkdir()
        argv = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "--config",
                "/owned/config", *arguments]
        host.receipt["commands"].append({"directory": str(directory), "argv": argv, "role": role})
        stdout = b""

        if role == "case-create":
            present[0] = True
            index = list(arguments).index("--track")
            active[0].track, active[0].path = arguments[index + 1], arguments[index + 3]
            stdout = b"ambiguous-id" if fault == "create" else (
                RawContainer()["Id"] + "\n").encode()

        elif role == "case-attach":
            stdout = b"inert original image bundle"

        elif role == "cleanup-owner-list":
            stdout = (RawContainer()["Id"] + "\n").encode() if present[0] else b""

        elif role == "cleanup-remove":
            present[0] = False

        (directory / "stdout.raw").write_bytes(stdout)
        (directory / "stderr.raw").write_bytes(b"inert no-process diagnostic")
        streams = {"stdout": stdout, "stderr": b"inert no-process diagnostic"}
        WriteJson(directory / "command.json", {"argv": argv, "exit_code": 0,
            "cleanup_confirmed": True, "streams_complete": True, "timed_out": False,
            "launch_error": None, "capture_error": None, "interrupted": None,
            "duration_seconds": 0.01, **{role: {"size_bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest()} for role, raw in streams.items()}})

        if fault == "attach" and role == "case-attach":
            raise ValueError("inert failed attachment")

        return {"argv": argv, "exit_code": 0}, stdout

    def OriginalObservation(pack, target, case, track, root, scanner, provenance, outcome):
        """Replace bundle contents explicitly; actual producer-to-bundle checks run separately."""

        result = ContractNucleiObservation(pack, target, root, case_id=case["id"],
                                           track=track, matched=case["expected"])
        result["execution"]["target_instance"] = active[0].provenance["container_id"]
        result["execution"]["target_url"] = "http://127.0.0.1:3000" + case["path"]
        result["execution"]["effective_budget"] = {"request_timeout_seconds": 3,
            "operation_timeout_seconds": 3, "max_requests": 1,
            "max_response_bytes": 1048576, "rate_limit": 1}

        for finding in result["execution"]["findings"]:
            finding["target_url"] = result["execution"]["target_url"]

        WriteNucleiContractEvidence(result, root)

        return result

    monkeypatch.setattr(lifecycle, "ComparisonTargetLab", Target)
    monkeypatch.setattr(host, "Source", Source)
    monkeypatch.setattr(host, "AdmitTarget", AdmitTarget)
    monkeypatch.setattr(host, "Inspect", Inspect)
    monkeypatch.setattr(host, "Command", Command)
    monkeypatch.setattr(lifecycle, "BindApplicationBundle", lambda *_args: {"outcome": {}})
    monkeypatch.setattr(lifecycle, "Observation", OriginalObservation)
    # Actual reset bytes are selected from this repository; the target transport remains replaced.
    host.repository = originals.Path(__file__).absolute().parents[2]

    return host, events


def test_InertSixCaseOwnerUsesFreshTargetsAndRemovesRunnerBeforeTarget(tmp_path, monkeypatch):
    """Exercise all six orchestration slots without a genuine binary, Docker or target contact."""

    host, events = InertApplicationHost(tmp_path, monkeypatch)

    for track in ("whole1337", "external-nuclei"):
        for case in host.pack["cases"]:
            observation = host.RunCase(track, case)
            assert observation["status"] in {"completed", "unproven"}, (
                "The inert owner fixture must traverse actual source lifecycle and v2 publication"
            )

    assert len(host.targets) == len(host.observations) == 6, (
        "Every track/case slot must own a fresh distinct target instance"
    )
    assert events.count("case-attach") == events.count("cleanup-remove") == (
        events.count("target-stop")
    ) == 6, "Every attempted runner must terminate and be removed before its target stops"


@pytest.mark.parametrize("fault,expected", [("image", "prerequisite-failed"),
    ("create", "prerequisite-failed"), ("attach", "failed")])
def test_InertLifecycleRetainsBeforeStartVersusFailedAttempt(
    tmp_path, monkeypatch, fault, expected
):
    """An invalid pre-start image earns no execution; failed attachment stays failed."""

    host, events = InertApplicationHost(tmp_path, monkeypatch, fault=fault)
    observation = host.RunCase("whole1337", host.pack["cases"][0])
    assert observation["status"] == expected and observation["execution"] is None, (
        "The matrix must distinguish missing prerequisites from a source-proven failed host attempt"
    )
    assert ("case-attach" in events) is (fault == "attach") and "target-stop" in events, (
        "Refused pre-start conditions cannot reach a provider; both paths require cleanup"
    )


@pytest.mark.parametrize("track", ["whole1337", "external-nuclei"])
@pytest.mark.parametrize("fault", ["container-exit", "oom", "restart", "running",
                                   "attach-exit", "attach-missing-exit", "attach-bool-exit"])
def test_LateHostTerminalFailureRetainsProviderFactsWithoutCompletionCredit(
    tmp_path, monkeypatch, track, fault
):
    """An original provider match cannot overrule failed enclosing Docker terminal facts."""

    host, events = InertApplicationHost(tmp_path, monkeypatch)
    original_inspect, original_command = host.Inspect, host.Command

    async def Inspect(kind, identifier, role):
        """Change only the independently observed late container state in this inert fixture."""

        value = await original_inspect(kind, identifier, role)

        if role == "case-after":
            if fault == "container-exit":
                value["State"]["ExitCode"] = 137

            elif fault == "oom":
                value["State"]["OOMKilled"] = True

            elif fault == "restart":
                value["RestartCount"] = 1

            elif fault == "running":
                value["State"]["Running"] = True

        return value

    async def Command(role, arguments, **options):
        """Keep original bundle bytes while changing only the inert attach terminal code."""

        result, raw = await original_command(role, arguments, **options)

        if role == "case-attach" and fault.startswith("attach-"):
            result["exit_code"] = {"attach-exit": 1, "attach-missing-exit": None,
                                   "attach-bool-exit": False}[fault]
            path = host.receipt["commands"][-1]["directory"] + "/command.json"
            metadata = json.loads(originals.Path(path).read_bytes())
            metadata["exit_code"] = result["exit_code"]
            WriteJson(originals.Path(path), metadata)

        return result, raw

    monkeypatch.setattr(host, "Inspect", Inspect)
    monkeypatch.setattr(host, "Command", Command)
    observation = host.RunCase(track, host.pack["cases"][0])
    assert observation["status"] == "failed" and observation["execution"] is not None, (
        "Late enclosing-process failure must retain valid provider facts as failed, never completed"
    )
    assert observation["execution"]["exit_code"] == 0 and len(
        observation["execution"]["findings"]
    ) == 1, "An enclosing Docker failure must not relabel the original provider exit or match"
    counts = BuildComparison(host.pack, host.target, host.observations, host.root)[
        "finite_completed_case_counts"][track]
    assert counts["tp"] == counts["tn"] == counts["fn"] == 0, (
        "A failed enclosing attempt cannot earn matching or absence credit"
    )
    assert events.count("cleanup-remove") == events.count("target-stop") == 1, (
        "Late terminal refusal still owns scanner removal before target teardown"
    )


def ComparisonGateFixture(tmp_path, monkeypatch):
    """Create marked synthetic gate originals using the actual inert six-slot lifecycle fixture."""

    host, _ = InertApplicationHost(tmp_path, monkeypatch)

    for track in ("whole1337", "external-nuclei"):
        for case in host.pack["cases"]:
            host.RunCase(track, case)

    image = {"source_revision": REVISION, "installed": {"installed": {"source_revision": REVISION}},
             "material": {"executable": {"sha256": "a" * 64}}}
    prerequisite = host.root / "governed-prerequisite"
    prerequisite.mkdir()
    WriteJson(prerequisite / "image-provisioning.json", image)
    WriteJson(prerequisite / "prerequisites.json", {
        "governed_no_home_compatibility": "established"})
    (host.root / "runner.iid").write_text(host.image["id"])
    host.receipt.update(status="completed-comparison", source_revision=REVISION,
                        source_tree=host.tree, image_id=host.image["id"])
    WriteJson(host.root / "host.json", host.receipt)
    destination = tmp_path / "functional-evidence/external-nuclei-prerequisites" / (
        "run-" + OWNER[:12])
    destination.parent.mkdir(parents=True)
    host.root.rename(destination)
    cases = "".join('<testcase classname="tests.functional.test_external_nuclei_benchmark" '
        f'name="test_GenuineNucleiApplicationComparison[{case}-{track}]"/>'
        for case in ("metrics.exposed", "metrics.json-control", "metrics.html-control")
        for track in ("whole1337", "external-nuclei"))
    junit = '<testsuites><testsuite tests="6" failures="0" errors="0" skipped="0">' + (
        cases + '</testsuite></testsuites>')
    (tmp_path / "functional-evidence/nuclei-comparison.xml").write_text(junit)

    return destination


@pytest.mark.parametrize("mutation", [None, "skip", "wrong-head", "reused-target", "count",
                                      "original-bytes", "cleanup"])
def test_FinalComparisonGateRequiresSixOriginalExecutedCases(tmp_path, monkeypatch, mutation):
    """The read-only gate refuses stale, skipped, rehashed or uncleaned evidence."""

    from tests.functional.external_nuclei_comparison_gate import Verify

    root = ComparisonGateFixture(tmp_path, monkeypatch)
    report = originals.Json(root, "comparison.json")

    if mutation == "skip":
        path = tmp_path / "functional-evidence/nuclei-comparison.xml"
        path.write_text(path.read_text().replace('skipped="0"', 'skipped="1"'))

    elif mutation == "wrong-head":
        host = originals.Json(root, "host.json")
        host["source_revision"] = "0" * 40
        WriteJson(root / "host.json", host)

    elif mutation == "reused-target":
        report["observations"][1]["execution"]["target_instance"] = report[
            "observations"][0]["execution"]["target_instance"]
        WriteJson(root / "comparison.json", report)

    elif mutation == "count":
        report["finite_completed_case_counts"]["whole1337"].update(tn=2, unscored=0)
        WriteJson(root / "comparison.json", report)

    elif mutation == "original-bytes":
        record = report["observations"][0]["execution"]["evidence"][0]
        (root / record["path"]).write_bytes(b"substituted original")

    elif mutation == "cleanup":
        host = originals.Json(root, "host.json")
        host["cleanup"][0]["container_absent"] = False
        WriteJson(root / "host.json", host)

    if mutation is None:
        assert Verify(tmp_path, REVISION, "c" * 40) == {
            "executed_cases": 6, "fresh_targets": 6, "nuclei_tp": 2, "unproven": 4}, (
            "Synthetic gate fixtures cannot establish genuine scanner acceptance"
        )

    else:
        with pytest.raises(ValueError):
            Verify(tmp_path, REVISION, "c" * 40)


def test_FrozenProviderProvenanceKeepsIndependentInputsAndEffectiveDeviations():
    """Provenance cannot change the case oracle, rule review or official release pin."""

    from pathlib import Path

    from tests.functional.external_nuclei_runner import (
        ARCHIVE_BYTES,
        ARCHIVE_SHA256,
        TEMPLATE_REVIEW,
        EffectiveBudget,
    )

    repository = Path(__file__).absolute().parents[2]
    path = repository / "labs/external/benchmark/nuclei-provider.v1.json"
    record = json.loads(path.read_bytes())
    pack, target = LoadPack()
    assert record["schema_version"] == 1 and record["comparison_id"] == pack["pack_id"] and (
        record["provider"]["version"] == "3.4.10"
        and record["provider"]["archive_sha256"] == ARCHIVE_SHA256
        and record["provider"]["archive_size_bytes"] == ARCHIVE_BYTES
        and record["rule"]["review_reference"] == TEMPLATE_REVIEW
        and record["target"]["source_revision"] == target["source_revision"]
        and record["target"]["image_index_digest"] == target["index_digest"]
        and record["effective_nuclei_budget"] == EffectiveBudget()
    ), "Frozen upstream inputs and the independently declared oracle must not drift with an outcome"
    assert record["effective_nuclei_budget"] != pack["requested_budget"], (
        "Provenance must retain actual3s/1MiB deviations from requested10s/256KiB limits"
    )
