# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Genuine installed native configuration SDK/CLI acceptance on unchanged owned source specimens."""

from __future__ import annotations

import asyncio
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, ImpactLevel, SerializeContract
from fuzzy1337.artifact_inputs import ArtifactProfile, ArtifactReadConsent
from fuzzy1337.artifact_policy import ArtifactDeniedError
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.executors import (
    CapabilityDescriptor,
    ExecutionAuthorization,
    ExecutionResources,
    ExecutionTermination,
    InvocationDigest,
    LocalExecutionRequest,
    LocalExecutor,
)
from fuzzy1337.executors.owned_process import RequireLinuxOwnership
from fuzzy1337.findings import Findings
from fuzzy1337.jobs import JobEventKind, JobState
from fuzzy1337.model import LocalModelStore
from fuzzy1337.native_configuration import NativeConfigurationSelection
from fuzzy1337.native_configuration_evidence import VerifyNativeConfigurationReplay
from fuzzy1337.native_configuration_workflow import (
    PlanNativeConfigurationScan,
    ScanNativeConfiguration,
)
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy
from fuzzy1337.scan_commands import CreateWorkspace
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)

OWNER = "owner:installed-native-configuration"
CASE_IDS = (
    "dockerfile.root-user", "dockerfile.non-root-user", "kubernetes.privileged-container",
    "kubernetes.non-privileged-container", "kubernetes.second-document",
    "approval-refused", "scope-refused", "invalid-utf8-refused", "oversized-source-refused",
    "unsupported-executable-refused",
)
ROLE_LIMITS = {"native-configuration-version-stdout": 16 * 1024,
    "native-configuration-version-stderr": 16 * 1024,
    "native-configuration-version-receipt": 256 * 1024,
    "native-configuration-scan-stdout": 1024 * 1024,
    "native-configuration-scan-stderr": 64 * 1024,
    "native-configuration-scan-receipt": 256 * 1024,
    "native-configuration-source": 4096}


def Canonical(value: object) -> bytes:
    """Encode handwritten expected metadata without production identity or report builders."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def Digest(path: Path) -> str:
    """Hash explicitly selected physical bounded files without executing their bytes."""

    assert path.is_file() and not path.is_symlink() and path.stat().st_size <= 256 * 1024**2, (
        "Installed acceptance may hash only explicitly selected bounded physical files"
    )

    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def ReadJson(path: Path, maximum: int = 1024 * 1024) -> dict:
    """Read explicit bounded synthetic acceptance metadata, refusing oversized context."""

    assert path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum, (
        "Installed acceptance metadata must be physical and bounded"
    )

    with path.open("rb") as source:
        raw = source.read(maximum + 1)

    assert len(raw) <= maximum, "Installed acceptance metadata grew beyond its bound"

    return json.loads(raw)


def InstalledModuleHashes(context: dict) -> dict[str, str]:
    """Bind every loaded first-party module to its original noneditable wheel member."""

    prefix = Path(context["environment"])
    package = Path(sys.modules["fuzzy1337"].__file__).parent
    hashes = {}

    for name, module in tuple(sys.modules.items()):
        if name != "fuzzy1337" and not name.startswith("fuzzy1337."):
            continue

        path = Path(module.__file__).resolve()
        assert path.is_relative_to(prefix), "First-party code escaped the installed environment"
        member = "fuzzy1337/" + path.relative_to(package).as_posix()
        digest = Digest(path)
        assert digest == context["source_hashes"][member], "Installed source differs from its wheel"
        hashes[name] = digest

    return hashes


@pytest.fixture(scope="module")
def installed_product():
    """Require actual installed/no-egress prerequisites; absent optional context is unexecuted."""

    selected = os.environ.get("FUZZY1337_CONFIGURATION_PRODUCT_CONTEXT")

    if selected is None:
        pytest.skip("Genuine installed product acceptance is UNRUN without its dedicated context")

    context = ReadJson(Path(selected))
    assert sys.platform == "linux" and platform.machine() == "x86_64" and os.geteuid() != 0, (
        "Required installed native product proof needs its ordinary Linux x86_64 owner"
    )
    RequireLinuxOwnership()
    assert sys.flags.isolated and Path(sys.executable).absolute() == Path(context["interpreter"]), (
        "Controller, pytest workers, helpers and CLI must use the isolated installed interpreter"
    )
    assert Path(sys.prefix) == Path(context["environment"]) and Path.cwd() == Path(
        context["run_directory"]
    ), "Product acceptance must run from its outside-checkout installed environment"
    repository = Path(context["repository"])
    assert not Path.cwd().is_relative_to(repository) and "PYTHONPATH" not in os.environ and all(
        not Path(value).absolute().is_relative_to(repository) for value in sys.path if value
    ), "Installed product acceptance must not import the checkout"
    distribution = importlib.metadata.distribution("1337")
    direct = json.loads(distribution.read_text("direct_url.json"))
    assert "dir_info" not in direct and direct["url"].endswith(context["wheel"]["name"]), (
        "Actual product imports must originate from the built wheel without editability"
    )

    for name, digest in context["copied_hashes"].items():
        assert Digest(Path.cwd() / name) == digest, "Copied source differs from its revision"

    namespace = os.readlink("/proc/self/ns/net")
    assert namespace != os.environ["FUZZY1337_CONFIGURATION_PRODUCT_HOST_NETNS"], (
        "Required product execution must not reuse the provisioning network namespace"
    )
    assert socket.if_nameindex() == [(1, "lo")], "Product namespace may expose only loopback"
    routes = Path("/proc/net/route").read_text().splitlines()[1:]
    assert all(int(line.split()[1], 16) == int(line.split()[2], 16) == 0 for line in routes), (
        "Product namespace must contain no external IPv4 route"
    )
    assert all(line.split()[0] == "0" * 32 for line in
               Path("/proc/net/ipv6_route").read_text().splitlines()), (
        "Product namespace must contain no external IPv6 route"
    )
    executable = Path(context["provisioning"]["executable"])
    assert Digest(executable) == context["provisioning"]["executable_sha256"], (
        "Required product executable must retain its independently pinned original release bytes"
    )
    context["network_namespace"] = namespace
    context["oracle"] = ReadJson(Path.cwd() / "configuration_oracle.json")

    return context


def Policy(kind: str) -> ImpactPolicy:
    """Grant exactly the independently selected native SAFE config capability, without approval."""

    return ImpactPolicy("owned-native-configuration-product", permissions=(CapabilityPermission(
        "config." + kind + "-misconfigurations", "native.trivy", ImpactLevel.SAFE),))


def Owned(root: Path, case: dict, context: dict):
    """Create canonical stores and exact selected copies of unchanged pinned specimens."""

    CreateWorkspace(root, "owned-native-configuration", "Owned native configuration acceptance")
    item = case["inputs"][0]
    original = Path(context["run_directory"]) / "specimens" / item["fixture"]
    source = original.read_bytes()
    assert len(source) == item["sizeBytes"] and hashlib.sha256(source).hexdigest() == (
        item["sha256"]
    ), (
        "Owned original specimens must never be changed to fit actual scanner output"
    )
    selected_source = root / "selected-source"
    selected_source.write_bytes(source)
    executable = root / "selected-trivy"
    shutil.copyfile(Path(context["provisioning"]["executable"]), executable)
    executable.chmod(0o600)
    profile = "trivy." + case["scanner"] + "-offline.v1"
    manifest = {"schema_version": 1, "profile": profile, "role": "input", "files": [{
        "name": item["logicalPath"], "size_bytes": item["sizeBytes"], "sha256": item["sha256"]}]}
    target = Target(TargetKind.ARTIFACT, "manifest-sha256:" + hashlib.sha256(
        Canonical(manifest)).hexdigest())
    now = datetime.now(UTC)
    LocalScopeStore(root).Create(ScopeSnapshot("owned", "owned-native-configuration",
        ScopeAuthorization(AuthorizationState.GRANTED, "attester:owned-native-config",
            "consent:owned-native-config", (now - timedelta(minutes=1)).isoformat(),
            (now + timedelta(minutes=30)).isoformat()), targets=(target,), allow=(target,)))
    selection = NativeConfigurationSelection(ArtifactProfile(profile), item["logicalPath"],
        selected_source, executable, ArtifactReadConsent(OWNER, "read:owned-source-and-provider"))

    return selection, target, source


def AssertOriginalPair(root: Path, records: tuple, case: dict, source: bytes) -> None:
    """Inspect raw native JSON against independent selected rules and exact seven-role custody."""

    roles = {record.reference.role: record for record in records}
    assert len(records) == 7 and set(roles) == set(ROLE_LIMITS), (
        "Every original successful pair must retain all seven distinct immutable roles"
    )
    store = LocalEvidenceStore(root / "evidence")
    raw = {}

    for role, record in roles.items():
        assert record.reference.size_bytes <= ROLE_LIMITS[role], "Original role exceeds its bound"
        assert store.Get(record.evidence_id) == record, "Original immutable record identity changed"
        raw[role] = store.Read(record.reference)
        assert hashlib.sha256(raw[role]).hexdigest() == record.reference.sha256, (
            "Original immutable blob differs from its acquisition digest"
        )

    assert raw["native-configuration-source"] == source, "Evidence must retain exact source"
    assert json.loads(raw["native-configuration-version-stdout"])["Version"] == "0.75.0", (
        "Original VERSION must positively observe the independently pinned provider"
    )
    report = json.loads(raw["native-configuration-scan-stdout"])
    assert report["SchemaVersion"] == 2 and len(report["Results"]) == 1, (
        "Actual native JSON must positively process exactly the selected source"
    )
    result = report["Results"][0]
    assert result["Target"] == case["inputs"][0]["logicalPath"] and (
        result["Class"] == "config" and
        result["Type"] == case["scanner"]
    ), "Actual selected native file/type identity must match the unchanged independent oracle"

    for expected in case["requiredChecks"]:
        candidates = [row for row in result["Misconfigurations"] if row["ID"] == expected["id"]
                      and row["Status"] == expected["status"]]
        assert len(candidates) == 1, "Native output lacks its independent required check/status"
        row = candidates[0]

        for oracle_key, provider_key in (("nativeStartLine", "StartLine"),
                                          ("nativeEndLine", "EndLine")):
            if oracle_key in expected:
                assert row["CauseMetadata"][provider_key] == expected[oracle_key], (
                    "Native source coordinates must match the independently authored source oracle"
                )

    for operation in ("version", "scan"):
        receipt = json.loads(raw["native-configuration-" + operation + "-receipt"])
        assert receipt["refusal"] is None and receipt["cleanup_confirmed"] is True and (
            receipt["raw_facts"]["execution"]["state"] == "succeeded"
            and receipt["raw_facts"]["execution"]["exit_code"] == 0
            and receipt["raw_facts"]["termination"] == "process_exit"
            and receipt["prepared"]["operation"] == operation
        ), "Original receipt must preserve successful actual terminal process and cleanup facts"
        argv = receipt["request"]["invocation"]["argv"]
        assert argv[0] == str(root / "selected-trivy") and "--config=" in argv, (
            "Native invocation must use the exact selected pinned executable and empty config"
        )

        if operation == "scan":
            assert "config" in argv and "--include-non-failures" in argv and (
                "--skip-check-update" in argv and "--skip-version-check" in argv
                and "--disable-telemetry" in argv and "--ignorefile=" in argv
                and argv[argv.index("--misconfig-scanners") + 1] == case["scanner"]
            ), "Actual SCAN must retain its fixed embedded-check-only configuration grammar"

    loader = raw["native-configuration-scan-stderr"].decode()
    assert "Embedded libraries are loaded" in loader and "Embedded checks are loaded" in loader, (
        "Original provider debug evidence must positively identify embedded checks and libraries"
    )
    assert all(value not in loader for value in ("Checks from disk are loaded",
        "Checks from readers are loaded", "Overriding filesystem for checks")), (
        "Actual provider cannot load unselected external checks"
    )
    VerifyNativeConfigurationReplay(records, root)


def AssertSelectedFindings(root: Path, case: dict) -> None:
    """Compare saved selected native Findings to handwritten oracle expectations."""

    findings = Findings(LocalModelStore(root).Open())

    for expected in case["requiredChecks"]:
        candidates = [item for item in findings if item.check_id ==
                      "configuration.native." + expected["id"].lower()]

        if expected["status"] == "FAIL":
            assert len(candidates) == 1, "Expected native failed rule must become one Finding"
            position = json.loads(candidates[0].location_key)
            assert position["native_check_id"] == expected["id"], (
                "Canonical location must preserve the exact original native rule identity"
            )

            if "nativeStartLine" in expected:
                assert position["start_line"] == expected["nativeStartLine"] and (
                    position["end_line"] == expected["nativeEndLine"]
                ), "Saved Finding coordinates must match the independent original source oracle"

            if "severity" in expected:
                assert candidates[0].severity.value == expected["severity"].lower(), (
                    "Saved native Finding severity must retain independent upstream severity"
                )

        elif not any(item["id"] == expected["id"] and item["status"] == "FAIL"
                     for item in case["requiredChecks"]):
            assert not candidates, "Independent selected safe rule must not become a false Finding"


@pytest.mark.parametrize("case_id", CASE_IDS)
def test_InstalledNativeConfigurationProduct(tmp_path, installed_product, case_id, monkeypatch):
    """Exercise actual installed SDK/CLI originals and meaningful native refusal paths."""

    context = installed_product
    case = next((item for item in context["oracle"]["cases"] if item["caseId"] == case_id),
                context["oracle"]["cases"][0])
    output = Path(context["evidence"]) / case_id
    output.mkdir(mode=0o700)
    root = tmp_path / "owned-product"
    selection, target, source = Owned(root, case, context)
    (output / "original-source.txt").write_bytes(source)
    facts = {"case_id": case_id, "commit": context["commit"], "tree": context["tree"],
        "wheel_sha256": context["wheel"]["sha256"],
        "network_namespace": context["network_namespace"],
        "outcome": "unassessed", "native_product_acceptance": False,
        "original_operations": [], "sdk_evidence_ids": [], "cli_evidence_ids": []}
    original_execute = LocalExecutor.Execute
    provider_results = []
    provider_checkpoints = []

    async def Audit(self, request, **options):
        """Observe actual provider returns and both authority checkpoints without replacing IO."""

        provider = request.invocation.adapter_id == "native.trivy"

        if provider:
            assert options["own_descendants"] is True, "Actual native provider must own descendants"
            original_check = options["pre_launch"]

            def Check(actual):
                """Retain the real executor checkpoint and delegate unchanged current authority."""

                provider_checkpoints.append(request.invocation.request.parameters["operation"])

                return original_check(actual)

            options["pre_launch"] = Check

        outcome = await original_execute(self, request, **options)

        if provider:
            provider_results.append((request, outcome))

        return outcome

    monkeypatch.setattr(LocalExecutor, "Execute", Audit)

    try:
        if case_id in CASE_IDS[:5]:
            preview = asyncio.run(PlanNativeConfigurationScan(root, OWNER, selection))
            assert preview.Target == target and preview.ToDict()["execution_authorized"] is False, (
                "Read planning must preserve the independently calculated target without execution"
            )
            selection.executable.chmod(0o700)
            events = []
            report = output / "sdk-report.json"
            summary = asyncio.run(ScanNativeConfiguration(root, "owned", OWNER, selection,
                lambda: Policy(case["scanner"]), approve_safe_configuration=True,
                report_format="json", report_output=report, on_event=events.append))
            (output / "sdk-summary.json").write_bytes(Canonical(summary.ToDict()))
            assert summary.ExitCode() == 0 and summary.snapshot.state is JobState.COMPLETED and (
                not summary.custody_uncertain and summary.report.output_published
            ), "Actual governed SDK must save native Findings and export its committed report"
            assert len([item for item in events if item.kind is JobEventKind.MODEL_DELTA]) == 1, (
                "Actual SDK model delta must follow the acknowledged durable save"
            )
            assert provider_checkpoints == ["version", "version", "scan", "scan"], (
                "Actual original native processes must pass both initial and READY authority checks"
            )
            assert len(provider_results) == 2 and all(
                actual is captured.outcome and request is captured.request
                for (request, actual), captured in zip(provider_results, summary.captures,
                                                       strict=True)
            ), "SDK captures must retain exact independently observed actual executor originals"
            AssertOriginalPair(root, summary.retained_records, case, source)
            AssertSelectedFindings(root, case)
            facts["original_operations"] = [item.Operation for item in summary.captures]
            facts["sdk_evidence_ids"] = [item.evidence_id for item in summary.retained_records]
            policy = root / "policy.json"
            policy.write_text(SerializeContract(Policy(case["scanner"])))
            arguments = ["scan", "config", str(root), "--profile", "native", "--type",
                case["scanner"], "--logical-path", selection.logical_path,
                "--source", str(selection.source), "--scope", "owned", "--owner", OWNER,
                "--executable", str(selection.executable), "--read-consent-reference",
                selection.read_consent.record_ref, "--policy", str(policy),
                "--approve-safe-configuration", "--json"]
            completed = subprocess.run([sys.executable, "-I", "-m", "fuzzy1337", *arguments],
                capture_output=True, timeout=120, check=False)
            (output / "cli-stdout.json").write_bytes(completed.stdout)
            (output / "cli-stderr.txt").write_bytes(completed.stderr)
            assert completed.returncode == 0, "Installed native configuration CLI must succeed"
            cli = json.loads(completed.stdout)
            assert cli["state"] == "completed" and cli["workflow"] == "native-configuration", (
                "CLI must expose its actual native terminal workflow facts"
            )
            cli_records = tuple(LocalEvidenceStore(root / "evidence").Get(identity)
                                for identity in cli["retained_evidence_ids"])
            AssertOriginalPair(root, cli_records, case, source)
            AssertSelectedFindings(root, case)
            facts["cli_evidence_ids"] = list(cli["retained_evidence_ids"])
            relocated = output / "relocated-workspace"
            shutil.copytree(root, relocated, ignore=shutil.ignore_patterns(
                "selected-trivy", "selected-source", ".native-configuration-claims", "policy.json"))
            VerifyNativeConfigurationReplay(summary.retained_records, relocated)
            facts["native_product_acceptance"] = True

        else:
            selection.executable.chmod(0o700)

            if case_id == "approval-refused":
                with pytest.raises(ArtifactDeniedError):
                    asyncio.run(ScanNativeConfiguration(root, "owned", OWNER, selection,
                        lambda: Policy(case["scanner"])))

            else:
                if case_id == "scope-refused":
                    store = LocalScopeStore(root)
                    scope = store.Open("owned")
                    from dataclasses import replace

                    store.Save(replace(scope, allow=()))

                elif case_id == "invalid-utf8-refused":
                    selection.source.write_bytes(b"\xff")

                elif case_id == "oversized-source-refused":
                    selection.source.write_bytes(b"#" * 4097)

                else:
                    selection.executable.write_bytes(b"Unsupported inert executable; never run")

                summary = asyncio.run(ScanNativeConfiguration(root, "owned", OWNER, selection,
                    lambda: Policy(case["scanner"]), approve_safe_configuration=True))
                (output / "refused-summary.json").write_bytes(Canonical(summary.ToDict()))
                assert summary.snapshot.state is JobState.FAILED and not summary.captures, (
                    "Actual unsupported material or scope must refuse before provider execution"
                )

            assert LocalModelStore(root).Open().revision == 0, (
                "Refused native inputs must never save canonical model success"
            )
            assert provider_results == [] and provider_checkpoints == [], (
                "Refused inputs must have no independently observed actual native provider launch"
            )

        facts["outcome"] = "installed-product-assertions-passed"

    finally:
        shutil.copytree(root / "evidence", output / "original-evidence", dirs_exist_ok=True)
        controls = root / ".native-configuration-claims"

        if controls.exists():
            shutil.copytree(controls, output / "original-private-controls", dirs_exist_ok=True)

        facts["installed_module_hashes"] = InstalledModuleHashes(context)
        facts["provider_authority_checkpoints"] = provider_checkpoints
        facts["observed_provider_operations"] = [request.invocation.request.parameters["operation"]
                                                   for request, _ in provider_results]
        (output / "case.json").write_bytes(Canonical(facts))


def test_InstalledOwnedHarmlessExecutor(installed_product, tmp_path):
    """Execute a harmless installed producer through actual initial and READY ownership checks."""

    context = installed_product
    assert os.environ.get("FUZZY1337_REQUIRE_OWNED_CONFIGURATION_EXECUTION") == "1", (
        "The installed owned executor case must be required rather than optionally skipped"
    )
    root = tmp_path / "owned-harmless-producer"
    root.mkdir(mode=0o700)
    invocation = AdapterInvocation("owned.configuration-probe", AdapterRequest(
        "config.owned-executor-probe", "owned:harmless-local-producer", ImpactLevel.SAFE),
        (sys.executable, "-I", "-c", "print('owned-configuration-probe')"), 5)
    authorization = ExecutionAuthorization("owned:explicit-local-producer", "scope:owned-producer",
        "policy:owned-producer", InvocationDigest(invocation))
    request = LocalExecutionRequest(invocation, CapabilityDescriptor(
        "config.owned-executor-probe", "owned.configuration-probe", ImpactLevel.SAFE),
        authorization, environment={"PATH": "", "HOME": str(root), "LANG": "C", "LC_ALL": "C"},
        resources=ExecutionResources(max_stdout_bytes=1024, max_stderr_bytes=1024))
    checks = []

    def Check(actual):
        """Observe both real callbacks and retain exact original full-request identity."""

        assert actual is request, "Actual owned checkpoint cannot replace the original request"
        checks.append(InvocationDigest(actual.invocation))

    outcome = asyncio.run(LocalExecutor(root).Execute(request, pre_launch=Check,
                                                      own_descendants=True))
    output = Path(context["evidence"]) / "owned-executor-checkpoints"
    output.mkdir(mode=0o700)
    (output / "original-stdout.bin").write_bytes(outcome.stdout)
    (output / "original-stderr.bin").write_bytes(outcome.stderr)
    facts = {"case_id": "owned-executor-checkpoints", "commit": context["commit"],
        "tree": context["tree"], "wheel_sha256": context["wheel"]["sha256"],
        "installed_module_hashes": InstalledModuleHashes(context),
        "outcome": "unassessed", "native_product_acceptance": False,
        "original_operations": ["owned-harmless-producer"], "sdk_evidence_ids": [],
        "cli_evidence_ids": [], "observed_provider_operations": [],
        "provider_authority_checkpoints": [], "actual_checkpoints": checks,
        "request": json.loads(SerializeContract(request)),
        "execution": json.loads(SerializeContract(outcome.execution)),
        "termination": outcome.termination.value,
        "stdout_sha256": hashlib.sha256(outcome.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(outcome.stderr).hexdigest()}

    try:
        assert checks == [InvocationDigest(invocation)] * 2, (
            "Actual Linux ownership must invoke both initial and READY-to-worker current checks"
        )
        assert outcome.termination is ExecutionTermination.PROCESS_EXIT and (
            outcome.execution.exit_code == 0 and outcome.stdout == b"owned-configuration-probe\n"
            and outcome.stderr == b""
        ), "Actual harmless owned producer must return its exact original output and terminal facts"
        facts["outcome"] = "installed-product-assertions-passed"

    finally:
        (output / "case.json").write_bytes(Canonical(facts))
