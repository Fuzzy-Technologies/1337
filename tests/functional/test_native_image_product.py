# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent genuine Trivy product oracle over the two existing inert Docker-save archives."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from fuzzy1337.adapters import ExecutionState, ImpactLevel, SerializeContract
from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.executors import LocalExecutionError, LocalExecutor
from fuzzy1337.executors.owned_process import RequireLinuxOwnership
from fuzzy1337.findings import Finding, FindingStatus
from fuzzy1337.jobs import JobState
from fuzzy1337.model import CanonicalModelJson, LocalModelStore, ObjectKind, RelationKind
from fuzzy1337.native_image_admission import VerifyNativeTrivyImageReplay
from fuzzy1337.native_image_capture import NativeTrivySelection
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy
from fuzzy1337.scan_commands import CreateWorkspace, OpenWorkspace
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.fixtures.trivy.native_archive import ArchiveBytes
from tests.integration.test_trivy_native import native_runtime as native_runtime

FIXTURES = Path(__file__).parents[1] / "fixtures" / "trivy"
ORACLE = json.loads((FIXTURES / "product_oracle.v1.json").read_bytes())
SOURCE_ORACLE = json.loads((FIXTURES / "native_oracle.json").read_bytes())
EVIDENCE = Path("functional-evidence/native-image-product")
REQUIRED = "FUZZY1337_RUN_NATIVE_IMAGE_PRODUCT_ACCEPTANCE"
OWNER = "actor:owned-native-image-product"
SCAN_TIMEOUT = 30
ROLE_LIMITS = {"provider-version": 16 * 1024, "provider-version-stderr": 16 * 1024,
    "native-version-receipt": 256 * 1024, "stdout": 4 * 1024 * 1024,
    "stderr": 1024 * 1024, "native-scan-receipt": 16 * 1024 * 1024}


@pytest.fixture(scope="module")
def product_runtime(request):
    """Make the required product lane fail before an optional provider fixture can skip."""

    names = ("FUZZY1337_TRIVY_BINARY", "FUZZY1337_TRIVY_CACHE",
             "FUZZY1337_TRIVY_PROVISIONING", "FUZZY1337_TRIVY_HOST_NETNS")
    selected = tuple(os.environ.get(name) for name in names)
    required = os.environ.get(REQUIRED) == "1"

    if not required and all(value is None for value in selected):
        pytest.skip("Optional genuine product material is absent; this is not acceptance")

    assert all(selected), "Required native product acceptance cannot skip missing pinned material"
    assert ORACLE["provider_version"] == SOURCE_ORACLE["provider_version"] == "0.75.0", (
        "The product must retain the independently pinned existing provider version"
    )
    assert ORACLE["release_asset_sha256"] == SOURCE_ORACLE["release_asset_sha256"] and (
        ORACLE["database_repository"] == SOURCE_ORACLE["database_repository"]
    ), "The product oracle cannot replace the original release or official DB digest pins"
    runtime = request.getfixturevalue("native_runtime")

    try:
        RequireLinuxOwnership()

    except LocalExecutionError:
        if required:
            pytest.fail("Required product acceptance lacks actual Linux descendant ownership")

        pytest.skip("Optional genuine ownership is unavailable; this is not acceptance")

    return runtime


def Policy() -> ImpactPolicy:
    """Permit exactly the native SAFE archive capability; product approval remains separate."""

    return ImpactPolicy("owned-native-image-product", permissions=(CapabilityPermission(
        "image.archive-vulnerabilities", "native.trivy", ImpactLevel.SAFE),))


def Canonical(value: object) -> bytes:
    """Encode handwritten expected JSON independently of production identity builders."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def ConfigDigest(archive: bytes) -> str:
    """Read only the existing inert archive's bounded config bytes without extraction."""

    with tarfile.open(fileobj=io.BytesIO(archive)) as stream:
        manifest_file = stream.extractfile("manifest.json")
        assert manifest_file is not None, "Owned archive must contain its literal manifest"
        manifest = json.loads(manifest_file.read(4096))
        assert len(manifest) == 1, "The existing owned fixture has one image only"
        name = manifest[0]["Config"]
        config_file = stream.extractfile(name)
        assert config_file is not None, "Owned image must contain its exact selected config"
        config = config_file.read(4096)

    digest = hashlib.sha256(config).hexdigest()
    assert name == digest + ".json", "The Docker-save config filename must identify actual bytes"

    return "sha256:" + digest


def OwnedSelection(root: Path, case: dict, runtime) -> NativeTrivySelection:
    """Copy only the fixed approved binary/DB selections and the unchanged inert archive."""

    executable, cache, provisioning, _ = runtime
    workspace_id = "native-product-" + case["package_version"].replace(".", "")
    CreateWorkspace(root, workspace_id, "Owned genuine native image product acceptance")
    archive = ArchiveBytes(case["package_version"])
    assert len(archive) == case["archive_size_bytes"] and hashlib.sha256(archive).hexdigest() == (
        case["archive_sha256"]
    ), "Only the original two independently pinned inert archive byte sequences are accepted"
    (root / "owned.tar").write_bytes(archive)
    selected = root / "selected-trivy"
    shutil.copyfile(executable, selected)
    selected.chmod(0o600)

    with selected.open("rb") as copied:
        assert hashlib.file_digest(copied, "sha256").hexdigest() == (
            provisioning["executable_sha256"]
        ), "The nonexecutable planning copy must retain exact independently pinned provider bytes"

    database = root / "trivy-cache" / "db"
    database.mkdir(parents=True)

    for name in ("trivy.db", "metadata.json"):
        shutil.copyfile(cache / "db" / name, database / name)

    return NativeTrivySelection(root, selected, "owned.tar", "trivy-cache",
        ArtifactReadConsent(OWNER, "read:owned-native-product-four-files"))


def RegisterScope(root: Path, case: dict) -> Target:
    """Register the handwritten oracle's literal manifest target with an independent attester."""

    target = Target(TargetKind.ARTIFACT, case["artifact_target_value"])
    workspace_id = LocalWorkspaceStore(root).Open().workspace_id
    now = datetime.now(UTC)
    LocalScopeStore(root).Create(ScopeSnapshot("local", workspace_id, ScopeAuthorization(
        AuthorizationState.GRANTED, "attester:owned-product-consent",
        "consent:owned-native-product",
        (now - timedelta(minutes=1)).isoformat(), (now + timedelta(minutes=30)).isoformat(),
    ), targets=(target,), allow=(target,)))

    return target


def Console(arguments: list[str], output: Path, label: str) -> dict:
    """Exercise the actual installed isolated CLI with a finite complete process budget."""

    result = subprocess.run([sys.executable, "-I", "-m", "fuzzy1337", *arguments, "--json"],
        capture_output=True, timeout=SCAN_TIMEOUT + 85, check=False, shell=False)
    (output / (label + ".stdout")).write_bytes(result.stdout)
    (output / (label + ".stderr")).write_bytes(result.stderr)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")[:4096]

    return json.loads(result.stdout)


def CheckPair(root: Path, records: tuple, case: dict, target: Target, provisioning: dict):
    """Independently inspect original raw custody, literal argv, events and advisory correlation."""

    assert len(records) == 6, "A product pair must retain exactly six original acquisition roles"
    store = LocalEvidenceStore(root / "evidence")
    roles = {record.reference.role: record for record in records}
    assert set(roles) == set(ROLE_LIMITS), "Original native acquisition roles must remain unchanged"
    raw = {}

    for role, record in roles.items():
        assert record.reference.size_bytes <= ROLE_LIMITS[role], "Original role exceeded its bound"
        assert store.Get(record.evidence_id) == record, "Original acquisition identity changed"
        raw[role] = store.Read(record.reference)
        assert hashlib.sha256(raw[role]).hexdigest() == record.reference.sha256, (
            "Original raw bytes must match their separately retained blob identity"
        )

    version = json.loads(raw["native-version-receipt"])
    scan = json.loads(raw["native-scan-receipt"])
    executable = str(root / "selected-trivy")
    cache = str(root / "trivy-cache")
    version_argv = [executable, "--cache-dir", cache, "--config=", "--version", "--format", "json"]
    scan_argv = [executable, "--cache-dir", cache, "--config=", "image", "--input",
        str(root / "owned.tar"), "--format", "json", "--scanners", "vuln", "--disable-telemetry",
        "--offline-scan", "--skip-db-update", "--skip-java-db-update", "--skip-check-update",
        "--skip-version-check", "--skip-vex-repo-update", "--ignorefile=", "--list-all-pkgs",
        "--exit-code", "0", "--no-progress", "--timeout", str(SCAN_TIMEOUT) + "s"]

    for receipt, operation, wanted_argv, stream_roles in (
        (version, "version", version_argv, ("provider-version", "provider-version-stderr")),
        (scan, "scan", scan_argv, ("stdout", "stderr")),
    ):
        assert receipt["schema_version"] == 1 and receipt["operation"] == operation, (
            "Product custody must preserve the original schema-one operation discriminator"
        )
        assert receipt["refusal"] is None and receipt["execution"]["state"] == "succeeded" and (
            receipt["execution"]["exit_code"] == 0 and receipt["termination"] == "process_exit"
        ), "Genuine original successful execution is required; empty/refused output is unassessed"
        request = receipt["request"]
        invocation = request["invocation"]
        assert invocation["argv"] == wanted_argv, "The product changed its finite offline argv"
        assert invocation["request"]["target_reference"] == target.Reference(), (
            "Original execution must bind the literal independently registered artifact target"
        )
        assert request["authorization"]["policy_reference"] == Policy().Reference(), (
            "SAFE product opt-in cannot replace the explicit native policy permission"
        )
        assert request["authorization"]["scope_reference"] == "scope:local", (
            "Each original grant must retain the exact current registered scope"
        )
        assert request["authorization"]["invocation_sha256"] == hashlib.sha256(
            Canonical(invocation)).hexdigest(), "Original authorization must bind its invocation"
        assert receipt["owner_reference"] == receipt["read_consent"]["actor_ref"] == OWNER, (
            "Execution ownership must match read consent without rewriting the recorded attester"
        )
        assert receipt["material_before"] == receipt["material_after"], (
            "Genuine offline execution must preserve all four selected material facts"
        )
        facts = {item["role"]: item for item in receipt["material_before"]}
        assert list(facts) == ["archive", "executable", "database", "database-metadata"], (
            "The existing ordered selected-material roles must remain exact"
        )
        assert facts["archive"]["sha256"] == case["archive_sha256"] and (
            facts["executable"]["sha256"] == provisioning["executable_sha256"]
        ), "Actual provider and input facts must retain independently pinned byte identities"
        assert facts["database"]["sha256"] == provisioning["database_files"]["trivy.db"] and (
            facts["database-metadata"]["sha256"] == provisioning["database_files"]["metadata.json"]
        ), "The actual selected offline database must match the original provisioning receipt"
        events = receipt["events"]
        assert [event["sequence"] for event in events] == list(range(len(events))), (
            "Original events must retain their unmodified contiguous sequence"
        )
        assert events[0]["kind"] == "started" and events[-1]["kind"] == "completed", (
            "Original process lifecycle must remain complete"
        )

        for kind, role in zip(("stdout", "stderr"), stream_roles, strict=True):
            joined = b"".join(bytes.fromhex(event["data_hex"]) for event in events
                              if event["kind"] == kind)
            assert joined == raw[role], "Original event chunks must reconstruct exact streams"

        assert {item["evidence_id"] for item in receipt["streams"]} == {
            roles[role].evidence_id for role in stream_roles
        }, "Original receipts must retain their original stream acquisition manifest IDs"
        receipt_role = "native-version-receipt" if operation == "version" else "native-scan-receipt"

        for role in (*stream_roles, receipt_role):
            provenance = roles[role].provenance
            assert provenance.source_id == "native.trivy" and provenance.tool_version == "0.75.0", (
                "Original custody must retain the actual genuine provider identity/version"
            )
            assert json.loads(SerializeContract(provenance.execution)) == receipt["execution"], (
                "Every original record must retain its own exact actual execution facts"
            )

    assert version["request"]["workspace"] != scan["request"]["workspace"], (
        "VERSION and SCAN must retain their distinct original owned scratch associations"
    )

    assert version["request"]["invocation"]["provider_version"] is None and (
        version["observed_version"] == "0.75.0" and
        scan["request"]["invocation"]["provider_version"] == "0.75.0"
    ), "Original unknown-version VERSION and actually observed SCAN version must stay distinct"
    assert version["request"]["authorization"]["authorization_id"] != (
        scan["request"]["authorization"]["authorization_id"]
    ), "VERSION and SCAN require distinct original execution authorizations"
    assert scan["version_prerequisite_sha256"] == hashlib.sha256(
        raw["native-version-receipt"]).hexdigest(), "SCAN must bind the original VERSION capture"
    assert roles["native-version-receipt"].evidence_id != (
        "sha256:" + roles["native-version-receipt"].reference.sha256
    ), "A receipt manifest identity must not be substituted for its raw blob digest"
    wire = json.loads(raw["stdout"])
    assert wire["SchemaVersion"] == 2 and wire["ArtifactType"] == "container_image", (
        "The actual scanner must return its genuine native container-image envelope"
    )
    assert wire["Metadata"]["ImageID"] == ConfigDigest(ArchiveBytes(case["package_version"])), (
        "The actual provider must identify the independent owned archive's exact config bytes"
    )
    assert json.loads(raw["provider-version"])["Version"] == "0.75.0", (
        "The actual original VERSION bytes must establish the pinned provider version"
    )
    matches = [item for result in wire["Results"] for item in result.get("Vulnerabilities") or []
               if item["VulnerabilityID"] == "CVE-2023-32681" and item["PkgName"] == "requests"
               and item["InstalledVersion"] == case["package_version"]]
    assert bool(matches) is case["expected_selected_advisory_match"], (
        "Only the independently selected requests advisory correlation is scored"
    )

    return VerifyNativeTrivyImageReplay(records, root), roles, wire


def CheckModel(root: Path, case: dict, records: tuple):
    """Inspect saved image/package/finding identities using handwritten expected fields."""

    state = LocalModelStore(root).Open()
    assets = state.Objects(ObjectKind.ASSET)
    images = [item for item in assets if item.attributes.get("asset_type") == "image"]
    packages = [item for item in assets if item.attributes.get("asset_type") == "package"]
    image_digest = ConfigDigest(ArchiveBytes(case["package_version"]))
    assert len(images) == 1 and images[0].identity.key == "image-config:" + image_digest, (
        "Canonical image identity must retain the owned config digest, distinct from archive/DB"
    )
    package_fields = {"ecosystem": "pypi", "name": "requests", "version": case["package_version"],
                      "namespace": "", "qualifiers": []}
    package_key = "package-version:" + hashlib.sha256(Canonical(package_fields)).hexdigest()
    assert len(packages) == 1 and packages[0].identity.key == package_key and (
        packages[0].attributes["name"] == "requests" and
        packages[0].attributes["version"] == case["package_version"]
    ), "Canonical installed package identity must use independently selected name/version fields"
    assert any(item.kind is RelationKind.CONTAINS and item.source_reference == images[0].Reference()
               and item.target_reference == packages[0].Reference() for item in state.relations), (
        "The saved image must retain its installed package association"
    )
    selected = [Finding.FromObject(item) for item in state.Objects(ObjectKind.FINDING)
                if item.attributes["location_key"] == "CVE-2023-32681"]
    assert bool(selected) is case["expected_selected_advisory_match"], (
        "The fixed case omits only the selected advisory; unrelated Findings are not scored"
    )

    for finding in selected:
        assert finding.subject_reference == packages[0].Reference() and (
            finding.check_id == "supply-chain.vulnerability"
        ), "The selected Finding must correlate to the actual installed package"
        assert any(set(item.evidence_references) == {record.reference for record in records}
                   for item in finding.provenance), (
            "The selected canonical Finding must retain all six original pair evidence roles"
        )

    return state, selected


@pytest.mark.parametrize("case", ORACLE["cases"], ids=[item["case_id"] for item in ORACLE["cases"]])
def test_GenuineSdkAndInstalledCliPreserveOriginalPairTriageAndRelocatedReopen(
    tmp_path, product_runtime, case, monkeypatch,
):
    """Actual SDK/CLI execution crosses fresh authority, original custody and durable reopen."""

    from fuzzy1337.native_image_workflow import PlanNativeImageScan, ScanNativeImage

    root = tmp_path / "owned workspace"
    selection = OwnedSelection(root, case, product_runtime)
    _, _, provisioning, network = product_runtime
    output = EVIDENCE / case["case_id"]
    output.mkdir(parents=True, exist_ok=True)
    (output / "expected.json").write_bytes(Canonical({"case": case,
        "provisioning": provisioning, "network_namespace": network,
        "scan_completeness": "not-assessed", "unrelated_finding_count": "not-asserted"}))
    before = LocalWorkspaceStore(root).Open()
    calls = []
    original = LocalExecutor.Execute

    async def Audit(executor, request, **options):
        """Record actual requests while delegating every result unchanged to the real executor."""

        calls.append(request)

        return await original(executor, request, **options)

    with monkeypatch.context() as audit:
        audit.setattr(LocalExecutor, "Execute", Audit)
        assert stat.S_IMODE(selection.executable.stat().st_mode) & 0o111 == 0, (
            "Planning is exercised with a kernel-nonexecutable exact provider copy"
        )
        preview = asyncio.run(PlanNativeImageScan(root, OWNER, selection,
                                                timeout_seconds=SCAN_TIMEOUT))
        assert preview.phase == "material-preview" and preview.authority_plan is None, (
            "Explicit material preview cannot manufacture registered execution authority"
        )
        assert preview.Target.value == case["artifact_target_value"] and (
            LocalWorkspaceStore(root).Open() == before
        ), "Read planning must retain its literal target without granting or writing workspace"
        target = RegisterScope(root, case)
        plan = asyncio.run(PlanNativeImageScan(root, OWNER, selection, scope_id="local",
            policy_provider=Policy, timeout_seconds=SCAN_TIMEOUT))

    assert len(calls) == 2 and all(item.invocation.argv[1:4] == (
        "-I", "-m", "fuzzy1337.native_image_material_worker") for item in calls), (
        "Actual SDK planning may invoke only installed material readers, never provider requests"
    )
    assert plan.phase == "scoped-version-plan" and plan.Target == target and (
        plan.authority_plan is not None and plan.version_invocation is not None and
        plan.version_invocation.provider_version is None
    ), "Strict scoped planning must defer SCAN until an actual original VERSION exists"
    assert plan.ToDict()["execution_authorized"] is False and (
        plan.ToDict()["scan_recipe"]["requires_original_version"] is True
    ), "A planning response is never an execution grant or fabricated exact SCAN intent"
    assert not tuple((root / "native-image-claims").glob("*")), (
        "Read planning must not consume a native execution reservation"
    )
    selection.executable.chmod(0o700)
    observed = []
    summary = asyncio.run(ScanNativeImage(root, "local", OWNER, selection, Policy,
        approve_safe_image=True, timeout_seconds=SCAN_TIMEOUT, on_event=observed.append))
    (output / "sdk-summary.json").write_bytes(Canonical(summary.ToDict()))
    shutil.copytree(root / "evidence", output / "evidence", dirs_exist_ok=True)
    assert summary.ExitCode() == 0 and summary.snapshot.state is JobState.COMPLETED and (
        not summary.custody_uncertain
    ), "The genuine governed SDK pair must complete with confirmed original custody"
    assert list(summary.events) == observed, "Actual SDK job events must preserve their owner order"
    assert len(summary.captures) == 2, "The product must preserve both typed original captures"
    sdk_records = tuple(record for capture in summary.captures for record in capture.records)
    assert {record.evidence_id for record in sdk_records} == {
        record.evidence_id for record in summary.retained_records
    }, "Original acquisition IDs cannot be republished as substitutes"
    sdk_replay, sdk_roles, _ = CheckPair(root, sdk_records, case, target, provisioning)

    for capture in summary.captures:
        role = ("native-version-receipt" if capture.operation.value == "version" else
                "native-scan-receipt")
        assert capture.Digest() == sdk_roles[role].reference.sha256, (
            "Typed original capture must agree with its exact retained receipt blob"
        )
        assert capture.outcome.execution.state is ExecutionState.SUCCEEDED, (
            "Canonical success cannot be manufactured from a refused or failed original execution"
        )

    state, findings = CheckModel(root, case, sdk_records)

    for finding in findings:
        triaged = replace(finding, status=FindingStatus.CONFIRMED,
                          status_reason="Owned product oracle review")
        proposal, _ = state.Apply(objects=(triaged.ToObject(state.workspace_id),))
        state = LocalModelStore(root).Save(proposal, expected_revision=state.revision)

    identities = {item.Reference() for item in state.objects}
    retained_before = set(LocalWorkspaceStore(root).Open().evidence_record_references)
    policy_path = root / "explicit-native-policy.json"
    policy_path.write_text(SerializeContract(Policy()), encoding="utf-8")
    arguments = ["scan", "image", str(root), "--profile", "native", "--scope", "local",
        "--owner", OWNER, "--archive", "owned.tar", "--cache-directory", "trivy-cache",
        "--executable", str(selection.executable), "--read-consent-reference",
        selection.read_consent.record_ref, "--policy", str(policy_path),
        "--timeout", str(SCAN_TIMEOUT)]
    selection.executable.chmod(0o600)
    cli_plan = Console([*arguments, "--plan"], output, "cli-plan")
    assert cli_plan["phase"] == "scoped-version-plan" and (
        cli_plan["target"]["value"] == case["artifact_target_value"] and
        cli_plan["execution_authorized"] is False
    ), "The actual installed CLI must plan successfully with a kernel-nonexecutable provider"
    selection.executable.chmod(0o700)
    cli_summary = Console([*arguments, "--approve-safe-image"], output, "cli-run")
    assert cli_summary["workflow"] == "native-image" and (
        cli_summary["source_id"] == "native.trivy" and
        cli_summary["state"] == "completed" and not cli_summary["custody_uncertain"]
    ), "The actual installed native CLI must complete its separately authorized original pair"
    current = LocalWorkspaceStore(root).Open()
    new_ids = set(current.evidence_record_references) - retained_before
    cli_records = tuple(LocalEvidenceStore(root / "evidence").Get(identifier)
                        for identifier in cli_summary["retained_evidence_ids"])
    assert {record.evidence_id for record in cli_records} == new_ids and len(new_ids) == 6, (
        "CLI must persist exactly its own six original acquisitions and retain the SDK IDs"
    )
    cli_replay, cli_roles, _ = CheckPair(root, cli_records, case, target, provisioning)

    for operation in cli_summary["operations"]:
        role = ("native-version-receipt" if operation["operation"] == "version" else
                "native-scan-receipt")
        assert operation["capture_sha256"] == cli_roles[role].reference.sha256, (
            "CLI summary must name the original captured receipt digest"
        )

    repeated, repeated_findings = CheckModel(root, case, cli_records)
    assert {item.Reference() for item in repeated.objects} == identities, (
        "Repeated genuine SDK/CLI scans must preserve canonical logical object identities"
    )
    assert all(item.status is FindingStatus.CONFIRMED for item in repeated_findings), (
        "Repeated genuine scanning must preserve independently confirmed selected Finding triage"
    )
    canonical = CanonicalModelJson(repeated)
    (output / "model.json").write_bytes(canonical)
    shutil.copytree(root / "evidence", output / "evidence", dirs_exist_ok=True)
    (root / "owned.tar").unlink()
    selection.executable.unlink()
    shutil.rmtree(root / "trivy-cache")
    relocated = tmp_path / "relocated workspace"
    shutil.move(str(root), relocated)
    reopened = OpenWorkspace(relocated)
    assert reopened["verified_evidence_records"] == 12, (
        "Relocated reopen must verify both original pairs"
    )
    assert CanonicalModelJson(LocalModelStore(relocated).Open()) == canonical, (
        "Saved native canonical model must reopen identically without historical selected material"
    )
    assert VerifyNativeTrivyImageReplay(sdk_records, relocated) == sdk_replay and (
        VerifyNativeTrivyImageReplay(cli_records, relocated) == cli_replay
    ), "Relocated replay must retain original custody without executable/cache/archive reads"
    assert Console(["workspace", "open", str(relocated)], output, "cli-reopen") == reopened, (
        "Installed isolated CLI and SDK must independently agree on relocated offline reopening"
    )
    (output / "oracle.json").write_bytes(Canonical({"oracle_id": ORACLE["oracle_id"],
        "case": case, "actual_original_evidence_ids": sorted(current.evidence_record_references),
        "relocated_reopen": reopened, "result": "passed", "scan_completeness": "not-assessed",
        "unrelated_finding_count": "not-asserted"}))
