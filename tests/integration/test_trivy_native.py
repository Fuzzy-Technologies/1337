# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Opt-in pinned genuine Trivy acceptance over inert owned archives without network routes."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from fuzzy1337.adapters import (
    AdapterHealthState,
    AdapterReport,
    AdapterRequest,
    ExecutionState,
    ImpactLevel,
    SerializeContract,
)
from fuzzy1337.adapters.trivy import TrivyAdapter
from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.executors import (
    CapabilityDescriptors,
    ExecutionAuthorization,
    ExecutionResources,
    InvocationDigest,
    LocalExecutionRequest,
    LocalExecutor,
)
from tests.fixtures.trivy.native_archive import ArchiveBytes

ORACLE = json.loads((Path(__file__).parents[1] / "fixtures/trivy/native_oracle.json").read_bytes())


def FileDigest(path: Path) -> str:
    """Hash explicitly selected large database/binary files with bounded memory."""

    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def NoIpv4Routes(raw: str) -> bool:
    """Accept kernel empty or sole recognized header forms without admitting any route record."""

    lines = raw.splitlines()

    return not lines or (len(lines) == 1 and lines[0].split()[:3] == [
        "Iface", "Destination", "Gateway",
    ])


@pytest.fixture(scope="module")
def native_runtime():
    """Require explicit material and an actual separate network namespace without routes."""

    names = ("FUZZY1337_TRIVY_BINARY", "FUZZY1337_TRIVY_CACHE",
             "FUZZY1337_TRIVY_PROVISIONING", "FUZZY1337_TRIVY_HOST_NETNS")
    selected = tuple(os.environ.get(name) for name in names)

    if all(value is None for value in selected):
        pytest.skip("Native acceptance requires pinned Trivy/cache and isolated Linux netns")

    assert all(selected), "Partial native acceptance setup must fail rather than silently skip"
    assert sys.platform == "linux", "Native no-egress acceptance currently requires Linux netns"
    current = os.readlink("/proc/self/ns/net")
    assert current != selected[3], "Native scanner must run in a different netns from provisioning"
    assert socket.if_nameindex() == [(1, "lo")], "Isolated native netns must have only loopback"
    assert NoIpv4Routes(Path("/proc/net/route").read_text()), (
        "The native network namespace must have no IPv4 routes"
    )
    assert all(line.split()[0] == "0" * 32 for line in
               Path("/proc/net/ipv6_route").read_text().splitlines()), (
        "Native netns must not contain an external IPv6 route"
    )
    executable, cache, receipt = (Path(value) for value in selected[:3])
    assert executable.is_absolute() and executable.is_file() and not executable.is_symlink(), (
        "Native executable must be an explicit selected regular physical file"
    )
    assert cache.is_absolute() and cache.is_dir() and not cache.is_symlink(), (
        "Native database cache must be an explicit selected physical directory"
    )
    assert receipt.is_absolute() and receipt.is_file() and not receipt.is_symlink(), (
        "Provisioning receipt must be an explicit selected regular physical file"
    )
    provisioning = json.loads(receipt.read_bytes())
    assert provisioning["release_asset_sha256"] == ORACLE["release_asset_sha256"], (
        "Provisioned binary release must retain the independent upstream checksum pin"
    )
    assert provisioning["database_repository"] == ORACLE["database_repository"], (
        "Vulnerability material must retain the exact official immutable OCI reference"
    )
    assert FileDigest(executable) == provisioning["executable_sha256"], (
        "Native executable bytes must match the selected provisioning receipt"
    )

    for name in ("metadata.json", "trivy.db"):
        path = cache / "db" / name
        assert path.is_file() and not path.is_symlink(), (
            "Database selection must contain regular files"
        )
        assert FileDigest(path) == provisioning["database_files"][name], (
            "Pre-provisioned database bytes must match the selected original receipt"
        )

    return executable, cache, provisioning, {"host": selected[3], "scan": current,
        "interfaces": socket.if_nameindex(), "no_ipv4_routes": True,
        "no_external_ipv6_routes": True}


def RunNative(root: Path, executable: Path, package_version: str):
    """Use the unchanged adapter and accepted low-level executor for an owned test invocation."""

    store = LocalEvidenceStore(root / "evidence")
    probe_adapter = TrivyAdapter(store.Read, root, str(executable))
    version_started = datetime.now(UTC).isoformat()
    probe = probe_adapter.ProbeHealth()
    version_finished = datetime.now(UTC).isoformat()
    assert probe.health.state is AdapterHealthState.AVAILABLE, (
        "Actual installed version probe must pass"
    )
    assert probe.health.provider_version == ORACLE["provider_version"], (
        "Only the genuine pinned native version can establish this acceptance"
    )
    adapter = TrivyAdapter(store.Read, root, str(executable), probe.health.provider_version)
    archive = ArchiveBytes(package_version)
    (root / "owned.tar").write_bytes(archive)
    request = AdapterRequest("image.archive-vulnerabilities", "target:pytest-owned-native-image",
        ImpactLevel.SAFE, {"archive": "owned.tar", "timeout_seconds": 60})
    invocation = adapter.PrepareInvocation(request)
    digest = InvocationDigest(invocation)
    authority = ExecutionAuthorization("authorization:pytest-owned-native-image",
        "scope:pytest-owned-native-image", "policy:pytest-native-acceptance", digest)
    scratch = root / "scratch"
    scratch.mkdir()
    execution_request = LocalExecutionRequest(invocation,
        CapabilityDescriptors(adapter.Descriptor)[0], authority,
        environment={"HOME": str(scratch), "XDG_CONFIG_HOME": str(scratch),
            "XDG_CACHE_HOME": str(scratch), "TMPDIR": str(scratch), "PATH": "/usr/bin:/bin"},
        resources=ExecutionResources(max_stdout_bytes=4 * 1024 * 1024,
                                    max_stderr_bytes=1024 * 1024))
    started = datetime.now(UTC).isoformat()
    captured = asyncio.run(LocalExecutor(root).Execute(execution_request))
    finished = datetime.now(UTC).isoformat()
    provenance = EvidenceProvenance("workspace:owned-native-acceptance", authority.scope_reference,
        adapter.Descriptor.adapter_id, adapter.Descriptor.version, probe.health.provider_version,
        started, finished, digest, captured.execution)
    stdout = store.Put(captured.stdout, "stdout", "application/json", provenance)
    stderr = store.Put(captured.stderr, "stderr", "text/plain", provenance)
    version = store.Put(probe.stdout, "provider-version", "application/json", EvidenceProvenance(
        "workspace:owned-native-acceptance", authority.scope_reference,
        adapter.Descriptor.adapter_id, adapter.Descriptor.version, probe.health.provider_version,
        version_started, version_finished))
    report = AdapterReport(invocation, captured.execution,
        (stdout.reference, stderr.reference, version.reference))

    return adapter, report, captured, probe, execution_request


def PreserveRun(root: Path, label: str, report, captured, probe, request,
                provisioning: dict, network: dict) -> Path:
    """Retain raw acquisitions and exact run facts before applying an acceptance assertion."""

    output = Path("functional-evidence/trivy-native") / label
    output.mkdir(parents=True, exist_ok=True)
    shutil.copytree(root / "evidence", output / "evidence", dirs_exist_ok=True)
    summary = {"schema_version": 1, "fixture_id": ORACLE["fixture_id"],
        "report": json.loads(SerializeContract(report)),
        "termination": captured.termination.value,
        "health": json.loads(SerializeContract(probe.health)),
        "selected_environment": dict(request.environment), "provisioning": provisioning,
        "network_namespace": network, "archive_sha256": FileDigest(root / "owned.tar"),
        "scan_completeness": "not-assessed", "native_artifact_profile": "metadata-only"}
    metadata = root / "trivy-cache" / "db" / "metadata.json"
    summary["selected_database_metadata"] = json.loads(metadata.read_bytes()) if (
        metadata.is_file()
    ) else None
    summary["observed_provider_version"] = json.loads(probe.stdout)
    (output / "run.json").write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n")

    return output


@pytest.mark.integration
@pytest.mark.parametrize("case", ORACLE["cases"])
def test_GenuinePinnedTrivyInventoryAndAdvisoryBoundaryOffline(tmp_path, native_runtime, case):
    """Decode owned metadata and match an independently selected real advisory without egress."""

    executable, supplied_cache, provisioning, network = native_runtime
    root = tmp_path.resolve()
    cache = root / "trivy-cache" / "db"
    cache.mkdir(parents=True)

    for name in ("metadata.json", "trivy.db"):
        shutil.copyfile(supplied_cache / "db" / name, cache / name)

    before = {name: FileDigest(cache / name) for name in ("metadata.json", "trivy.db")}
    assert before == provisioning["database_files"], (
        "Fresh test cache bytes must match the original selected database receipt"
    )
    adapter, report, captured, probe, request = RunNative(root, executable, case["version"])
    output = PreserveRun(root, case["version"], report, captured, probe, request,
                         provisioning, network)
    assert captured.execution.state is ExecutionState.SUCCEEDED, (
        "Native flags or scan failure must fail acceptance; inspect the original raw artifacts"
    )
    assert before == {name: FileDigest(cache / name) for name in before}, (
        "Offline native execution must not refresh or alter selected vulnerability database bytes"
    )
    assert FileDigest(executable) == provisioning["executable_sha256"], (
        "Actual native execution must preserve the selected pinned executable bytes"
    )
    selected_metadata = json.loads((cache / "metadata.json").read_bytes())
    observed_metadata = json.loads(probe.stdout)["VulnerabilityDB"]
    assert selected_metadata.get("Version") == 2 and isinstance(
        selected_metadata.get("UpdatedAt"), str
    ), "Selected native database must explicitly declare schema 2 and its update timestamp"

    for field in ("Version", "UpdatedAt", "NextUpdate", "DownloadedAt"):
        if field in selected_metadata:
            assert observed_metadata.get(field) == selected_metadata[field], (
                f"Actual native version DB metadata must match the selected cache field {field}"
            )

    result = adapter.NormalizeReport(report)
    (output / "normalized.json").write_text(SerializeContract(result) + "\n")
    packages = [item.attributes["provider_fields"] for item in result.observations
                if item.kind == "image.package"]
    assert len(packages) == 1 and packages[0]["Name"] == ORACLE["package_name"] and (
        packages[0]["Version"] == case["version"]
    ), "Actual native inventory must contain exactly the owned declared package/version"
    matches = [item for item in result.findings if
               item.attributes["provider_fields"]["VulnerabilityID"] == ORACLE["advisory_id"]]
    assert bool(matches) is case["expected_advisory_match"], (
        "Genuine provider must match the independently declared vulnerable/fixed advisory boundary"
    )
    assert all(item.attributes["provider_fields"]["PkgName"] == ORACLE["package_name"]
               for item in matches), "Selected advisory must remain correlated to the owned package"
    assert result.observations[0].attributes["database_metadata"]["Version"] == 2, (
        "Successful native evidence must retain actual schema-2 provider-observed DB metadata"
    )


@pytest.mark.integration
def test_GenuinePinnedTrivyMissingOfflineDatabaseIsActualFailure(tmp_path, native_runtime):
    """A missing database never becomes a successful empty scan or automatic network download."""

    executable, _, provisioning, network = native_runtime
    root = tmp_path.resolve()
    (root / "trivy-cache").mkdir()
    adapter, report, captured, probe, request = RunNative(root, executable, "2.30.0")
    PreserveRun(root, "missing-db", report, captured, probe, request, provisioning, network)
    assert captured.execution.state is ExecutionState.FAILED and (
        captured.execution.exit_code != 0
    ), (
        "Actual native provider must fail when explicitly supplied offline database is absent"
    )
    result = adapter.NormalizeReport(report)
    assert not result.findings and result.observations[0].attributes["complete"] is False, (
        "Missing offline DB retains original failure rather than successful interpretations"
    )
