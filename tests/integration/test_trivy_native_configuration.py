# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Required pinned Trivy configuration compatibility on five unchanged inert owned specimens."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import socket
import sys
from pathlib import Path

import pytest

from fuzzy1337.adapters import ExecutionState
from fuzzy1337.adapters.trivy import ParseJson
from fuzzy1337.executors import ExecutionTermination
from fuzzy1337.executors.owned_process import RequireLinuxOwnership
from tests.fixtures.trivy.native_configuration import (
    MAX_VERSION_STDOUT_BYTES,
    CaptureOriginal,
    VerifyEmbeddedChecks,
    VerifyNativeInterpretation,
)
from tests.integration.test_trivy_native import FileDigest, NoIpv4Routes

FIXTURES = Path(__file__).parents[1] / "fixtures" / "trivy"
SOURCE_ROOT = Path(__file__).parents[1] / "contract" / "fixtures" / "configuration_profiles"
ORACLE = json.loads((FIXTURES / "configuration_compatibility.v1.json").read_bytes())
PROVIDER_ORACLE = json.loads((FIXTURES / "native_oracle.json").read_bytes())
EVIDENCE = Path("functional-evidence/native-configuration-compatibility")
REQUIRED = "FUZZY1337_RUN_NATIVE_CONFIGURATION_COMPATIBILITY"


def Inventory(root: Path) -> list[dict]:
    """Record bounded owned directory contents, refusing links and unknown file kinds."""

    pending = [root]
    inventory = []

    while pending:
        directory = pending.pop()

        for path in sorted(directory.iterdir()):
            assert len(inventory) < 512, "Owned config process inventory exceeded its finite bound"
            assert not path.is_symlink(), "Owned config process created a nonphysical path"
            relative = path.relative_to(root).as_posix()

            if path.is_dir():
                inventory.append({"path": relative, "kind": "directory"})
                pending.append(path)

            else:
                assert path.is_file() and path.stat().st_size <= 1024 * 1024, (
                    "Owned compatibility inventory contains an unsupported or oversized file"
                )
                inventory.append({"path": relative, "kind": "file",
                    "size_bytes": path.stat().st_size, "sha256": FileDigest(path)})

    return sorted(inventory, key=lambda item: item["path"])


@pytest.fixture(scope="module")
def native_configuration_runtime():
    """Require pinned executable/provisioning and no-egress ownership, without an image DB."""

    if os.environ.get(REQUIRED) != "1":
        pytest.skip("Optional genuine configuration compatibility is unexecuted without its opt-in")

    names = ("FUZZY1337_TRIVY_BINARY", "FUZZY1337_TRIVY_PROVISIONING",
             "FUZZY1337_TRIVY_HOST_NETNS")
    selected = tuple(os.environ.get(name) for name in names)
    assert all(selected), "Required native config compatibility cannot skip missing pinned material"
    assert sys.platform == "linux" and os.geteuid() != 0, (
        "Required native config proof needs the ordinary nonroot Linux owner"
    )
    RequireLinuxOwnership()
    current_namespace = os.readlink("/proc/self/ns/net")
    assert current_namespace != selected[2], "Config execution reused the provisioning namespace"
    interfaces = socket.if_nameindex()
    assert interfaces == [(1, "lo")] and NoIpv4Routes(Path("/proc/net/route").read_text()), (
        "Native config compatibility requires only loopback and no IPv4 route"
    )
    assert all(line.split()[0] == "0" * 32 for line in
               Path("/proc/net/ipv6_route").read_text().splitlines()), (
        "Native config compatibility must have no external IPv6 route"
    )
    executable, receipt = (Path(value) for value in selected[:2])
    assert executable.is_absolute() and executable.is_file() and not executable.is_symlink(), (
        "Pinned native config executable must be a selected physical regular file"
    )
    assert 1 <= executable.stat().st_size <= 256 * 1024 * 1024, (
        "Selected native executable exceeded its finite release-member budget"
    )
    assert receipt.is_absolute() and receipt.is_file() and not receipt.is_symlink() and (
        receipt.stat().st_size <= 16 * 1024
    ), "Native config requires the original bounded provisioning receipt"
    provisioning = json.loads(receipt.read_bytes())
    assert provisioning["release_asset"] == PROVIDER_ORACLE["release_asset"] and (
        provisioning["release_asset_sha256"] == PROVIDER_ORACLE["release_asset_sha256"]
    ), "Native config must retain the original independently pinned official release asset"
    assert FileDigest(executable) == provisioning["executable_sha256"], (
        "The actual native binary must match its original pinned-release provisioning receipt"
    )

    return executable, provisioning, {"host": selected[2], "scan": current_namespace,
        "interfaces": interfaces, "no_ipv4_routes": True, "no_external_ipv6_routes": True}


@pytest.mark.parametrize("case", ORACLE["cases"], ids=[case["caseId"] for case in ORACLE["cases"]])
def test_GenuinePinnedConfigurationProcessesOriginalSourcesWithEmbeddedChecks(
    tmp_path, native_configuration_runtime, case,
):
    """Real VERSION/config retain original custody and independent native file/rule facts."""

    original_binary, provisioning, network = native_configuration_runtime
    assert len(case["inputs"]) == 1 and case["scanner"] in {"dockerfile", "kubernetes"}, (
        "The independent compatibility catalog must retain its closed one-file selections"
    )
    root = tmp_path / "owned-native-configuration"
    root.mkdir(mode=0o700)
    inputs, cache = root / "inputs", root / "empty-cache"
    inputs.mkdir(mode=0o700)
    cache.mkdir(mode=0o700)
    executable = root / "selected-trivy"
    shutil.copyfile(original_binary, executable)
    executable.chmod(0o700)
    assert FileDigest(executable) == provisioning["executable_sha256"], (
        "Each owned case must use the exact independently provisioned provider bytes"
    )
    item = case["inputs"][0]
    source = SOURCE_ROOT / item["fixture"]
    raw = source.read_bytes()
    assert len(raw) == item["sizeBytes"] and hashlib.sha256(raw).hexdigest() == item["sha256"], (
        "The five original inert specimens must not change to fit actual native output"
    )
    selected_source = inputs / item["logicalPath"]
    selected_source.write_bytes(raw)
    evidence = EVIDENCE / case["caseId"]
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "original-source").write_bytes(raw)
    before_inputs, before_cache = Inventory(inputs), Inventory(cache)
    assert len(before_inputs) == 1 and before_cache == [], (
        "Each compatibility process must begin with exactly one input and wholly empty check cache"
    )
    facts = {"classification": "test-only-native-configuration-compatibility",
        "native_product_acceptance": False, "scan_completeness": "not-assessed",
        "case_id": case["caseId"], "provider_version": ORACLE["providerVersion"],
        "release_asset": provisioning["release_asset"],
        "release_asset_sha256": provisioning["release_asset_sha256"],
        "executable_sha256": provisioning["executable_sha256"],
        "checks_source": ORACLE["checksSource"], "loader_source": ORACLE["trivySource"],
        "network_namespace": network, "inputs_before": before_inputs,
        "cache_before": before_cache, "outcome": "unassessed"}

    try:
        version = asyncio.run(CaptureOriginal(root, executable, cache, inputs, case["scanner"],
            "version", root / "version-environment", evidence))
        assert version.execution.state is ExecutionState.SUCCEEDED and (
            version.execution.exit_code == 0
            and version.termination is ExecutionTermination.PROCESS_EXIT
        ), "Original native VERSION must succeed with confirmed owned process termination"
        actual_version = ParseJson(version.stdout, max_bytes=MAX_VERSION_STDOUT_BYTES)
        assert actual_version["Version"] == ORACLE["providerVersion"] == "0.75.0", (
            "Only the actual originally observed pinned provider version establishes compatibility"
        )
        assert Inventory(cache) == [], "VERSION cannot populate the selected empty checks cache"
        config = asyncio.run(CaptureOriginal(root, executable, cache, inputs, case["scanner"],
            "config", root / "config-environment", evidence))
        assert config.execution.state is ExecutionState.SUCCEEDED and (
            config.execution.exit_code == 0
            and config.termination is ExecutionTermination.PROCESS_EXIT
        ), "Native config failure/timeout/overflow cannot become successful empty interpretation"
        facts["embedded_loader"] = VerifyEmbeddedChecks(config.stderr)
        facts["interpretation"] = VerifyNativeInterpretation(config.stdout, case)
        assert Inventory(inputs) == before_inputs and FileDigest(executable) == (
            provisioning["executable_sha256"]
        ), "Selected source and provider bytes must remain unchanged after actual execution"
        facts["outcome"] = "selected-compatibility-assertions-passed"

    finally:
        facts["inputs_after"] = Inventory(inputs)
        facts["cache_after"] = Inventory(cache)
        facts["environment_after"] = {path.name: Inventory(path) for path in (
            root / "version-environment", root / "config-environment") if path.is_dir()}
        (evidence / "compatibility.json").write_text(json.dumps(facts, sort_keys=True,
            indent=2, allow_nan=False) + "\n", encoding="utf-8")
