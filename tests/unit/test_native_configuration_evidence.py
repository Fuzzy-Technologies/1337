# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Adversarial native receipt/replay attribution tests with explicitly doubled provider facts."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from fuzzy1337.adapters import EvidenceReference, SerializeContract
from fuzzy1337.artifact_policy import ArtifactPolicyEngine
from fuzzy1337.evidence import EvidenceError, LocalEvidenceStore
from fuzzy1337.model import LocalModelStore
from fuzzy1337.native_configuration_evidence import (
    ApplyVerifiedNativeConfiguration,
    NativeConfigurationEvidenceStore,
    VerifyNativeConfigurationReplay,
)
from fuzzy1337.native_configuration_policy import (
    NativeConfigurationExecutionClaim,
    NativeConfigurationVersionPrerequisite,
)
from tests.unit.test_native_configuration_workflow import Run
from tests.unit.test_native_configuration_workflow import (
    configuration_runner as configuration_runner,
)
from tests.unit.test_native_configuration_workflow import controlled_runtime as controlled_runtime


def ReplaceRaw(root, records, role, data, *, provenance=None):
    """Publish an explicitly adversarial new acquisition while retaining other original records."""

    original = next(item for item in records if item.reference.role == role)
    record = LocalEvidenceStore(root / "evidence").Put(data, role, original.reference.media_type,
        original.provenance if provenance is None else provenance)

    return tuple(record if item is original else item for item in records)


@pytest.mark.parametrize("attack", [
    "schema", "selection-profile", "selection-reserved-name", "stage-fields", "partition-alias",
    "file-name", "file-size", "scanner-pin", "extra-material", "extra-argv", "resources",
    "cleanup", "full-request", "exit-status", "termination", "stream-digest", "event-sequence",
    "event-digest", "event-size", "event-kind", "event-termination", "time",
])
def test_ChangedOriginalControlCannotBecomeSuccessfulReplay(
    controlled_runtime, configuration_runner, attack
):
    """Changed original facts refuse even when republished as valid immutable blobs."""

    root, selection, context, settings = controlled_runtime
    summary = Run(configuration_runner, controlled_runtime)
    records = summary.retained_records
    role = "native-configuration-scan-receipt"
    original = next(item for item in records if item.reference.role == role)
    envelope = json.loads(LocalEvidenceStore(root / "evidence").Read(original.reference))
    prepared = envelope["prepared"]
    stage = prepared["stage_metadata"]
    raw = envelope["raw_facts"]

    if attack == "schema":
        prepared["schema_version"] = True

    elif attack == "selection-profile":
        prepared["selection"]["profile"] = "trivy.image-archive-offline.v1"

    elif attack == "selection-reserved-name":
        prepared["selection"]["logical_path"] = "trivy.yaml"

    elif attack == "stage-fields":
        stage["unselected"] = "material"

    elif attack == "partition-alias":
        stage["partitions"]["input"]["directory_identity"] = stage["root_identity"]

    elif attack == "file-name":
        stage["partitions"]["input"]["identities"][0][0] = "other-file"

    elif attack == "file-size":
        stage["partitions"]["input"]["identities"][0][1][2] += 1

    elif attack == "scanner-pin":
        stage["partitions"]["scanner"]["manifest"]["files"][0]["sha256"] = "0" * 64

    elif attack == "extra-material":
        part = stage["partitions"]["material"]
        part["manifest"]["files"] = [{"name": "checks.rego", "size_bytes": 1, "sha256": "a" * 64}]
        part["identities"] = [["checks.rego", [987, 654, 1, 0, 0]]]

    elif attack == "extra-argv":
        prepared["invocation"]["argv"].insert(-1, "--checks=/unselected")

    elif attack == "resources":
        prepared["resources"]["max_stdout_bytes"] *= 2

    elif attack == "cleanup":
        envelope["cleanup_confirmed"] = False

    elif attack == "full-request":
        envelope["request"]["environment"]["TRIVY_CONFIG"] = "/unselected"

    elif attack == "exit-status":
        raw["execution"]["exit_code"] = 1

    elif attack == "termination":
        raw["termination"] = "timeout"

    elif attack == "stream-digest":
        raw["stdout_sha256"] = "0" * 64

    elif attack == "event-sequence":
        raw["events"][1]["sequence"] = 0

    elif attack == "event-digest":
        raw["events"][1]["sha256"] = "0" * 64

    elif attack == "event-size":
        raw["events"][1]["size_bytes"] = 0

    elif attack == "event-kind":
        raw["events"][1]["kind"] = "unknown"

    elif attack == "event-termination":
        raw["events"][-1]["termination"] = "cancellation"

    else:
        envelope["finished_at"] = envelope["started_at"]

    changed = ReplaceRaw(root, records, role, SerializeContract(envelope).encode())

    with pytest.raises(ValueError):
        VerifyNativeConfigurationReplay(changed, root)


@pytest.mark.parametrize("attack", ["source", "provenance", "duplicate", "missing", "foreign-id"])
def test_OriginalAcquisitionIdentityAndSourceCannotBeSubstituted(
    controlled_runtime, configuration_runner, attack
):
    """Raw source bytes, immutable identities and full provenance remain independently bound."""

    root, selection, context, settings = controlled_runtime
    summary = Run(configuration_runner, controlled_runtime)
    records = summary.retained_records
    source = next(item for item in records if item.reference.role == "native-configuration-source")

    if attack == "source":
        records = ReplaceRaw(root, records, source.reference.role, b"FROM scratch\nUSER 12345\n")

    elif attack == "provenance":
        data = LocalEvidenceStore(root / "evidence").Read(source.reference)
        records = ReplaceRaw(root, records, source.reference.role, data,
            provenance=replace(source.provenance, source_version="2"))

    elif attack == "duplicate":
        records = (*records[:-1], records[0])

    elif attack == "missing":
        records = records[:-1]

    else:
        records = tuple(replace(item, provenance=replace(item.provenance, source_version="foreign"))
                        if item is source else item for item in records)

    with pytest.raises((ValueError, EvidenceError)):
        VerifyNativeConfigurationReplay(records, root)


def test_IndividuallyValidOperationsCannotBorrowAnotherOriginalPair(
    controlled_runtime, configuration_runner
):
    """A second actual component run supplies valid records but cannot replace original VERSION."""

    root, selection, context, settings = controlled_runtime
    first = Run(configuration_runner, controlled_runtime)
    second = Run(configuration_runner, controlled_runtime)
    substituted = tuple(item for item in first.retained_records
                        if "-version-" not in item.reference.role) + tuple(
        item for item in second.retained_records if "-version-" in item.reference.role)

    with pytest.raises(ValueError, match="VERSION/SCAN"):
        VerifyNativeConfigurationReplay(substituted, root)


@pytest.mark.parametrize("reference", [
    EvidenceReference("unrelated", "unrelated", "a" * 64, "text/plain", 0),
    EvidenceReference("native-configuration-source", "unrelated", "a" * 64, "text/plain", 4097),
    EvidenceReference("native-configuration-source", "unrelated", "a" * 64,
                      "application/json", 1),
])
def test_ReplayBudgetsRefuseBeforeAnyBlobRead(tmp_path, monkeypatch, reference):
    """The consumer's streaming preflight must reject role/media/size expansion before eager IO."""

    def Forbidden(*args):
        """Expose any eager canonical blob read reached after a failed admission contract."""

        pytest.fail("Invalid native role reached eager blob IO")

    monkeypatch.setattr(LocalEvidenceStore, "Read", Forbidden)

    with pytest.raises(ValueError):
        NativeConfigurationEvidenceStore(tmp_path).Read(reference)


def test_HistoricalFactsCannotCreateFreshModelWriteAuthority(
    controlled_runtime, configuration_runner
):
    """A caller cannot turn replay plus copied capture metadata into a live engine association."""

    root, selection, context, settings = controlled_runtime
    summary = Run(configuration_runner, controlled_runtime)
    version, scan = summary.captures
    invented_claim = object.__new__(NativeConfigurationExecutionClaim)
    prerequisite = NativeConfigurationVersionPrerequisite(version.prepared, version.grant,
                                                          invented_claim, version)

    with pytest.raises(ValueError, match="claim is not original"):
        ApplyVerifiedNativeConfiguration(LocalModelStore(root).Open(), scan,
            summary.retained_records, root, engine=ArtifactPolicyEngine(),
            version_prerequisite=prerequisite, scan_claim=invented_claim,
            observer=None, material_proof=None, context_provider=lambda: context)
