# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Native provider interpretation boundaries, explicitly separate from genuine scanner proof."""

from __future__ import annotations

import hashlib
import json

import pytest

from fuzzy1337.artifact_inputs import (
    ArtifactFile,
    ArtifactManifest,
    ArtifactProfile,
    ArtifactReadConsent,
    ArtifactRole,
)
from fuzzy1337.native_configuration import NativeConfigurationSelection
from fuzzy1337.native_configuration_report import (
    ParseNativeConfigurationReport,
    VerifyEmbeddedConfigurationChecks,
)

LOADER = b"Embedded libraries are loaded count=4\nEmbedded checks are loaded count=20\n"


def Material(tmp_path):
    """Declare noncatalog source bytes without executing a provider."""

    source = b"FROM scratch\nUSER root\n"
    selection = NativeConfigurationSelection(ArtifactProfile.DOCKERFILE, "Dockerfile",
        tmp_path / "source", tmp_path / "trivy", ArtifactReadConsent("owner:test", "read:test"))
    manifest = ArtifactManifest(selection.profile, ArtifactRole.INPUT,
        (ArtifactFile("Dockerfile", len(source), hashlib.sha256(source).hexdigest()),))
    report = {"SchemaVersion": 2, "Results": [{"Target": "Dockerfile", "Class": "config",
        "Type": "dockerfile", "Misconfigurations": [{"ID": "DS-0002", "Status": "FAIL",
        "Severity": "HIGH", "Title": "Use a non-root user", "Resolution": "Select a user",
        "CauseMetadata": {"StartLine": 2, "EndLine": 2}}]}]}

    return selection, manifest, source, report


def test_ProviderRowsRetainNativeIdentityAndCoordinates(tmp_path):
    """Native interpretation keeps original IDs and does not invent synthetic selectors."""

    selection, manifest, source, report = Material(tmp_path)
    checks = ParseNativeConfigurationReport(json.dumps(report).encode(), LOADER,
                                             selection, manifest, source)
    assert len(checks) == 1 and checks[0].check_id == "DS-0002", (
        "The native check identity must be preserved"
    )
    assert checks[0].start_line == 2 and checks[0].resource is None, (
        "Native coordinates must retain absent selectors without inference"
    )


@pytest.mark.parametrize("mutation", ["empty", "unknown", "duplicate", "wrong-type",
    "line", "status", "severity", "title", "schema", "cause"])
def test_MalformedOrUnprocessedSelectedFilesAreRefused(tmp_path, mutation):
    """Successful process exit cannot stand in for positive selected-file processing."""

    selection, manifest, source, report = Material(tmp_path)
    result = report["Results"][0]
    row = result["Misconfigurations"][0]

    if mutation == "empty":
        result["Misconfigurations"] = []

    elif mutation == "unknown":
        result["Target"] = "other-file"

    elif mutation == "duplicate":
        report["Results"].append(result)

    elif mutation == "wrong-type":
        result["Type"] = "kubernetes"

    elif mutation == "line":
        row["CauseMetadata"]["EndLine"] = 200

    elif mutation == "status":
        row["Status"] = "SUCCESS"

    elif mutation == "severity":
        row["Severity"] = "SEVERE"

    elif mutation == "title":
        row["Title"] = None

    elif mutation == "schema":
        report["SchemaVersion"] = True

    else:
        row["CauseMetadata"] = []

    with pytest.raises(ValueError):
        ParseNativeConfigurationReport(json.dumps(report).encode(), LOADER,
                                         selection, manifest, source)


@pytest.mark.parametrize("stderr", [b"", b"Embedded checks are loaded count=0",
    LOADER + b"Checks from disk are loaded", LOADER + b"Checks from readers are loaded",
    LOADER + b"Overriding filesystem for checks"])
def test_EmbeddedProvenanceCannotBeReplacedByExitStatus(stderr):
    """Missing embedded proof or explicit external check provenance refuses acceptance."""

    with pytest.raises(ValueError):
        VerifyEmbeddedConfigurationChecks(stderr)


def test_UpstreamVirtualDefaultDataDoesNotImplyCallerOverride():
    """The pinned provider's ordinary virtual data diagnostic remains admissible."""

    assert VerifyEmbeddedConfigurationChecks(LOADER + b"Overriding filesystem for data") == (
        4, 20
    ), "Virtual default data must not be confused with caller-selected checks"
