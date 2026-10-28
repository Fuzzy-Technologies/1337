# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Inert Nuclei source contracts; no genuine binary, provider, target, or Docker execution."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from fuzzy1337.adapters import AdapterRequest, ImpactLevel, SerializeContract
from fuzzy1337.adapters.nuclei import NucleiAdapter
from fuzzy1337.nucleiscan import NucleiScanLimits, ReadNucleiProfile
from tests.contract.test_external_benchmark import (
    ContractNucleiObservation,
    WriteNucleiContractEvidence,
)
from tests.functional.external_benchmark import BuildComparison, LoadPack, ProjectNucleiMatches
from tests.functional.external_native_runner import ExportBundle, ImportBundle
from tests.functional.external_nuclei_runner import (
    ARCHIVE_BYTES,
    ARCHIVE_NAME,
    ARCHIVE_SHA256,
    CONFIG_SHA256,
    EMPTY_CONFIG,
    MAX_FILE_BYTES,
    PATHS,
    PROVIDER_TIMEOUT_SECONDS,
    STDERR_BYTES,
    STDOUT_BYTES,
    TEMPLATE_BYTES,
    TEMPLATE_ID,
    TEMPLATE_REVIEW,
    TEMPLATE_SHA256,
    VERSION,
    WRAPPER_TIMEOUT_SECONDS,
    AttemptProvenance,
    ExactUrl,
    InstalledInventory,
    ProfileDocument,
    ProjectStandaloneMatches,
    RegularIdentity,
    StandaloneArguments,
    VerifyArchive,
    VerifyBinary,
)

REPOSITORY = Path(__file__).resolve().parents[2]


def Material(tmp_path):
    """Copy real reviewed rule bytes without preparing a process or installing a binary."""

    template = tmp_path / "prometheus.yaml"
    template.write_bytes((REPOSITORY / "labs/external/benchmark/templates/"
                         "prometheus-exposition.yaml").read_bytes())
    configuration = tmp_path / "empty.yaml"
    configuration.write_bytes(EMPTY_CONFIG)

    return template, configuration


def Match(**overrides):
    """Return explicitly synthetic raw provider-shaped bytes for parser contracts only."""

    record = {"type": "http", "template-id": TEMPLATE_ID,
              "matched-at": ExactUrl("/metrics")}
    record.update(overrides)

    return json.dumps(record).encode() + b"\n"


def test_FrozenPinsAndInputsAgreeWithAcceptedCasePack():
    """Do not silently substitute target paths, rule bytes, archive identity, or budgets."""

    pack, _ = LoadPack()
    assert tuple(case["path"] for case in pack["cases"]) == PATHS, (
        "The runner must retain all three exact independently declared case paths."
    )
    assert VERSION == "3.4.10", "The comparison must use the accepted exact Nuclei version."
    assert ARCHIVE_NAME == "nuclei_3.4.10_linux_amd64.zip", (
        "The acquired archive must name the pinned Linux amd64 release asset."
    )
    assert ARCHIVE_BYTES == 33657343, "The release archive's pinned byte length must be preserved."
    assert ARCHIVE_SHA256 == "234c12cc5288af071abdcd6f854245b6067345556e1235cf96b76725c1004357", (
        "The release archive's independently reviewed SHA-256 pin must be preserved."
    )
    assert TEMPLATE_BYTES == 1215, "The comparison must retain the exact reviewed template length."
    assert TEMPLATE_SHA256 == pack["scanner_tracks"][1]["artifact"]["sha256"], (
        "The runner template digest must agree with the unchanged case-pack artifact."
    )
    assert "cdc0a17fa4b8710fd1d4db9bae606582448d863c6d03a28451fb299ae60859e2" in TEMPLATE_REVIEW, (
        "The profile must cite the actual accepted ADR0106 semantic review."
    )
    assert hashlib.sha256(EMPTY_CONFIG).hexdigest() == CONFIG_SHA256, (
        "The operator configuration must remain exactly the reviewed empty configuration."
    )
    assert (PROVIDER_TIMEOUT_SECONDS, WRAPPER_TIMEOUT_SECONDS) == (3, 8), (
        "Provider and wrapper deadlines must preserve their distinct approved time windows."
    )
    assert (STDOUT_BYTES, STDERR_BYTES, MAX_FILE_BYTES) == (4194304, 65536, 2097152), (
        "Capture ceilings and the smaller original-file export ceiling must remain distinct."
    )


@pytest.mark.parametrize("path", PATHS)
def test_DirectArgumentsMatchGovernedDetectionFlagsWithoutLaunching(tmp_path, path):
    """The independently built direct argv equals the existing governed invocation contract."""

    template, configuration = Material(tmp_path)
    document = ProfileDocument(template, configuration)
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(document))
    profile = ReadNucleiProfile(profile_path)
    executable = tmp_path / "nuclei-not-installed"
    adapter = NucleiAdapter(lambda reference: b"", profile, str(executable), VERSION)
    limits = NucleiScanLimits(timeout_seconds=3, rate_limit=1)
    request = AdapterRequest("web.http-template-check", "target:contract-only",
        ImpactLevel.STANDARD, {"url": ExactUrl(path), "profile_sha256": profile.Digest,
                              "timeout_seconds": limits.timeout_seconds,
                              "rate_limit": limits.rate_limit})
    invocation = adapter.BuildInvocation(request)
    direct = StandaloneArguments(executable, path, template, configuration)
    assert direct == invocation.argv, (
        "Direct standalone arguments must exactly match the governed detection flags."
    )
    assert invocation.timeout_seconds == 3, "The governed provider deadline must remain 3 seconds."
    assert invocation.provider_version == VERSION, (
        "The invocation must retain the exact binary pin."
    )
    assert json.loads(SerializeContract(profile)) == document, (
        "Product profile serialization must preserve every reviewed material and attribution field."
    )
    assert "fixture" not in document["templates"][0]["review_reference"], (
        "Actual rule provenance must not substitute a contract fixture for semantic review."
    )
    assert not executable.exists(), "Argument construction must never acquire or run a provider."


@pytest.mark.parametrize("path", [
    "/metrics/", "/metrics?x=1", "http://example.test/", "../metrics",
])
def test_OnlyTheSameThreeExactInputsAreAdmitted(path):
    """No route discovery, arbitrary target URL, spelling rewrite, or input expansion is allowed."""

    with pytest.raises(ValueError, match="three exact"):
        ExactUrl(path)


def test_ProfileRefusesChangedOrLinkedMaterial(tmp_path):
    """Digest equality and singly linked ordinary files remain independent requirements."""

    template, configuration = Material(tmp_path)
    template.write_bytes(template.read_bytes().replace(b"GET", b"PUT"))

    with pytest.raises(ValueError, match="exact reviewed"):
        ProfileDocument(template, configuration)

    template, configuration = Material(tmp_path)
    alias = tmp_path / "alias.yaml"
    os.link(template, alias)

    with pytest.raises(ValueError, match="singly linked"):
        ProfileDocument(template, configuration)


def test_PreflightSeparatesArchiveBinaryAndVersionFacts(tmp_path):
    """Synthetic digest checks do not establish official acquisition or genuine version probing."""

    binary = tmp_path / "inert-binary-not-executed"
    binary.write_bytes(b"inert source-contract bytes; never executed")
    binary.chmod(0o700)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    assert VerifyBinary(binary, digest, VERSION)["sha256"] == digest, (
        "Digest preflight must report the exact inert file bytes without executing them."
    )

    with pytest.raises(ValueError, match="exact 3.4.10"):
        VerifyBinary(binary, digest, "3.4.11")

    with pytest.raises(ValueError, match="acquired identity"):
        VerifyBinary(binary, "0" * 64, VERSION)

    archive = tmp_path / ARCHIVE_NAME
    archive.write_bytes(b"not the official archive")

    with pytest.raises(ValueError, match="pinned official"):
        VerifyArchive(archive)


def test_InstalledInventoryRefusesTheSourceCheckout(tmp_path):
    """Importability from this test checkout cannot masquerade as installed-wheel acceptance."""

    with pytest.raises(ValueError, match="isolated current-wheel"):
        InstalledInventory("a" * 40, tmp_path / "not-installed.whl")


@pytest.mark.parametrize("raw", [
    b'{"type":"http","type":"http"}\n', b'{"value":NaN}\n', b'{"value":1e999}\n',
    b'\xff\n', b'\n', b'[]\n', Match(**{"type": "dns"}),
    Match(**{"matcher-status": False}), Match(**{"template-id": ""}),
    Match(**{"matched-at": "relative"}),
])
def test_StandaloneProjectionRejectsAmbiguousOrNonmatchBytes(raw):
    """Malformed, nonfinite, duplicate-key, and unsuccessful events cannot become matches."""

    with pytest.raises((ValueError, UnicodeError)):
        ProjectStandaloneMatches(raw)


def test_StandaloneProjectionPreservesUnknownIdentitiesAndOriginalOrder():
    """Unmapped rule/input records remain visible without product prefix or normalization."""

    raw = Match() + Match(**{"template-id": "unreviewed-rule",
                             "matched-at": "http://127.0.0.1:3000/other"})
    projected = ProjectStandaloneMatches(raw)
    assert projected == ProjectNucleiMatches(raw, "external-nuclei"), (
        "Independent standalone identities must remain compatible with the accepted v2 consumer."
    )
    assert projected[1] == {"rule_id": "unreviewed-rule", "path": "/other",
                            "target_url": "http://127.0.0.1:3000/other"}, (
        "Unknown rule and off-case URL identities must remain visible in their original order."
    )
    assert ProjectStandaloneMatches(b"") == [], "Empty output proves no response-level absence."


@pytest.mark.parametrize("case_id", [
    "metrics.exposed", "metrics.json-control", "metrics.html-control",
])
@pytest.mark.parametrize("identity_change", ["query", "fragment", "no-port"])
def test_OffCaseHttpIdentitiesRemainUnprovenThroughV2(tmp_path, case_id, identity_change):
    """Valid HTTP identities survive verbatim while exact-input mismatches receive no score."""

    pack, target = LoadPack()
    track = next(item for item in pack["scanner_tracks"] if item["id"] == "external-nuclei")
    track["implementation"] = "available"
    observation = ContractNucleiObservation(pack, target, tmp_path, case_id=case_id)
    execution = observation["execution"]
    target_url = execution["target_url"]

    if identity_change == "query":
        matched_at = target_url + "?raw=%2f&source=off-case"

    elif identity_change == "fragment":
        matched_at = target_url + "#raw-marker"

    else:
        matched_at = target_url.replace(":3000", "", 1)

    raw = Match(**{"matched-at": matched_at})
    findings = ProjectStandaloneMatches(raw)
    execution["findings"] = findings
    WriteNucleiContractEvidence(observation, tmp_path, stdout=raw)
    report = BuildComparison(pack, target, [observation], tmp_path)
    cell = next(item for item in report["cells"]
                if item["case_id"] == case_id and item["scanner_track"] == "external-nuclei")
    stdout = next(item for item in execution["evidence"] if item["role"] == "stdout")
    counts = report["finite_completed_case_counts"]["external-nuclei"]
    assert findings == ProjectNucleiMatches(raw, "external-nuclei"), (
        "Standalone projection must preserve valid off-case identities accepted by v2."
    )
    assert findings[0]["target_url"] == matched_at, (
        "Projection must retain query, fragment and absent explicit port verbatim."
    )
    assert (tmp_path / stdout["path"]).read_bytes() == raw, (
        "The v2 envelope must retain the original raw record without rewriting its URL."
    )
    assert cell["status"] == "unproven" and cell["score"] is None, (
        "An exact-input mismatch must remain unproven on both positive and negative controls."
    )
    assert cell["unadjudicated_findings"] == findings, (
        "Every off-case raw identity must remain visible for later adjudication."
    )
    assert all(counts[score] == 0 for score in ("tp", "fp", "tn", "fn")), (
        "Off-case identities must never receive detection or absence credit."
    )
    assert report["pairwise_conditions"] == [], (
        "An unproven observation must not enter completed-case comparison pairs."
    )


@pytest.mark.parametrize("matched_at", [
    "http://operator@127.0.0.1:3000/metrics", "http://127.0.0.1:invalid/metrics",
    "http://127.0.0.1:0/metrics", "http://127.0.0.1:65536/metrics", "http:///metrics",
    "https://127.0.0.1:3000/metrics", "http://127.0.0.1:3000/metrics\x7f",
    "http://127.0.0.1:3000/metrics\nignored",
])
def test_ProjectionKeepsMalformedHttpIdentityRefusals(matched_at):
    """Preserving valid off-case URLs cannot admit malformed authority or control characters."""

    with pytest.raises(ValueError, match="HTTP"):
        ProjectStandaloneMatches(Match(**{"matched-at": matched_at}))


@pytest.mark.parametrize("path", PATHS)
def test_AttemptManifestRetainsUnknownContacts(path):
    """The exact configured GET neither claims a completed response nor fabricates telemetry."""

    attempt = AttemptProvenance(path)
    assert attempt == {"basis": "approved-single-configured-nuclei-invocation",
        "approved_attempt_count": 1, "independent_server_contact_count": None,
        "configured_requests": [{"method": "GET", "url": ExactUrl(path)}]}, (
        "Attempt provenance must retain the configured exact GET and explicitly unknown contacts."
    )


def test_OriginalCustodyRefusesOversizeInsteadOfTruncating(tmp_path):
    """The reused original-byte transport keeps its unchanged 2 MiB refusal boundary."""

    source = tmp_path / "source"
    source.mkdir()
    raw = Match() + b"\x00\xff\r\n"
    (source / "stdout.raw").write_bytes(raw)
    output = tmp_path / "imported"
    bundle = ExportBundle(source, {"status": "inert-contract-not-executed"}).encode()
    ImportBundle(bundle, output)
    assert (output / "stdout.raw").read_bytes() == raw, (
        "Bundle transport must preserve original raw bytes, including non-UTF-8 bytes."
    )
    (source / "stdout.raw").write_bytes(b"x" * (MAX_FILE_BYTES + 1))

    with pytest.raises(ValueError, match="finite original-byte"):
        ExportBundle(source, {"status": "inert-contract-not-executed"})

    with pytest.raises(ValueError, match="2 MiB"):
        ProjectStandaloneMatches(b"x" * (MAX_FILE_BYTES + 1))


def test_RegularIdentityRejectsSymlinksWithoutReadingTheTarget(tmp_path):
    """Artifact provenance cannot traverse a symbolic alias even when the target is bounded."""

    target = tmp_path / "target"
    target.write_bytes(b"inert")
    alias = tmp_path / "alias"
    alias.symlink_to(target)

    with pytest.raises(ValueError, match="symbolic links"):
        RegularIdentity(alias, maximum=16)
