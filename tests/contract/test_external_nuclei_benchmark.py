# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Inert Nuclei source contracts; no genuine binary, provider, target, or Docker execution."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from fuzzy1337.adapters import AdapterRequest, ImpactLevel, SerializeContract
from fuzzy1337.adapters import nuclei as nuclei_adapter
from fuzzy1337.adapters.nuclei import NucleiAdapter
from fuzzy1337.nucleiscan import NucleiScanLimits, ReadNucleiProfile
from tests.contract.test_external_benchmark import (
    ContractNucleiObservation,
    WriteNucleiContractEvidence,
)
from tests.functional import external_nuclei_runner as runner
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
    TARGET_INDEX_DIGEST,
    TARGET_PLATFORM_DIGEST,
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
    RunStandalone,
    StandaloneArguments,
    VerifyArchive,
    VerifyBinary,
)

REPOSITORY = Path(__file__).resolve().parents[2]
CONTAINER_EXECUTABLE = PurePosixPath("/opt/benchmark/nuclei")
CONTAINER_TEMPLATE = PurePosixPath("/opt/benchmark/prometheus.yaml")
CONTAINER_CONFIGURATION = PurePosixPath("/opt/benchmark/operator-config.yaml")


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
def test_DirectArgumentsMatchGovernedDetectionFlagsWithoutLaunching(tmp_path, monkeypatch, path):
    """The independently built direct argv equals the existing governed invocation contract."""

    template, configuration = Material(tmp_path)
    document = ProfileDocument(template, configuration)
    # This pure argv fixture represents Linux container paths, without filesystem access.
    monkeypatch.setattr(nuclei_adapter, "Path", PurePosixPath)
    document["templates"][0]["path"] = str(CONTAINER_TEMPLATE)
    document["configuration_path"] = str(CONTAINER_CONFIGURATION)
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(document))
    profile = ReadNucleiProfile(profile_path)
    executable = tmp_path / "nuclei-not-installed"
    adapter = NucleiAdapter(lambda reference: b"", profile, str(CONTAINER_EXECUTABLE), VERSION)
    limits = NucleiScanLimits(timeout_seconds=3, rate_limit=1)
    request = AdapterRequest("web.http-template-check", "target:contract-only",
        ImpactLevel.STANDARD, {"url": ExactUrl(path), "profile_sha256": profile.Digest,
                              "timeout_seconds": limits.timeout_seconds,
                              "rate_limit": limits.rate_limit})
    invocation = adapter.BuildInvocation(request)
    direct = StandaloneArguments(CONTAINER_EXECUTABLE, path,
                                 CONTAINER_TEMPLATE, CONTAINER_CONFIGURATION)
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


def StandaloneMaterial(tmp_path, path="/metrics"):
    """Prepare inert executable bytes and an explicit synthetic fixture authorization claim."""

    template, configuration = Material(tmp_path)
    executable = tmp_path / "inert-never-executed"
    executable.write_bytes(b"inert contract material; Popen is always replaced")
    executable.chmod(0o700)
    authorization = {"basis": "owned-pinned-external-target-fixture",
        "authorization_reference": "consent:inert-contract-only", "owner": "operator:contract",
        "target_url": ExactUrl(path), "target_instance": "a" * 64,
        "image_index_digest": TARGET_INDEX_DIGEST, "platform_digest": TARGET_PLATFORM_DIGEST,
        "network_internal": True, "published_ports": 0}

    return (tmp_path / "run", path, executable, template, configuration,
            hashlib.sha256(executable.read_bytes()).hexdigest(), VERSION, authorization)


def InertProcess(monkeypatch, *, stdout=b"", stderr=b"", exit_code=0, stalled=False,
                 launch_error=None, cleanup_error=None, wait_timeout=False, interrupted=False,
                 capture_error=None, reap_error=None, read_delay=0, container_paths=False):
    """Replace every process, pipe, selector, signal, and clock interaction without OS execution."""

    monkeypatch.setattr(runner.sys, "platform", "linux")

    for name, fallback in (("P_PID", 1), ("WEXITED", 4), ("WNOHANG", 1), ("WNOWAIT", 0x1000000)):
        monkeypatch.setattr(runner.os, name, getattr(os, name, fallback), raising=False)

    monkeypatch.setattr(runner.signal, "SIGKILL", getattr(signal, "SIGKILL", 9), raising=False)

    def ContainerArguments(executable, path, template, configuration):
        """Spell only mocked Linux container argv paths independently of host workspace syntax."""

        return StandaloneArguments(CONTAINER_EXECUTABLE, path,
                                   CONTAINER_TEMPLATE, CONTAINER_CONFIGURATION)

    if os.name == "nt" or container_paths:
        # Real host files still supply identity/custody. Only nonexecuted argv uses Linux spelling.
        monkeypatch.setattr(runner, "StandaloneArguments", ContainerArguments)

    process = MagicMock()
    process.pid = 424242
    process.stdout.fileno.return_value = 101
    process.stderr.fileno.return_value = 102
    process.wait.return_value = exit_code

    process.wait.side_effect = reap_error

    popen = MagicMock(return_value=process, side_effect=launch_error)
    kill = MagicMock(side_effect=cleanup_error)
    selector = MagicMock()
    selector.__enter__.return_value = selector
    registered = {}
    buffers = {101: stdout, 102: stderr}
    clock = [0.0]

    def Register(stream, events, data):
        """Retain synthetic stream registrations using the real selector-shaped fields."""

        registered[stream] = SimpleNamespace(fileobj=stream, data=data)

    def Select(timeout):
        """Deliver deterministic readiness or advance the owned provider deadline."""

        if interrupted:
            raise KeyboardInterrupt("Inert cancellation")

        if capture_error is not None:
            raise capture_error

        if stalled:
            clock[0] += 3.01

            return []

        return [(key, 1) for key in list(registered.values())]

    def Read(descriptor, count):
        """Respect each real read budget while delivering only explicitly supplied inert bytes."""

        raw = buffers[descriptor][:count]
        buffers[descriptor] = buffers[descriptor][count:]
        clock[0] += read_delay

        return raw

    def Sleep(duration):
        """Advance only the synthetic deadline while an unreaped leader is still running."""

        clock[0] += duration

    selector.register.side_effect = Register
    selector.unregister.side_effect = registered.pop
    selector.get_map.side_effect = lambda: registered
    selector.select.side_effect = Select
    monkeypatch.setattr(runner.subprocess, "Popen", popen)
    monkeypatch.setattr(runner.selectors, "DefaultSelector", MagicMock(return_value=selector))
    monkeypatch.setattr(runner.os, "read", Read)
    monkeypatch.setattr(runner.os, "killpg", kill, raising=False)
    monkeypatch.setattr(runner.os, "waitid", MagicMock(
        return_value=None if wait_timeout else SimpleNamespace(si_status=exit_code)), raising=False)
    monkeypatch.setattr(runner.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(runner.time, "sleep", Sleep)

    return process, popen, kill


@pytest.mark.parametrize("path", PATHS)
def test_StandaloneRuntimeEmptyInvocationRemainsUnprovenThroughV2(tmp_path, monkeypatch, path):
    """Inert successful empty capture earns no absence credit for any frozen truth case."""

    arguments = StandaloneMaterial(tmp_path, path)
    process, popen, kill = InertProcess(monkeypatch)
    outcome = RunStandalone(*arguments)
    root = arguments[0]
    invocation = json.loads((root / "invocation.json").read_bytes())
    assert outcome["status"] == "unproven" and outcome["findings"] == [], (
        "Empty exit-zero output must remain unproven for positive and negative controls."
    )
    assert (root / "stdout.raw").read_bytes() == b"", (
        "The runner must retain an actual empty original stdout artifact."
    )
    assert json.loads((root / "attempt-provenance.json").read_bytes()) == AttemptProvenance(path), (
        "Process completion must never replace unknown contacts with invented server telemetry."
    )
    expected_argv = StandaloneArguments(CONTAINER_EXECUTABLE, path,
        CONTAINER_TEMPLATE, CONTAINER_CONFIGURATION) if os.name == "nt" else StandaloneArguments(
            arguments[2], path, root / "prometheus-exposition.yaml", root / "operator-config.yaml")
    assert tuple(invocation["argv"]) == expected_argv, (
        "The launched argv must retain only the exact independently constructed detection flags."
    )
    options = popen.call_args.kwargs
    home = root / "runtime-home"
    assert options["env"] == {"HOME": str(home), "XDG_CONFIG_HOME": str(home / "config"),
        "XDG_CACHE_HOME": str(home / "cache"), "TMPDIR": str(home / "tmp")}, (
        "The process must receive only its owned HOME/cache/temp paths, "
        "without inherited variables."
    )
    assert options["start_new_session"] is True and options["shell"] is False, (
        "The runner must own a separate process group without introducing shell interpretation."
    )
    runner.os.waitid.assert_called_once_with(
        os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    assert process.wait.call_args.kwargs["timeout"] == 1, (
        "The unreaped leader must keep its group identity until cleanup, followed by bounded reap."
    )
    kill.assert_called_once_with(process.pid, signal.SIGKILL)
    assert process.stdout.close.called and process.stderr.close.called, (
        "Both original capture handles must close after unconditional group cleanup and reap."
    )
    pack, target = LoadPack()
    next(track for track in pack["scanner_tracks"]
         if track["id"] == "external-nuclei")["implementation"] = "available"
    case = next(case for case in pack["cases"] if case["path"] == path)
    observation = ContractNucleiObservation(pack, target, tmp_path, case_id=case["id"])
    observation.update(status=outcome["status"], reason=outcome["reason"])
    observation["execution"]["findings"] = outcome["findings"]
    WriteNucleiContractEvidence(observation, tmp_path, stdout=(root / "stdout.raw").read_bytes())
    report = BuildComparison(pack, target, [observation], tmp_path)
    counts = report["finite_completed_case_counts"]["external-nuclei"]
    assert all(counts[score] == 0 for score in ("tp", "fp", "tn", "fn")), (
        "Runner-produced empty invocation status must receive no TP, FP, TN, or FN through v2."
    )


@pytest.mark.parametrize("record_change, expected_status", [
    ({}, "completed"), ({"template-id": "unknown-rule"}, "unproven"),
    ({"matched-at": ExactUrl("/")}, "unproven"),
])
def test_StandaloneRuntimeUsesOnlyExactRawMatchBinding(
    tmp_path, monkeypatch, record_change, expected_status,
):
    """Only the frozen rule and actual exact case URL can establish finite mapped completion."""

    arguments = StandaloneMaterial(tmp_path)
    raw = Match(**record_change)
    InertProcess(monkeypatch, stdout=raw, stderr=b"inert diagnostics\xff\r\n")
    outcome = RunStandalone(*arguments)
    root = arguments[0]
    assert outcome["status"] == expected_status, (
        "Only an explicit exact-rule/exact-input match may move an invocation to completed."
    )
    assert outcome["findings"] == ProjectStandaloneMatches(raw), (
        "Unknown and off-case raw identities must remain visible without product normalization."
    )
    assert (root / "stdout.raw").read_bytes() == raw, (
        "Standalone execution must preserve original matching stdout bytes verbatim."
    )
    assert (root / "stderr.raw").read_bytes() == b"inert diagnostics\xff\r\n", (
        "Non-UTF-8 stderr must remain original bytes instead of a replacement-decoded log view."
    )
    assert (root / "prometheus-exposition.yaml").read_bytes() == arguments[3].read_bytes(), (
        "Execution must use and retain its own singly linked copy of the reviewed exact template."
    )
    assert (root / "operator-config.yaml").read_bytes() == EMPTY_CONFIG, (
        "Execution must retain the exact copied empty operator configuration."
    )


@pytest.mark.parametrize("failure", ["nonzero", "invalid", "blank", "cleanup", "timeout"])
def test_StandaloneRuntimeFailuresRetainOriginalPartialMatches(tmp_path, monkeypatch, failure):
    """A valid observed match cannot conceal lifecycle, parse, or cleanup failure."""

    arguments = StandaloneMaterial(tmp_path)
    raw = Match() + (b"not-json\xff\n" if failure == "invalid" else
                     b"\n" if failure == "blank" else b"")
    process, _, kill = InertProcess(monkeypatch, stdout=raw,
        exit_code=2 if failure == "nonzero" else 0,
        cleanup_error=PermissionError("inert cleanup failure") if failure == "cleanup" else None,
        wait_timeout=failure == "timeout")
    outcome = RunStandalone(*arguments)
    root = arguments[0]
    lifecycle = json.loads((root / "process.json").read_bytes())
    assert outcome["status"] == "failed", (
        "Nonzero, malformed, timed-out, or cleanup-failed execution must remain unscored."
    )
    assert outcome["findings"] == ProjectStandaloneMatches(Match()), (
        "Available valid raw matches must remain visible even when the enclosing execution fails."
    )
    assert (root / "stdout.raw").read_bytes() == raw, (
        "Failed execution must preserve every captured original byte, including malformed records."
    )
    assert lifecycle["timed_out"] == (failure == "timeout"), (
        "A provider deadline failure must stay distinct from nonzero and parse failures."
    )
    assert (lifecycle["cleanup_error"] is not None) == (failure == "cleanup"), (
        "An unsuccessful process-group cleanup must remain explicit in original lifecycle evidence."
    )
    kill.assert_called_once_with(process.pid, signal.SIGKILL)


def test_StandaloneRuntimeStalledPipesAreKilledAndReaped(tmp_path, monkeypatch):
    """Pipe ownership cannot extend the provider window when no output or EOF arrives."""

    arguments = StandaloneMaterial(tmp_path)
    process, _, kill = InertProcess(monkeypatch, stalled=True)
    outcome = RunStandalone(*arguments)
    lifecycle = json.loads((arguments[0] / "process.json").read_bytes())
    assert outcome["status"] == "failed" and lifecycle["timed_out"] is True, (
        "A stalled provider must fail at its three-second deadline without response-success credit."
    )
    assert lifecycle["streams_complete"] is False, (
        "Killed stalled pipes must never be represented as complete original capture."
    )
    kill.assert_called_once_with(process.pid, signal.SIGKILL)
    assert process.wait.call_args.kwargs["timeout"] == 1, (
        "The cleanup reap must use its own bounded one-second window after provider termination."
    )


@pytest.mark.parametrize("role", ["stdout", "stderr"])
def test_StandaloneRuntimeCaptureExhaustionRefusesSuccess(tmp_path, monkeypatch, role):
    """Each finite capture ceiling kills the owned process and records incomplete streams."""

    arguments = StandaloneMaterial(tmp_path)
    limit = STDOUT_BYTES if role == "stdout" else STDERR_BYTES
    raw = b"x" * (limit + 1)
    process, _, kill = InertProcess(monkeypatch, **{role: raw})
    outcome = RunStandalone(*arguments)
    lifecycle = json.loads((arguments[0] / "process.json").read_bytes())
    assert outcome["status"] == "failed" and lifecycle["capture_exhausted"] == role, (
        "Exhausting either capture ceiling must fail with the exact stream identified."
    )
    assert lifecycle["streams_complete"] is False, (
        "An exhausted stream must never masquerade as a complete output acquisition."
    )
    assert (arguments[0] / (role + ".raw")).read_bytes() == raw, (
        "Available original bytes, including the overflow detection byte, must remain retained."
    )
    kill.assert_called_once_with(process.pid, signal.SIGKILL)


def test_StandaloneRuntimeSmallerExportCeilingRefusesWithoutTruncating(tmp_path, monkeypatch):
    """A complete capture below four MiB still fails the unchanged two MiB file transport."""

    arguments = StandaloneMaterial(tmp_path)
    raw = Match() + b" " * (MAX_FILE_BYTES + 1)
    InertProcess(monkeypatch, stdout=raw)
    outcome = RunStandalone(*arguments)
    assert outcome["status"] == "failed" and outcome["oversized_original"] is True, (
        "A provider-success capture above two MiB must fail original-byte custody without scoring."
    )
    assert (arguments[0] / "stdout.raw").read_bytes() == raw, (
        "Export refusal must preserve the complete available original capture without truncation."
    )
    assert outcome["findings"] == [], (
        "An oversized original must never be parsed through a misleading bounded matching prefix."
    )
    with pytest.raises(ValueError, match="finite original-byte"):
        ExportBundle(arguments[0], outcome)


def test_StandaloneRuntimeLaunchFailurePreservesEmptyRawAndError(tmp_path, monkeypatch):
    """A missing executable at launch cannot become an empty successful no-match invocation."""

    arguments = StandaloneMaterial(tmp_path)
    _, popen, kill = InertProcess(monkeypatch, launch_error=FileNotFoundError("inert missing file"))
    outcome = RunStandalone(*arguments)
    lifecycle = json.loads((arguments[0] / "process.json").read_bytes())
    assert outcome["status"] == "failed" and lifecycle["launch_error"] == "FileNotFoundError", (
        "A launch failure must remain an explicit unscored process error."
    )
    assert outcome["exit_code"] is None and lifecycle["streams_complete"] is False, (
        "A process that never launched has no exit code or complete capture to invent."
    )
    assert (arguments[0] / "stdout.raw").read_bytes() == b"", (
        "Launch failure must preserve its available empty raw stdout artifact."
    )
    popen.assert_called_once()
    kill.assert_not_called()


@pytest.mark.parametrize("field, value", [
    ("target_url", "http://example.test/metrics"), ("target_instance", "unowned"),
    ("network_internal", False), ("published_ports", True),
    ("image_index_digest", "sha256:" + "0" * 64), ("platform_digest", "sha256:" + "0" * 64),
    ("basis", "product-policy-grant"), ("authorization_reference", ""),
])
def test_StandaloneRuntimeRejectsUnprovenAuthorityBeforeLaunch(
    tmp_path, monkeypatch, field, value,
):
    """Exact fixture authority is mandatory even for negative controls and empty output."""

    arguments = StandaloneMaterial(tmp_path)
    arguments[-1][field] = value
    _, popen, _ = InertProcess(monkeypatch)

    with pytest.raises(ValueError, match="owned-fixture authorization"):
        RunStandalone(*arguments)

    popen.assert_not_called()
    assert not arguments[0].exists(), (
        "Rejected fixture authority must not create artifacts or imply an admitted attempt."
    )


def test_StandaloneRuntimeCancellationAlwaysCleansItsOwnedGroup(tmp_path, monkeypatch):
    """Propagate interruption after retaining partial streams and bounded owned-process cleanup."""

    arguments = StandaloneMaterial(tmp_path)
    process, _, kill = InertProcess(monkeypatch, interrupted=True)

    with pytest.raises(KeyboardInterrupt, match="Inert cancellation"):
        RunStandalone(*arguments)

    kill.assert_called_once_with(process.pid, signal.SIGKILL)
    assert process.wait.called and process.stdout.close.called and process.stderr.close.called, (
        "Cancellation must reap the process and close both capture handles before propagation."
    )
    lifecycle = json.loads((arguments[0] / "process.json").read_bytes())
    assert lifecycle["streams_complete"] is False, (
        "Interrupted capture must retain explicit incomplete lifecycle evidence."
    )
    assert lifecycle["interrupted"] == "KeyboardInterrupt", (
        "Cancellation must retain its explicit interruption cause before propagating."
    )


@pytest.mark.parametrize("failure", ["selector", "reap"])
def test_StandaloneRuntimeUnexpectedCaptureAndReapFailuresStayUnscored(
    tmp_path, monkeypatch, failure,
):
    """Retain explicit failed lifecycle evidence for unexpected selector and reap errors."""

    arguments = StandaloneMaterial(tmp_path)
    process, _, kill = InertProcess(monkeypatch, stdout=Match(),
        capture_error=RuntimeError("inert selector failure") if failure == "selector" else None,
        reap_error=subprocess.TimeoutExpired("inert", 1) if failure == "reap" else None)
    outcome = RunStandalone(*arguments)
    lifecycle = json.loads((arguments[0] / "process.json").read_bytes())
    assert outcome["status"] == "failed", (
        "Unexpected capture exceptions and unsuccessful reaping must never receive case credit."
    )
    expected_field = "capture_error" if failure == "selector" else "cleanup_error"
    assert lifecycle[expected_field] is not None, (
        "The actual capture or cleanup failure category must remain in lifecycle evidence."
    )
    assert (arguments[0] / "stdout.raw").exists() and (arguments[0] / "stderr.raw").exists(), (
        "Every available original capture must remain on disk even after unexpected failure."
    )
    kill.assert_called_once_with(process.pid, signal.SIGKILL)


@pytest.mark.parametrize("changed", ["binary", "version", "template", "configuration"])
def test_StandaloneRuntimeRejectsChangedPrerequisitesBeforeProcessCreation(
    tmp_path, monkeypatch, changed,
):
    """Runtime entry cannot bypass exact preflight pins just because fixture authority is valid."""

    arguments = list(StandaloneMaterial(tmp_path))

    if changed == "binary":
        arguments[2].write_bytes(b"changed inert executable")

    elif changed == "version":
        arguments[6] = "3.4.11"

    elif changed == "template":
        arguments[3].write_bytes(b"changed rule")

    else:
        arguments[4].write_bytes(b"[]\n")

    _, popen, _ = InertProcess(monkeypatch)

    with pytest.raises(ValueError):
        RunStandalone(*arguments)

    popen.assert_not_called()
    assert not arguments[0].exists(), (
        "Changed prerequisites must fail before workspace creation or provider launch."
    )


def test_StandaloneRuntimeFinalEofCannotExtendProviderDeadline(tmp_path, monkeypatch):
    """EOF at the deadline cannot turn a late observed exit into successful completion."""

    arguments = StandaloneMaterial(tmp_path)
    process, _, kill = InertProcess(monkeypatch, stdout=Match(), read_delay=1)
    outcome = RunStandalone(*arguments)
    lifecycle = json.loads((arguments[0] / "process.json").read_bytes())
    assert outcome["status"] == "failed" and lifecycle["timed_out"] is True, (
        "Reaching final EOF at the provider deadline must remain an unscored timeout."
    )
    assert lifecycle["duration_seconds"] == 3 and lifecycle["streams_complete"] is False, (
        "The runner must not grant extra observation time after consuming its three-second budget."
    )
    runner.os.waitid.assert_not_called()
    kill.assert_called_once_with(process.pid, signal.SIGKILL)
    assert outcome["findings"] == ProjectStandaloneMatches(Match()), (
        "An unscored deadline failure must still preserve available original matching identities."
    )


@pytest.mark.parametrize("platform", ["win32", "darwin"])
def test_StandaloneRuntimeUnsupportedPlatformRefusesBeforeLaunch(tmp_path, monkeypatch, platform):
    """Actual non-Linux execution must refuse before material preparation or child creation."""

    arguments = StandaloneMaterial(tmp_path)
    popen = MagicMock()
    monkeypatch.setattr(runner.sys, "platform", platform)
    monkeypatch.setattr(runner.subprocess, "Popen", popen)

    with pytest.raises(ValueError, match="requires Linux"):
        RunStandalone(*arguments)

    popen.assert_not_called()
    assert not arguments[0].exists(), (
        "Unsupported process ownership semantics must refuse before creating execution artifacts."
    )


def test_StandaloneRuntimeMissingLinuxPrimitiveRefusesBeforeLaunch(tmp_path, monkeypatch):
    """A nominal Linux host still needs every unreaped-group ownership primitive."""

    arguments = StandaloneMaterial(tmp_path)
    popen = MagicMock()
    monkeypatch.setattr(runner.sys, "platform", "linux")
    monkeypatch.delattr(runner.os, "waitid", raising=False)
    monkeypatch.setattr(runner.subprocess, "Popen", popen)

    with pytest.raises(ValueError, match="WNOWAIT support"):
        RunStandalone(*arguments)

    popen.assert_not_called()
    assert not arguments[0].exists(), (
        "Missing unreaped-group support must fail before workspace creation or process launch."
    )


def test_StandaloneRuntimeContainerPathSpellingStaysInsideInertMock(tmp_path, monkeypatch):
    """A non-POSIX host may spell mocked Linux argv while retaining real local custody files."""

    arguments = StandaloneMaterial(tmp_path)
    _, popen, _ = InertProcess(monkeypatch, container_paths=True)
    outcome = RunStandalone(*arguments)
    assert popen.call_args.args[0] == StandaloneArguments(CONTAINER_EXECUTABLE, "/metrics",
        CONTAINER_TEMPLATE, CONTAINER_CONFIGURATION), (
        "Only the nonexecuted mock argv may substitute explicit Linux container path spellings."
    )
    assert outcome["status"] == "unproven", (
        "Mock container path spelling cannot establish genuine execution or response-level absence."
    )
    copied = arguments[0] / "prometheus-exposition.yaml"
    assert copied.read_bytes() == arguments[3].read_bytes(), (
        "The host workspace must still retain the exact independently verified template copy."
    )
