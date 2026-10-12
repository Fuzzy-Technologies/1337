# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Reviewed profiles, finite argv, strict JSONL and truthful execution failures."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from fuzzy1337.adapters import (
    AdapterExecution,
    AdapterHealthState,
    AdapterReport,
    AdapterRequest,
    EvidenceReference,
    ExecutionState,
    ImpactLevel,
    ToolAdapter,
    nuclei,
)
from fuzzy1337.adapters.nuclei import (
    CanonicalUrl,
    NucleiAdapter,
    NucleiProfile,
    NucleiReportError,
    NucleiTemplate,
    ParseJsonl,
    VerifyArtifact,
)

FIXTURES = Path(__file__).parents[1] / "fixtures/nuclei"
JSONL = (FIXTURES / "result.jsonl").read_bytes()


def Profile(tmp_path):
    """Materialize owned reviewed artifacts, keeping their synthetic provenance.

    Args:
        tmp_path: Owned physical pytest directory.

    Returns:
        Profile containing one exact source-controlled synthetic template.
    """

    template_path = tmp_path / "reviewed-get.yaml"
    raw = (FIXTURES / "reviewed-get.yaml").read_bytes()
    template_path.write_bytes(raw)
    configuration_path = tmp_path / "nuclei-empty.yaml"
    configuration_path.write_bytes(b"{}\n")
    template = NucleiTemplate("owned-http-marker", str(template_path),
        hashlib.sha256(raw).hexdigest(), len(raw), "fixture:owned-nuclei", "1",
        "review:source-controlled-synthetic", "single-get-exact-url")

    return NucleiProfile("owned-synthetic", (template,), str(configuration_path))


def Request(profile, **parameters):
    """Build finite preparation metadata without granting any execution authorization.

    Args:
        profile: Exact reviewed profile.
        parameters: Request parameter overrides.

    Returns:
        Existing SDK request bound to every profile provenance field.
    """

    values = {"url": "http://127.0.0.1:8080/", "profile_sha256": profile.Digest,
              "timeout_seconds": 10, "rate_limit": 2}
    values.update(parameters)

    return AdapterRequest("web.http-template-check", "target:owned", ImpactLevel.STANDARD, values)


def Report(tmp_path, raw=JSONL, state=ExecutionState.SUCCEEDED):
    """Bind exact raw fixture bytes to a real SDK invocation and terminal outcome.

    Args:
        tmp_path: Owned artifact directory.
        raw: Exact captured stdout fixture.
        state: Terminal executor truth.

    Returns:
        Adapter and immutable report for parser tests.
    """

    profile = Profile(tmp_path)
    adapter = NucleiAdapter(lambda reference: raw, profile, provider_version="3.4.10-synthetic")
    reference = EvidenceReference("stdout", "fixture/nuclei.jsonl", hashlib.sha256(raw).hexdigest(),
                                  "application/x-ndjson", len(raw))
    execution = AdapterExecution(state, 0 if state is ExecutionState.SUCCEEDED else 7, 0.5)
    report = AdapterReport(adapter.PrepareInvocation(Request(profile)), execution, (reference,))

    return adapter, report


def test_FinitePreparationKeepsSdkAndReviewedProvenance(tmp_path, monkeypatch):
    """Preparation reads only explicit artifacts and never invokes the provider process."""

    profile = Profile(tmp_path)
    adapter = NucleiAdapter(lambda reference: JSONL, profile, provider_version="3.4.10")

    def NoProcess(*arguments, **keywords):
        """Fail if preparation starts a process instead of preparing argv."""

        pytest.fail("preparation must never start a process")

    monkeypatch.setattr(nuclei.subprocess, "Popen", NoProcess)
    invocation = adapter.PrepareInvocation(Request(profile))

    assert isinstance(adapter, ToolAdapter), "Nuclei must satisfy the unchanged SDK protocol."
    assert adapter.Descriptor.capabilities == ("web.http-template-check",), (
        "Only the reviewed finite HTTP capability may be declared."
    )
    assert invocation.argv == ("nuclei", "-u", "http://127.0.0.1:8080/", "-config",
        profile.configuration_path, "-pt", "http", "-jsonl", "-silent", "-nc", "-omit-raw",
        "-omit-template", "-duc", "-ni", "-dr", "-no-stdin", "-nh", "-dc", "-rl", "2",
        "-bs", "1", "-c", "1", "-retries", "0", "-mhe", "1", "-timeout", "10", "-rsr",
        "1048576", "-rss", "1048576", "-t", profile.templates[0].path), (
        "Exact argv must suppress remote updates, OAST, redirects and implicit tool profiles."
    )
    assert invocation.provider_version == "3.4.10", "Observed version must survive preparation."
    assert invocation.timeout_seconds == 10, "The executor keeps an independent total deadline."
    assert invocation.request is not None, "The exact approval request must remain attributable."


@pytest.mark.parametrize("url", [
    "http://localhost/", "http://127.0.0.1,127.0.0.2/", "ftp://127.0.0.1/",
    "http://user:password@127.0.0.1/", "http://127.0.0.1/?secret=x", "http://127.0.0.1/#fragment",
    "http://0.0.0.0/", "http://224.0.0.1/", "http://[fe80::1%eth0]/", "http://127.0.0.1:0/",
    "http://127.0.0.1:65536/", "http://127.0.0.1/\n", "http://127.0.0.1/\\path", None,
    "http://255.255.255.255/", "\x01http://127.0.0.1/", "http://127.0.0.1/\x01",
    "http://127.0.0.1/\x7f",
])
def test_RejectUrlExpansionAndCredentials(url):
    """Only one exact literal URL can enter the finite CLI profile."""

    with pytest.raises(ValueError):
        CanonicalUrl(url)


def test_CanonicalLiteralIpv6AndHttpsDefaults():
    """Canonical URL binding is offline and keeps IPv6 brackets and exact paths."""

    assert CanonicalUrl("https://[2001:0db8::1]/owned") == "https://[2001:db8::1]:443/owned", (
        "IPv6 canonicalization must not resolve or expand targets."
    )
    assert CanonicalUrl("http://127.0.0.1") == "http://127.0.0.1:80/", (
        "An explicit default port and root path make replay comparisons deterministic."
    )


@pytest.mark.parametrize("parameters", [
    {"profile_sha256": "0" * 64}, {"timeout_seconds": True}, {"timeout_seconds": 301},
    {"timeout_seconds": 0}, {"rate_limit": 11}, {"rate_limit": 0}, {"rate_limit": 2.5},
    {"flags": "-code"},
])
def test_RejectUnsupportedParameters(tmp_path, parameters):
    """No raw provider flags or out-of-budget parameters can be prepared."""

    profile = Profile(tmp_path)
    adapter = NucleiAdapter(lambda reference: JSONL, profile, provider_version="3.4.10")

    with pytest.raises(ValueError):
        adapter.PrepareInvocation(Request(profile, **parameters))


def test_RejectCapabilityImpactCredentialsAndUnknownVersion(tmp_path):
    """Tool presence/profile selection cannot supply authority or version provenance."""

    profile = Profile(tmp_path)
    adapter = NucleiAdapter(lambda reference: JSONL, profile, provider_version="3.4.10")
    request = Request(profile)

    for invalid in (replace(request, capability="web.arbitrary"),
                    replace(request, impact=ImpactLevel.SAFE),
                    replace(request, credential_references=("secret:opaque",))):
        with pytest.raises(ValueError):
            adapter.PrepareInvocation(invalid)

    with pytest.raises(ValueError, match="observed version"):
        NucleiAdapter(lambda reference: JSONL, profile).PrepareInvocation(request)

    with pytest.raises(ValueError, match="3.x"):
        NucleiAdapter(lambda reference: JSONL, profile, provider_version="2.9.0")

    with pytest.raises(ValueError, match="profile"):
        NucleiAdapter(lambda reference: JSONL, None)


def test_ArtifactChangeAndConfigurationOverrideFailClosed(tmp_path):
    """Hash/size checks reject drift in reviewed templates and ambient-config overrides."""

    profile = Profile(tmp_path)
    adapter = NucleiAdapter(lambda reference: JSONL, profile, provider_version="3.4.10")
    Path(profile.templates[0].path).write_bytes(b"http: malicious\n")

    with pytest.raises(ValueError, match="digest/size"):
        adapter.PrepareInvocation(Request(profile))

    profile = Profile(tmp_path)
    adapter = NucleiAdapter(lambda reference: JSONL, profile, provider_version="3.4.10")
    Path(profile.configuration_path).write_bytes(b"headless: true\n")

    with pytest.raises(ValueError, match="digest/size"):
        adapter.PrepareInvocation(Request(profile))


def test_MissingDirectoriesAndLinkedArtifactsFailClosed(tmp_path):
    """Only existing regular owned files may reach a real Nuclei -t argument."""

    with pytest.raises(ValueError, match="unavailable"):
        VerifyArtifact(str(tmp_path / "missing.yaml"), "0" * 64, 1)

    with pytest.raises(ValueError, match="regular"):
        VerifyArtifact(str(tmp_path), "0" * 64, 1)

    if os.name != "nt":
        target = tmp_path / "target.yaml"
        target.write_bytes(b"x")
        link = tmp_path / "link.yaml"
        link.symlink_to(target)

        with pytest.raises(ValueError, match="links"):
            VerifyArtifact(str(link), hashlib.sha256(b"x").hexdigest(), 1)

        link.unlink()
        os.link(target, link)

        with pytest.raises(ValueError, match="regular"):
            VerifyArtifact(str(link), hashlib.sha256(b"x").hexdigest(), 1)


def test_TemplateAndProfileRejectUnreviewedOrAmbiguousArtifacts(tmp_path):
    """Provenance and approved read-only profile attestations are mandatory."""

    profile = Profile(tmp_path)
    template = profile.templates[0]

    for fields in ({"review_reference": ""}, {"source_revision": ""}, {"sha256": "bad"},
                   {"size_bytes": True}, {"path": "relative.yaml"},
                   {"path": str(tmp_path / "a,b.yaml")}, {"reviewed_profile": "arbitrary"}):
        with pytest.raises(ValueError):
            replace(template, **fields)

    for templates in ((), (template, template)):
        with pytest.raises(ValueError):
            replace(profile, templates=templates)

    with pytest.raises(ValueError, match="alias"):
        replace(profile, configuration_path=template.path)


def test_MatchNormalizationEvidenceAndReplayWithoutTemplates(tmp_path):
    """Replay uses verified raw stdout and frozen provenance, without rereading tool files."""

    adapter, report = Report(tmp_path)
    (tmp_path / "reviewed-get.yaml").unlink()
    normalized = adapter.NormalizeReport(report)
    finding = normalized.findings[0]

    assert normalized.report is report, "Raw evidence and terminal execution must remain exact."
    assert finding.kind == "web.template-match", "Nuclei matches use the existing generic SDK."
    assert finding.subject_reference == "target:owned", "Target references must remain opaque."
    assert finding.attributes["template_review"] == "review:source-controlled-synthetic", (
        "Normalized findings retain the trusted review/source/version attribution."
    )
    assert finding.attributes["classification"]["cwe-id"] == ("CWE-200",), (
        "Provider classifications remain metadata for a later Finding consumer."
    )
    assert normalized.observations[0].attributes["reported_matches"] == 1, (
        "Run metadata records actual parser output, never inferred target safety."
    )
    assert normalized.observations[0].attributes["template_provenance"][0]["sha256"], (
        "The enclosing run preserves all exact selected template provenance."
    )


@pytest.mark.parametrize("state", [ExecutionState.FAILED, ExecutionState.TIMED_OUT,
                                  ExecutionState.CANCELLED])
def test_FailedExecutionRemainsIncompleteWithValidMatches(tmp_path, state):
    """Useful partial matches never turn an unsuccessful provider run into success."""

    adapter, report = Report(tmp_path, state=state)
    normalized = adapter.NormalizeReport(report)

    assert normalized.report.execution.state is state, "Executor truth must remain unchanged."
    assert normalized.findings[0].attributes["complete"] is False, (
        "A valid match from incomplete execution must keep its incomplete attribution."
    )
    assert normalized.observations[0].attributes["complete"] is False, (
        "Every unsuccessful terminal state remains an incomplete run."
    )


def test_InvalidSuccessfulAndPartialFailedJsonl(tmp_path):
    """Successful malformed reports fail; failed truncated reports yield diagnostics only."""

    adapter, report = Report(tmp_path, raw=JSONL + b'{"template-id":')

    with pytest.raises(NucleiReportError, match="invalid"):
        adapter.NormalizeReport(report)

    normalized = adapter.NormalizeReport(replace(report,
        execution=AdapterExecution(ExecutionState.TIMED_OUT, None, 10)))

    assert not normalized.findings, "Truncated provider objects must not yield trusted findings."
    assert normalized.observations[0].kind == "nuclei.parse", (
        "Explicit diagnostic metadata preserves partial-output failure."
    )


@pytest.mark.parametrize("fields", [
    {"template-id": "unreviewed"}, {"type": "code"}, {"matcher-status": False},
    {"matcher-status": "false"}, {"host": "http://127.0.0.2:8080/"}, {"ip": "127.0.0.2"},
    {"matched-at": "http://127.0.0.2:8080/"}, {"matched-at": "http://127.0.0.1:8080/other"},
    {"template-path": "/unreviewed/template.yaml"}, {"info": {}},
    {"info": {"name": "bad", "severity": "invalid"}}, {"matcher-name": []},
])
def test_RejectUnboundProviderMatch(tmp_path, fields):
    """Matches require reviewed identities and the exact authorized URL, not just host scope."""

    record = json.loads(JSONL)
    record.update(fields)
    adapter, report = Report(tmp_path, raw=json.dumps(record).encode("utf-8"))

    with pytest.raises(NucleiReportError):
        adapter.NormalizeReport(report)


def test_EvidenceDigestSizeRoleAndInvocationBinding(tmp_path):
    """No replaced evidence or provider invocation can inherit trusted parser output."""

    adapter, report = Report(tmp_path)

    for reference in (replace(report.evidence[0], sha256="0" * 64),
                      replace(report.evidence[0], size_bytes=len(JSONL) + 1),
                      replace(report.evidence[0], size_bytes=nuclei.NUCLEI_JSONL_MAX_BYTES + 1)):
        with pytest.raises(NucleiReportError):
            adapter.NormalizeReport(replace(report, evidence=(reference,)))

    for evidence in ((), (replace(report.evidence[0], role="stderr"),),
                     (report.evidence[0], replace(report.evidence[0], locator="fixture/other"))):
        with pytest.raises(NucleiReportError, match="one stdout"):
            adapter.NormalizeReport(replace(report, evidence=evidence))

    with pytest.raises(NucleiReportError, match="invocation"):
        adapter.NormalizeReport(replace(report, invocation=replace(report.invocation,
            provider_version="3.5.0")))


@pytest.mark.parametrize("raw", [
    b"[]", b'{"same":1,"same":2}', b'{"number":NaN}', b'{"number":1e999}', b"\xff",
    b"\n", b'[{"nested":true}]', b'{"unclosed":',
    b'{"number":' + b'9' * 5000 + b'}',
])
def test_RejectMalformedJsonl(raw):
    """Strict JSON rejects ambiguous/non-finite data and invalid UTF-8 objects."""

    with pytest.raises(NucleiReportError):
        ParseJsonl(raw)


def test_EmptyMatchesAndParserResourceBudgets(tmp_path, monkeypatch):
    """No matches are honest empty output, while every parser resource budget fails closed."""

    adapter, report = Report(tmp_path, raw=b"")
    normalized = adapter.NormalizeReport(report)

    assert not normalized.findings, "Empty JSONL must not fabricate vulnerability findings."
    assert normalized.observations[0].attributes["reported_matches"] == 0, (
        "A zero count records matches only, never complete coverage of all selected templates."
    )

    with pytest.raises(NucleiReportError, match="structural"):
        ParseJsonl(b'{"nested":' + b'[' * 20 + b'0' + b']' * 20 + b'}')

    with pytest.raises(NucleiReportError, match="structural"):
        ParseJsonl(json.dumps({"nodes": [0] * 4097}).encode("utf-8"))

    monkeypatch.setattr(nuclei, "NUCLEI_JSONL_MAX_LINE_BYTES", 3)

    with pytest.raises(NucleiReportError, match="oversized"):
        ParseJsonl(b'{"a":1}')

    monkeypatch.setattr(nuclei, "NUCLEI_JSONL_MAX_RECORDS", 1)

    with pytest.raises(NucleiReportError, match="record budget"):
        ParseJsonl(b"{}\n{}\n")

    monkeypatch.setattr(nuclei, "NUCLEI_JSONL_MAX_BYTES", 1)

    with pytest.raises(NucleiReportError, match="byte budget"):
        ParseJsonl(b"{}")


def test_UnavailableAndFailedVersionProbe(tmp_path, monkeypatch):
    """Optional missing tools and failed local probes remain explicit health states."""

    profile = Profile(tmp_path)
    adapter = NucleiAdapter(lambda reference: JSONL, profile)
    monkeypatch.setattr(nuclei.shutil, "which", lambda executable: None)

    assert adapter.CheckHealth().state is AdapterHealthState.UNAVAILABLE, (
        "Absence of an optional provider must not become health success."
    )

    monkeypatch.setattr(nuclei.shutil, "which", lambda executable: "/owned/nuclei")

    def CannotStart(*arguments, **keywords):
        """Model a bounded local executable launch failure."""

        raise OSError("owned launch failure")

    monkeypatch.setattr(nuclei.subprocess, "Popen", CannotStart)

    assert adapter.CheckHealth().state is AdapterHealthState.UNAVAILABLE, (
        "An unavailable executable must stay unavailable when its path was found."
    )


@pytest.mark.skipif(os.name == "nt", reason="owned executable fixture uses a POSIX shebang")
@pytest.mark.parametrize("mode", ["good", "invalid", "failed", "timeout", "overflow"])
def test_RealBoundedHealthCapture(tmp_path, monkeypatch, mode):
    """Owned version-only processes exercise actual finite time/capture failure behavior."""

    import sys

    profile = Profile(tmp_path)
    executable = tmp_path / "owned-version"
    scripts = {
        "good": 'print("[INF] Nuclei Engine Version: v3.4.10-synthetic")',
        "invalid": 'print("unrecognized version")',
        "failed": 'raise SystemExit(7)',
        "timeout": 'import time; time.sleep(2)',
        "overflow": 'print("X" * 20000)',
    }
    executable.write_text(f"#!{sys.executable}\n" + scripts[mode] + "\n", encoding="utf-8")
    executable.chmod(0o700)
    adapter = NucleiAdapter(lambda reference: JSONL, profile, str(executable))
    monkeypatch.setattr(nuclei, "NUCLEI_HEALTH_TIMEOUT_SECONDS", 0.1)
    health = adapter.CheckHealth()

    if mode == "good":
        assert health.state is AdapterHealthState.AVAILABLE, "Owned version must be observed."
        assert health.provider_version == "3.4.10-synthetic", (
            "Fixture version attribution cannot pretend a real Nuclei installation."
        )

    else:
        assert health.state is AdapterHealthState.DEGRADED, (
            "Every failed/unbounded version probe must remain degraded."
        )
