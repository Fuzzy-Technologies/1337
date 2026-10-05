# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Finite Nmap arguments, bounded health, and evidence-backed XML failures."""

from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import replace

import pytest

from fuzzy1337.adapters import (
    AdapterExecution,
    AdapterHealthState,
    AdapterReport,
    AdapterRequest,
    EvidenceReference,
    ExecutionState,
    ImpactLevel,
    SerializeContract,
    ToolAdapter,
    nmap,
)
from fuzzy1337.adapters.nmap import NmapAdapter, NmapReportError, ParseXml

XML = b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///nonexistent/never-opened.xsl" type="text/xsl"?>
<nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05">
  <host><status state="up" reason="user-set"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports><extraports state="closed" count="1"/>
      <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
        <service name="http" product="Synthetic HTTP" version="1" method="probed" conf="10">
          <cpe>cpe:/a:example:synthetic:1</cpe>
        </service>
      </port>
    </ports>
  </host>
  <runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>'''


def Request(**parameters):
    """Build an explicit synthetic request without authorizing any scan.

    Args:
        parameters: Overrides for finite request parameters.

    Returns:
        SDK request whose target reference stays opaque.
    """

    values = {"address": "127.0.0.1", "ports": [443, 80], "timeout_seconds": 10}
    values.update(parameters)

    return AdapterRequest("network.tcp-connect", "target:synthetic", ImpactLevel.STANDARD, values)


def Report(raw=XML, state=ExecutionState.SUCCEEDED):
    """Create an attributed byte fixture through the unchanged SDK contract.

    Args:
        raw: Exact synthetic XML bytes.
        state: Terminal executor state to preserve.

    Returns:
        Adapter and matching immutable report.
    """

    reference = EvidenceReference("stdout", "fixture/nmap.xml", hashlib.sha256(raw).hexdigest(),
                                  "application/xml", len(raw))
    adapter = NmapAdapter(lambda item: raw, provider_version="7.95")
    exit_code = 0 if state is ExecutionState.SUCCEEDED else 7
    report = AdapterReport(adapter.PrepareInvocation(Request()),
                           AdapterExecution(state, exit_code, 0.25), (reference,))

    return adapter, report


def test_DeterministicFiniteArgumentsAndProtocol():
    """Preparation is side-effect free and retains opaque references and exact bounds."""

    adapter = NmapAdapter(lambda reference: XML)
    invocation = adapter.PrepareInvocation(Request())

    assert isinstance(adapter, ToolAdapter), "Nmap must implement the existing runtime protocol."
    assert adapter.Descriptor.capabilities == (
        "network.tcp-connect", "network.service-discovery"
    ), (
        "Only the finite network capability profiles may be advertised."
    )
    assert invocation.argv == ("nmap", "--unprivileged", "-n", "-Pn", "-sT", "-p", "80,443",
                               "--host-timeout", "10s", "-oX", "-", "127.0.0.1"), (
        "Exact sorted argv must not introduce shell, DNS, scripts, or implicit port ranges."
    )
    assert invocation.request.target_reference == "target:synthetic", (
        "Opaque object references must not be interpreted as network addresses."
    )
    assert invocation.timeout_seconds == 10, "Executor timeout must remain explicit."


def test_Ipv6ServiceProfileAndExplicitVersion():
    """The service profile opts into light version probes and IPv6 explicitly."""

    adapter = NmapAdapter(lambda reference: XML, "/owned/nmap", "7.95")
    request = replace(Request(address="2001:0db8::1"), capability="network.service-discovery")
    invocation = adapter.PrepareInvocation(request)

    assert invocation.argv == ("/owned/nmap", "--unprivileged", "-n", "-Pn", "-sT", "-sV",
                               "--version-light", "-p", "80,443", "--host-timeout", "10s",
                               "-oX", "-", "-6", "2001:db8::1"), (
        "Service discovery must have a deterministic independently reviewable profile."
    )
    assert invocation.provider_version == "7.95", "Earlier observed versions must be explicit."


@pytest.mark.parametrize("parameters", [
    {"address": "host.invalid"}, {"address": "127.0.0.1/24"}, {"address": "--script=all"},
    {"address": "127.0.0.1;id"}, {"address": "fe80::1%eth0"}, {"address": 123},
    {"address": "0.0.0.0"}, {"address": "224.0.0.1"}, {"ports": []},
    {"ports": [True]}, {"ports": [0]}, {"ports": [65536]}, {"ports": ["80"]},
    {"ports": [80, 80]}, {"ports": list(range(1, 1026))}, {"ports": "80-90"},
    {"timeout_seconds": 0}, {"timeout_seconds": True}, {"timeout_seconds": 3601},
    {"timeout_seconds": 1.5}, {"argv": ["-A"]},
])
def test_RejectUnsafeAndUnboundedParameters(parameters):
    """Reject flag injection, DNS, address expansion, and missing finite bounds.

    Args:
        parameters: One invalid finite-profile parameter override.
    """

    with pytest.raises(ValueError):
        NmapAdapter(lambda reference: XML).PrepareInvocation(Request(**parameters))


@pytest.mark.parametrize("change", [
    {"impact": ImpactLevel.PASSIVE}, {"impact": ImpactLevel.SAFE},
    {"impact": ImpactLevel.ACTIVE}, {"capability": "network.arbitrary"},
    {"credential_references": ("credential:opaque",)},
    {"parameters": {"address": "127.0.0.1", "ports": [80]}},
])
def test_RejectUnsupportedRequestContracts(change):
    """Finite active profiles cannot mislabel impact or accept unimplemented credentials.

    Args:
        change: Invalid request-field replacement.
    """

    with pytest.raises(ValueError):
        NmapAdapter(lambda reference: XML).PrepareInvocation(replace(Request(), **change))


def test_NormalizedEvidenceAndObjectsRemainSeparate():
    """XML facts retain original execution and produce proposals without vulnerability claims."""

    adapter, report = Report()
    result = adapter.NormalizeReport(report)

    assert result.report is report, "Normalization must preserve the exact source report."
    assert result.findings == (), "Open ports and service names are not vulnerability findings."
    assert tuple(item.object_kind for item in result.object_enrichments) == (
        "host", "port", "service"
    ), "The existing object envelopes must represent host, port, and service facts."
    assert tuple(item.relation_kind for item in result.relation_enrichments) == (
        "has-port", "hosts-service"
    ), "Port and service relations must retain their explicit provider references."
    assert result.object_enrichments[1].object_reference == "target:synthetic:tcp:80", (
        "Provider references must be deterministic, independent from SOM authority."
    )
    assert result.object_enrichments[2].attributes["cpe"] == ("cpe:/a:example:synthetic:1",), (
        "Service details and CPE must remain provider-attributed metadata."
    )
    assert result.object_enrichments[0].attributes["extraports"][0]["count"] == "1", (
        "Grouped omitted ports must stay grouped; individual states cannot be invented."
    )
    assert SerializeContract(result) == SerializeContract(adapter.NormalizeReport(report)), (
        "Normalization must serialize deterministically."
    )


@pytest.mark.parametrize("state", [ExecutionState.FAILED, ExecutionState.TIMED_OUT,
                                   ExecutionState.CANCELLED])
def test_FailedExecutionCannotBecomeSuccessfulNormalization(state):
    """Even complete XML cannot replace failed, timed-out, or cancelled executor facts.

    Args:
        state: Original unsuccessful terminal executor state.
    """

    adapter, report = Report(state=state)
    result = adapter.NormalizeReport(report)

    assert result.report.execution.state is state, "Normalized XML must not fabricate success."
    assert result.observations[0].attributes["execution_state"] == state.value, (
        "The XML completion observation must include the original terminal execution state."
    )


@pytest.mark.parametrize("raw", [b"", b"<nmaprun scanner='nmap'><host>"])
def test_FailedPartialOutputIsAnExplicitDiagnostic(raw):
    """Partial failed stdout preserves evidence and reports no guessed host or port facts.

    Args:
        raw: Incomplete or empty synthetic failed output.
    """

    adapter, report = Report(raw, ExecutionState.TIMED_OUT)
    result = adapter.NormalizeReport(report)

    assert result.report is report, "Partial parsing must retain the complete execution envelope."
    assert result.object_enrichments == (), "Incomplete XML must not fabricate model objects."
    assert result.observations[0].attributes["complete"] is False, (
        "Partial parsing must have an explicit incomplete diagnostic."
    )


@pytest.mark.parametrize("raw", [
    b"", b"<nmaprun", b"\xff", b"<nmaprun scanner='other'/>",
    b"<wrong scanner='nmap'/>",
    b'<!DOCTYPE nmaprun SYSTEM "file:///etc/passwd"><nmaprun scanner="nmap"/>',
    b'<!DOCTYPE nmaprun [<!ENTITY x "payload">]><nmaprun scanner="nmap">&x;</nmaprun>',
    b'<!ENTITY x "payload"><nmaprun scanner="nmap"/>',
    b'<?xml version="1.0" encoding="utf-16"?><nmaprun scanner="nmap"/>',
    b'<nmaprun scanner="nmap"><![CDATA[payload]]></nmaprun>',
])
def test_RejectMalformedAndActiveXmlDeclarations(raw):
    """Reject malformed, non-UTF-8, and active declarations before observations exist.

    Args:
        raw: Malformed or unsafe synthetic XML payload.
    """

    adapter, report = Report(raw)

    with pytest.raises(NmapReportError):
        adapter.NormalizeReport(report)


def test_IndependentXmlByteElementAndDepthBudgets(monkeypatch):
    """Byte and streaming structural budgets prevent oversized or pathological trees.

    Args:
        monkeypatch: Pytest scoped configuration replacement.
    """

    monkeypatch.setattr(nmap, "NMAP_XML_MAX_BYTES", 16)

    with pytest.raises(NmapReportError, match="byte budget"):
        ParseXml(XML)

    adapter, report = Report()

    with pytest.raises(NmapReportError, match="byte budget"):
        adapter.NormalizeReport(report)

    monkeypatch.setattr(nmap, "NMAP_XML_MAX_BYTES", 4096)
    monkeypatch.setattr(nmap, "NMAP_XML_MAX_ELEMENTS", 2)

    with pytest.raises(NmapReportError, match="structural budget"):
        ParseXml(b'<nmaprun scanner="nmap"><a/><b/></nmaprun>')

    monkeypatch.setattr(nmap, "NMAP_XML_MAX_ELEMENTS", 100)
    monkeypatch.setattr(nmap, "NMAP_XML_MAX_DEPTH", 2)

    with pytest.raises(NmapReportError, match="structural budget"):
        ParseXml(b'<nmaprun scanner="nmap"><a><b/></a></nmaprun>')


@pytest.mark.parametrize("old,new", [
    (b'exit="success"', b'exit="error"'),
    (b'<status state="up" reason="user-set"/>', b''),
    (b'state="up"', b'state="invented"'),
    (b'addr="127.0.0.1"', b'addr="127.0.0.2"'),
    (b'addr="127.0.0.1"', b'addr="host.invalid"'),
    (b'addrtype="ipv4"', b'addrtype="ipv6"'),
    (b'portid="80"', b'portid="81"'),
    (b'portid="80"', b'portid="invalid"'),
    (b'protocol="tcp"', b'protocol="udp"'),
    (b'<state state="open" reason="syn-ack"/>', b''),
    (b'state="open"', b'state="invented"'),
])
def test_RejectInconsistentXmlFacts(old, new):
    """Reported completion, addresses, and ports must match the approved request.

    Args:
        old: Existing XML fragment to replace.
        new: Inconsistent replacement XML fragment.
    """

    adapter, report = Report(XML.replace(old, new))

    with pytest.raises(NmapReportError):
        adapter.NormalizeReport(report)


def test_RejectDuplicateHostAndPortFacts():
    """Repeated object elements are ambiguous and cannot silently overwrite observations."""

    port = b'<port protocol="tcp" portid="80"><state state="open"/></port>'
    duplicate_port = XML.replace(b"</ports>", port + b"</ports>")
    duplicate_host = XML.replace(b"</host>", b"</host><host/>")

    for raw in (duplicate_port, duplicate_host):
        adapter, report = Report(raw)

        with pytest.raises(NmapReportError):
            adapter.NormalizeReport(report)


def test_EmptyHostAndNoServiceDoNotInventObjects():
    """No reported hosts or service details must remain absent after normalization."""

    adapter, report = Report(b'<nmaprun scanner="nmap"><runstats><finished exit="success"/>'
                             b'</runstats></nmaprun>')

    assert adapter.NormalizeReport(report).object_enrichments == (), (
        "A completed empty scan must not fabricate any host or port."
    )
    without_service = XML.replace(XML[XML.index(b"<service"):XML.index(b"</service>") + 10], b"")
    adapter, report = Report(without_service)

    assert len(adapter.NormalizeReport(report).object_enrichments) == 2, (
        "Missing service details must leave exactly the reported host and port."
    )


def test_NormalizationCanonicalizesIpv6AndIgnoresMacMetadata():
    """Equivalent literal IP spelling is canonicalized offline without resolving names."""

    raw = XML.replace(b'addr="127.0.0.1" addrtype="ipv4"',
        b'addr="2001:0db8:0000:0000:0000:0000:0000:0001" addrtype="ipv6"')
    raw = raw.replace(b"<ports>", b'<address addr="00:00:00:00:00:00" addrtype="mac"/><ports>')
    adapter, report = Report(raw)
    invocation = adapter.PrepareInvocation(Request(address="2001:db8::1"))
    result = adapter.NormalizeReport(replace(report, invocation=invocation))

    assert result.object_enrichments[0].attributes["address"] == "2001:db8::1", (
        "Host IP identity must use the approved canonical literal, never arbitrary MAC metadata."
    )


def test_RejectEvidenceAndInvocationMismatch():
    """Evidence integrity and exact invocation matching are checked before parsing."""

    adapter, report = Report()
    bad_invocations = (replace(report.invocation, argv=("nmap", "-A")),
                       replace(report.invocation, timeout_seconds=11),
                       replace(report.invocation, adapter_id="other.adapter"))

    for invocation in bad_invocations:
        with pytest.raises(NmapReportError, match="invocation"):
            adapter.NormalizeReport(replace(report, invocation=invocation))

    with pytest.raises(NmapReportError, match="exactly one stdout"):
        adapter.NormalizeReport(replace(report, evidence=()))

    other_reference = replace(report.evidence[0], locator="fixture/other.xml")

    with pytest.raises(NmapReportError, match="exactly one stdout"):
        adapter.NormalizeReport(replace(report, evidence=(*report.evidence, other_reference)))

    wrong_digest = replace(report.evidence[0], sha256="0" * 64)

    with pytest.raises(NmapReportError, match="evidence reference"):
        adapter.NormalizeReport(replace(report, evidence=(wrong_digest,)))

    wrong_length = replace(report.evidence[0], size_bytes=len(XML) - 1)

    with pytest.raises(NmapReportError, match="evidence reference"):
        adapter.NormalizeReport(replace(report, evidence=(wrong_length,)))


@pytest.mark.parametrize("executable,version", [("", None), ("nmap\nother", None), ("nmap", "")])
def test_RejectInvalidConstructionMetadata(executable, version):
    """Operator metadata must follow the SDK single-line text boundary.

    Args:
        executable: Invalid operator executable metadata.
        version: Optional invalid earlier version metadata.
    """

    with pytest.raises(ValueError):
        NmapAdapter(lambda reference: XML, executable, version)


def test_MissingHealthDoesNotClaimAvailability(monkeypatch):
    """No installed optional executable must produce explicit unavailable health.

    Args:
        monkeypatch: Pytest scoped tool lookup replacement.
    """

    monkeypatch.setattr(nmap.shutil, "which", lambda executable: None)

    health = NmapAdapter(lambda reference: XML).CheckHealth()

    assert health.state is AdapterHealthState.UNAVAILABLE, (
        "Optional tool absence must not become healthy availability."
    )


def test_HealthLaunchFailureIsUnavailable(monkeypatch):
    """An installed but unlaunchable executable is distinct from an observed healthy tool.

    Args:
        monkeypatch: Pytest scoped lookup and launch replacements.
    """

    def FailLaunch(*args, **kwargs):
        """Model an operator-selected binary that cannot be launched.

        Args:
            args: Ignored subprocess positional metadata.
            kwargs: Ignored subprocess keyword metadata.

        Raises:
            OSError: Deterministic synthetic launch failure.
        """

        raise OSError("synthetic launch failure")

    monkeypatch.setattr(nmap.shutil, "which", lambda executable: "/owned/nmap")
    monkeypatch.setattr(nmap.subprocess, "Popen", FailLaunch)

    health = NmapAdapter(lambda reference: XML).CheckHealth()

    assert health.state is AdapterHealthState.UNAVAILABLE, (
        "Launch failure must remain unavailable."
    )


@pytest.mark.parametrize("payload,exit_code,timed_out,expected,failure", [
    (b"Nmap version 7.95 ( https://nmap.org )\n", 0, False, AdapterHealthState.AVAILABLE, None),
    (b"Nmap version 7.95\n", 7, False, AdapterHealthState.DEGRADED, None),
    (b"unrecognized provider output\n", 0, False, AdapterHealthState.DEGRADED, None),
    (b"", 0, True, AdapterHealthState.DEGRADED, None),
    (b"x" * (nmap.NMAP_HEALTH_MAX_BYTES + 1), 0, False, AdapterHealthState.DEGRADED, None),
    (b"", 0, False, AdapterHealthState.DEGRADED, "read"),
    (b"", 0, False, AdapterHealthState.DEGRADED, "closed"),
    (b"", 0, True, AdapterHealthState.DEGRADED, "kill-race"),
])
def test_HealthProbePreservesVersionFailureAndResourceBudgets(
    monkeypatch, payload, exit_code, timed_out, expected, failure,
):
    """Exercise portable bounded pipe capture and truthful health classification.

    Args:
        monkeypatch: Pytest scoped process and pipe replacements.
        payload: Exact synthetic version stdout.
        exit_code: Synthetic process terminal code.
        timed_out: Whether the first bounded wait must time out.
        expected: Required explicit SDK health state.
        failure: Optional deterministic pipe-close/read or kill/exit race.
    """

    # A tiny portable real pipe models process output; large data is read from a bounded buffer.
    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    remaining = bytearray(payload)
    calls = []

    class OwnedProcess:
        """Controlled process facts with a real closable captured pipe."""

        def __init__(self):
            """Initialize exact synthetic terminal facts and an owned descriptor."""

            self.stdout = os.fdopen(read_fd, "rb", buffering=0)
            self.returncode = exit_code
            self.first_wait = True

        def wait(self, timeout=None):
            """Model the fixed bounded wait and subsequent process reaping.

            Args:
                timeout: Explicit bounded timeout from the version probe.

            Returns:
                Original or killed synthetic terminal exit code.

            Raises:
                subprocess.TimeoutExpired: Requested deterministic first-wait timeout.
            """

            calls.append(timeout)

            if self.first_wait and timed_out:
                self.first_wait = False

                raise subprocess.TimeoutExpired("owned-fixture", timeout)

            return self.returncode

        def kill(self):
            """Record terminal resource cancellation or a deterministic exit race.

            Raises:
                ProcessLookupError: The synthetic child exited before kill.
            """

            self.returncode = -9

            if failure == "kill-race":
                raise ProcessLookupError("synthetic process exited before kill")

    process = OwnedProcess()

    def ReadPipe(fd, size):
        """Return no more than the requested bounded slice from synthetic pipe data.

        Args:
            fd: Owned captured pipe descriptor.
            size: Maximum requested byte count.

        Returns:
            Bounded synthetic bytes or EOF.

        Raises:
            OSError: A deterministic captured-pipe read failure.
            ValueError: A deterministic closed-pipe race.
        """

        assert fd == read_fd, "Only the explicitly owned version pipe may be read."

        if failure == "read":
            raise OSError("synthetic pipe read failure")

        if failure == "closed":
            raise ValueError("synthetic closed pipe")

        result = bytes(remaining[:size])
        del remaining[:size]

        return result

    def Launch(argv, **options):
        """Prove the health-only executable argv and shell-free process options.

        Args:
            argv: Fixed executable plus --version command.
            options: Explicit subprocess capture and shell controls.

        Returns:
            Controlled synthetic process facts.
        """

        assert argv == ("/owned/nmap", "--version"), "Health must never include a target."
        assert options["shell"] is False, "The version probe must not invoke a shell."

        return process

    monkeypatch.setattr(nmap.shutil, "which", lambda executable: "/owned/nmap")
    monkeypatch.setattr(nmap.subprocess, "Popen", Launch)
    monkeypatch.setattr(nmap.os, "read", ReadPipe)
    health = NmapAdapter(lambda reference: XML).CheckHealth()

    assert health.state is expected, "Health classification must preserve observed failure."
    assert calls[0] == 3, "The local version command must have a fixed three-second deadline."
    assert nmap.NMAP_HEALTH_MAX_BYTES == 16 * 1024, "Health capture must stay limited to 16 KiB."
    expected_version = "7.95" if expected is AdapterHealthState.AVAILABLE else None

    assert health.provider_version == expected_version, (
        "Unhealthy probes must not supply a trusted provider version."
    )
