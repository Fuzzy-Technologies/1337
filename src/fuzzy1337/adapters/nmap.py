# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Optional Nmap preparation and evidence normalization without scan authority."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import shutil
import subprocess
import threading
from collections.abc import Callable, Iterator
from typing import cast
from xml.etree import ElementTree

from fuzzy1337.adapters import (
    AdapterDescriptor,
    AdapterHealth,
    AdapterHealthState,
    AdapterInvocation,
    AdapterReport,
    AdapterRequest,
    AdapterResult,
    EvidenceReference,
    ExecutionState,
    ImpactLevel,
    NormalizedObservation,
    ObjectEnrichment,
    RelationEnrichment,
)
from fuzzy1337.adapters.contracts import RequireText

NMAP_ADAPTER_VERSION = "1"
NMAP_HEALTH_TIMEOUT_SECONDS = 3
NMAP_HEALTH_MAX_BYTES = 16 * 1024
NMAP_XML_MAX_BYTES = 4 * 1024 * 1024
NMAP_XML_MAX_ELEMENTS = 65536
NMAP_XML_MAX_DEPTH = 32
NMAP_MAX_PORTS = 1024
NMAP_MAX_TIMEOUT_SECONDS = 3600

__all__ = [
    "NMAP_ADAPTER_VERSION", "NMAP_HEALTH_TIMEOUT_SECONDS", "NMAP_HEALTH_MAX_BYTES",
    "NMAP_XML_MAX_BYTES", "NMAP_XML_MAX_ELEMENTS", "NMAP_XML_MAX_DEPTH",
    "NMAP_MAX_PORTS", "NMAP_MAX_TIMEOUT_SECONDS", "NmapAdapter", "NmapReportError",
]

_DESCRIPTOR = AdapterDescriptor(
    "native.nmap", "Nmap", NMAP_ADAPTER_VERSION,
    ("network.tcp-connect", "network.service-discovery"), ImpactLevel.STANDARD,
)
_VERSION_PATTERN = re.compile(r"^Nmap version ([0-9][0-9A-Za-z.+_-]*)\b", re.MULTILINE)
_INERT_DOCTYPE = re.compile(r"<!DOCTYPE\s+nmaprun\s*>")
_PORT_STATES = frozenset({"open", "closed", "filtered", "unfiltered", "open|filtered",
                          "closed|filtered"})


class NmapReportError(ValueError):
    """A raw Nmap report cannot safely produce normalized observations."""


def ValidateParameters(request: AdapterRequest) -> tuple[str, tuple[int, ...], int]:
    """Validate a finite caller-approved literal target and explicit TCP port set.

    Args:
        request: Approved capability and non-secret parameters.

    Returns:
        Canonical literal address, sorted ports, and bounded timeout.

    Raises:
        ValueError: Capability, impact, credentials, or parameters are unsupported.
    """

    if not _DESCRIPTOR.Supports(request.capability) or request.impact is not ImpactLevel.STANDARD:
        raise ValueError("Nmap requires a supported capability with STANDARD impact")

    if request.credential_references:
        raise ValueError("the initial Nmap profiles do not accept credentials")

    if set(request.parameters) != {"address", "ports", "timeout_seconds"}:
        raise ValueError("Nmap parameters must be exactly address, ports, timeout_seconds")

    address = request.parameters["address"]

    if not isinstance(address, str) or "%" in address:
        raise ValueError("Nmap address must be one literal unscoped IP address")

    try:
        parsed_address = ipaddress.ip_address(address)

    except ValueError as error:
        raise ValueError("Nmap address must be one literal IP address") from error

    if parsed_address.is_multicast or parsed_address.is_unspecified:
        raise ValueError("Nmap address must be a unicast non-unspecified address")

    ports = request.parameters["ports"]

    if not isinstance(ports, tuple) or not 1 <= len(ports) <= NMAP_MAX_PORTS:
        raise ValueError("Nmap ports must be a nonempty bounded sequence")

    if any(isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
           for port in ports):
        raise ValueError("Nmap ports must be integers from 1 through 65535")

    if len(set(ports)) != len(ports):
        raise ValueError("Nmap ports must not contain duplicates")

    timeout = request.parameters["timeout_seconds"]

    if isinstance(timeout, bool) or not isinstance(timeout, int) or not (
        1 <= timeout <= NMAP_MAX_TIMEOUT_SECONDS
    ):
        raise ValueError("Nmap timeout_seconds must be an integer from 1 through 3600")

    return str(parsed_address), tuple(sorted(ports)), timeout


def ParseXml(raw: bytes) -> ElementTree.Element:
    """Parse bounded UTF-8 XML without loading DTDs, entities, or stylesheets.

    Args:
        raw: Verified raw stdout bytes, limited independently from executor budgets.

    Returns:
        A bounded Nmap XML tree. No external content is resolved.

    Raises:
        NmapReportError: Encoding, declaration, structure, or resource limits fail.
    """

    if len(raw) > NMAP_XML_MAX_BYTES:
        raise NmapReportError("Nmap XML exceeds the byte budget")

    try:
        text = raw.decode("utf-8-sig")

    except UnicodeDecodeError as error:
        raise NmapReportError("Nmap XML must be UTF-8") from error

    # Nmap emits this inert declaration; every DTD with content or a locator is rejected.
    text = _INERT_DOCTYPE.sub("", text, count=1)

    if "<!" in re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL):
        raise NmapReportError("Nmap XML declarations and entities are not allowed")

    declaration = re.match(r"\s*<\?xml\s+([^?]+)\?>", text)

    if declaration:
        encoding = re.search(r"encoding\s*=\s*['\"]([^'\"]+)['\"]", declaration[1])

        if encoding and encoding[1].lower() not in {"utf-8", "utf8"}:
            raise NmapReportError("Nmap XML must declare UTF-8")

    parser: ElementTree.XMLPullParser[ElementTree.Element] = ElementTree.XMLPullParser(
        events=("start", "end"),
    )
    count = 0
    depth = 0
    root: ElementTree.Element | None = None

    try:
        for offset in range(0, len(text), 4096):
            parser.feed(text[offset:offset + 4096])

            # Only start/end events are configured, excluding namespace event payloads.
            events = cast(Iterator[tuple[str, ElementTree.Element]], parser.read_events())

            for event, element in events:
                if event == "start":
                    root = element if root is None else root
                    count += 1
                    depth += 1

                    if count > NMAP_XML_MAX_ELEMENTS or depth > NMAP_XML_MAX_DEPTH:
                        raise NmapReportError("Nmap XML exceeds the structural budget")

                else:
                    depth -= 1

        parser.close()

    except ElementTree.ParseError as error:
        raise NmapReportError("Nmap XML is malformed or incomplete") from error

    if root is None or root.tag != "nmaprun" or root.get("scanner") != "nmap":
        raise NmapReportError("Nmap XML requires an nmaprun from scanner nmap")

    return root


def ReadVersion(executable: str) -> AdapterHealth:
    """Observe only the local version command under time and capture budgets.

    Args:
        executable: Operator-selected tool executable, never request parameters.

    Returns:
        Available, degraded, or unavailable health without target execution authority.
    """

    resolved = shutil.which(executable)

    if resolved is None:
        return AdapterHealth(_DESCRIPTOR.adapter_id, AdapterHealthState.UNAVAILABLE,
                             detail="Nmap executable is not available")

    output: list[bytes] = []

    try:
        process = subprocess.Popen(
            (resolved, "--version"), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False, bufsize=0,
        )

    except OSError:
        return AdapterHealth(_DESCRIPTOR.adapter_id, AdapterHealthState.UNAVAILABLE,
                             detail="Nmap version probe could not start")

    assert process.stdout is not None, "subprocess.PIPE did not provide its stdout capture handle"
    pipe = process.stdout
    capture_failed = threading.Event()

    def Capture() -> None:
        """Drain at most the capture budget plus one detection byte."""

        remaining = NMAP_HEALTH_MAX_BYTES + 1

        try:
            while remaining:
                chunk = os.read(pipe.fileno(), min(4096, remaining))

                if not chunk:
                    break

                output.append(chunk)
                remaining -= len(chunk)

            if not remaining:
                process.kill()

        except (OSError, ValueError):
            capture_failed.set()

            return

    worker = threading.Thread(target=Capture, daemon=True)
    worker.start()
    timed_out = False

    try:
        process.wait(timeout=NMAP_HEALTH_TIMEOUT_SECONDS)

    except subprocess.TimeoutExpired:
        timed_out = True

        try:
            process.kill()

        except ProcessLookupError:
            pass

        process.wait()

    worker.join(timeout=0.1)
    pipe.close()
    raw = b"".join(output)

    if timed_out or worker.is_alive() or capture_failed.is_set() or (
        len(raw) > NMAP_HEALTH_MAX_BYTES
    ):
        return AdapterHealth(_DESCRIPTOR.adapter_id, AdapterHealthState.DEGRADED,
                             detail="Nmap version probe exceeded a resource budget")

    version = _VERSION_PATTERN.search(raw.decode("utf-8", errors="replace"))

    if process.returncode != 0 or version is None:
        return AdapterHealth(_DESCRIPTOR.adapter_id, AdapterHealthState.DEGRADED,
                             detail="Nmap version probe failed or returned unrecognized output")

    return AdapterHealth(_DESCRIPTOR.adapter_id, AdapterHealthState.AVAILABLE, version[1])


class NmapAdapter:
    """Experimental finite Nmap profiles and immutable evidence interpretations.

    Construction, invocation preparation, and normalization perform no scanning.
    CheckHealth runs only the bounded local --version command. The executable is
    operator-selected and trusted; this adapter does not sandbox malicious binaries.
    """

    def __init__(self, evidence_reader: Callable[[EvidenceReference], bytes],
                 executable: str = "nmap", provider_version: str | None = None) -> None:
        """Bind a verified evidence reader and operator-selected optional tool.

        Args:
            evidence_reader: Usually LocalEvidenceStore.Read; never a path discovery hook.
            executable: Trusted local executable name or absolute path.
            provider_version: Explicit earlier observed version, if known.

        Raises:
            ValueError: Executable or version metadata is invalid.
        """

        RequireText(executable, "Nmap executable")

        if provider_version is not None:
            RequireText(provider_version, "Nmap provider version")

        self._read_evidence = evidence_reader
        self._executable = executable
        self._provider_version = provider_version

    @property
    def Descriptor(self) -> AdapterDescriptor:
        """Return finite capability metadata without loading or invoking Nmap.

        Returns:
            Immutable provider declaration with STANDARD maximum impact.
        """

        return _DESCRIPTOR

    def CheckHealth(self) -> AdapterHealth:
        """Observe local availability and version without granting scan authority.

        Returns:
            Explicit availability and version observation under fixed budgets.
        """

        return ReadVersion(self._executable)

    def PrepareInvocation(self, request: AdapterRequest) -> AdapterInvocation:
        """Prepare deterministic argv for an already approved finite profile.

        Args:
            request: Approved literal address, explicit TCP ports, and timeout.

        Returns:
            Shell-free invocation requiring a separate ExecutionAuthorization.

        Raises:
            ValueError: The request is outside the finite profile contract.
        """

        address, ports, timeout = ValidateParameters(request)
        arguments = [self._executable, "--unprivileged", "-n", "-Pn", "-sT"]

        if request.capability == "network.service-discovery":
            arguments.extend(("-sV", "--version-light"))

        arguments.extend(("-p", ",".join(map(str, ports)), "--host-timeout", f"{timeout}s",
                          "-oX", "-"))

        if ipaddress.ip_address(address).version == 6:
            arguments.append("-6")

        arguments.append(address)

        return AdapterInvocation(_DESCRIPTOR.adapter_id, request, tuple(arguments), timeout,
                                 self._provider_version)

    def NormalizeReport(self, report: AdapterReport) -> AdapterResult:
        """Interpret verified XML without changing terminal execution or raw evidence.

        Args:
            report: Exact invocation, terminal executor facts, and captured evidence.

        Returns:
            Existing SDK envelopes. Failed partial XML yields only a parse diagnostic.

        Raises:
            NmapReportError: Evidence, invocation, successful XML, or target binding fails.
            ValueError: Request metadata fails finite-profile validation.
        """

        expected = self.PrepareInvocation(report.invocation.request)

        if report.invocation.adapter_id != _DESCRIPTOR.adapter_id or (
            report.invocation.argv != expected.argv
            or report.invocation.timeout_seconds != expected.timeout_seconds
        ):
            raise NmapReportError("Nmap report invocation does not match the finite profile")

        references = [item for item in report.evidence if item.role == "stdout"]

        if len(references) != 1:
            raise NmapReportError("Nmap report requires exactly one stdout evidence reference")

        reference = references[0]

        if reference.size_bytes > NMAP_XML_MAX_BYTES:
            raise NmapReportError("Nmap XML exceeds the byte budget")

        raw = self._read_evidence(reference)

        if len(raw) != reference.size_bytes or hashlib.sha256(raw).hexdigest() != reference.sha256:
            raise NmapReportError("Nmap stdout does not match its evidence reference")

        try:
            root = ParseXml(raw)

        except NmapReportError:
            if report.execution.state is ExecutionState.SUCCEEDED:
                raise

            observation = NormalizedObservation(
                "nmap.parse", report.invocation.request.target_reference,
                {"complete": False, "status": "invalid-or-partial"},
            )

            return AdapterResult(report, observations=(observation,))

        return self.NormalizeTree(report, root)

    def NormalizeTree(self, report: AdapterReport, root: ElementTree.Element) -> AdapterResult:
        """Normalize validated host/port/service facts with opaque provider references.

        Args:
            report: Original immutable facts and raw evidence references.
            root: Bounded parsed XML tree.

        Returns:
            SDK observations and enrichment proposals, never persisted SOM objects.

        Raises:
            NmapReportError: Completion, host/address, or port facts are inconsistent.
        """

        address, ports, _ = ValidateParameters(report.invocation.request)
        subject = report.invocation.request.target_reference
        finished = root.find("runstats/finished")
        complete = finished is not None and finished.get("exit") == "success"

        if report.execution.state is ExecutionState.SUCCEEDED and not complete:
            raise NmapReportError("successful Nmap execution requires a successful XML completion")

        observations = [NormalizedObservation("nmap.run", subject, {
            "complete": complete, "xml_version": root.get("version"),
            "xml_output_version": root.get("xmloutputversion"),
            "execution_state": report.execution.state.value,
        })]
        objects: list[ObjectEnrichment] = []
        relations: list[RelationEnrichment] = []
        hosts = root.findall("host")

        if len(hosts) > 1:
            raise NmapReportError("the finite Nmap profile accepts at most one reported host")

        for host in hosts:
            addresses: list[str] = []

            for item in host.findall("address"):
                if item.get("addrtype") not in {"ipv4", "ipv6"}:
                    continue

                try:
                    reported_address = ipaddress.ip_address(item.get("addr", ""))

                except ValueError as error:
                    raise NmapReportError("Nmap host address is not a literal IP") from error

                if item.get("addrtype") != f"ipv{reported_address.version}" or (
                    "%" in str(reported_address)
                ):
                    raise NmapReportError("Nmap host address family is inconsistent")

                addresses.append(str(reported_address))

            if addresses != [address]:
                raise NmapReportError("Nmap host address differs from the approved literal target")

            status = host.find("status")

            if status is None or status.get("state") not in {"up", "down", "unknown", "skipped"}:
                raise NmapReportError("Nmap host status is missing or unsupported")

            host_attributes: dict[str, object] = {"address": address,
                "address_type": f"ipv{ipaddress.ip_address(address).version}",
                "state": status.get("state"), "reason": status.get("reason"),
                "extraports": tuple(dict(item.attrib) for item in host.findall("ports/extraports"))}
            observations.append(NormalizedObservation("network.host", subject, host_attributes))
            objects.append(ObjectEnrichment("host", subject, host_attributes))
            seen: set[int] = set()

            for port in host.findall("ports/port"):
                try:
                    number = int(port.get("portid", ""))

                except ValueError as error:
                    raise NmapReportError("Nmap port number is invalid") from error

                state = port.find("state")

                if port.get("protocol") != "tcp" or number not in ports or number in seen:
                    raise NmapReportError("Nmap port is duplicated or outside the approved TCP set")

                if state is None or state.get("state") not in _PORT_STATES:
                    raise NmapReportError("Nmap port state is missing or unsupported")

                seen.add(number)
                port_reference = f"{subject}:tcp:{number}"
                attributes: dict[str, object] = {"protocol": "tcp", "number": number,
                                               "state": state.get("state"),
                                               "reason": state.get("reason")}
                observations.append(NormalizedObservation(
                    "network.port", port_reference, attributes,
                ))
                objects.append(ObjectEnrichment("port", port_reference, attributes))
                relations.append(RelationEnrichment("has-port", subject, port_reference))
                service = port.find("service")

                if service is not None:
                    service_attributes: dict[str, object] = dict(service.attrib)
                    service_attributes["cpe"] = tuple(item.text for item in service.findall("cpe")
                                                       if item.text)
                    service_reference = f"{port_reference}:service"
                    observations.append(NormalizedObservation("network.service", service_reference,
                                                              service_attributes))
                    objects.append(ObjectEnrichment(
                        "service", service_reference, service_attributes,
                    ))
                    relations.append(RelationEnrichment("hosts-service", port_reference,
                                                        service_reference))

        return AdapterResult(report, tuple(observations), object_enrichments=tuple(objects),
                             relation_enrichments=tuple(relations))
