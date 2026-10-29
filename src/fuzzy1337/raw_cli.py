# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental exact native Nmap arguments within existing finite capability boundaries."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, EvidenceReference, ImpactLevel
from fuzzy1337.adapters.nmap import NMAP_MAX_PORTS, NMAP_MAX_TIMEOUT_SECONDS, NmapAdapter
from fuzzy1337.scope import Target, TargetKind

RAW_NMAP_PROFILE = "raw-nmap.v1"
_SWITCHES = frozenset({"--unprivileged", "-n", "-Pn", "-sT", "-sV", "--version-light", "-6"})
_VALUES = frozenset({"-p", "--host-timeout", "-oX"})
_REQUIRED = frozenset({"--unprivileged", "-n", "-Pn", "-sT", "-p", "--host-timeout", "-oX"})


def ParseNativeNmap(arguments: tuple[str, ...]) -> tuple[str, tuple[int, ...], int, str]:
    """Validate exact native tokens without normalizing their original spelling or order.

    Args:
        arguments: Native tokens after the wrapper delimiter, excluding the executable.

    Returns:
        Canonical literal address, sorted unique ports, timeout and existing capability.

    Raises:
        ValueError: Arguments exceed the supported finite native profile.
    """

    if type(arguments) is not tuple or not 1 <= len(arguments) <= 32 or any(
        type(value) is not str or not value or not value.isascii()
        or any(ord(character) <= 32 or ord(character) == 127 for character in value)
        for value in arguments
    ) or sum(len(value) for value in arguments) > 8192:
        raise ValueError("raw Nmap requires bounded explicit native argument tokens")

    selected: dict[str, str | None] = {}
    targets: list[str] = []
    index = 0

    while index < len(arguments):
        token = arguments[index]

        if token in _SWITCHES or token in _VALUES:
            if token in selected:
                raise ValueError("raw Nmap rejects duplicate options")

            selected[token] = None

            if token in _VALUES:
                index += 1

                if index >= len(arguments):
                    raise ValueError("raw Nmap option requires an explicit value")

                selected[token] = arguments[index]

        elif token.startswith("-"):
            raise ValueError("raw Nmap option is outside the supported profile")

        else:
            targets.append(token)

        index += 1

    if not _REQUIRED <= selected.keys() or len(targets) != 1 or selected["-oX"] != "-":
        raise ValueError("raw Nmap requires one target and its complete unprivileged XML profile")

    address = ipaddress.ip_address(targets[0])

    if str(address) != targets[0] or address.is_multicast or address.is_unspecified or (
        "%" in targets[0] or ("-6" in selected) != (address.version == 6)
    ):
        raise ValueError("raw Nmap requires one canonical unicast literal address and family")

    if ("-sV" in selected) != ("--version-light" in selected):
        raise ValueError("raw Nmap service discovery requires both reviewed service options")

    raw_ports = selected["-p"]

    if not isinstance(raw_ports, str):
        raise ValueError("raw Nmap requires explicit ports")

    parts = raw_ports.split(",")

    if not 1 <= len(parts) <= NMAP_MAX_PORTS or any(
        re.fullmatch(r"[1-9][0-9]{0,4}", part) is None or int(part) > 65535 for part in parts
    ):
        raise ValueError("raw Nmap ports must be unique explicit integers from one through 65535")

    ports = tuple(int(part) for part in parts)

    if len(set(ports)) != len(ports):
        raise ValueError("raw Nmap rejects duplicate ports")

    raw_timeout = selected["--host-timeout"]

    if not isinstance(raw_timeout, str) or re.fullmatch(r"[1-9][0-9]{0,3}s", raw_timeout) is None:
        raise ValueError("raw Nmap host timeout requires explicit whole seconds")

    timeout = int(raw_timeout[:-1])

    if timeout > NMAP_MAX_TIMEOUT_SECONDS:
        raise ValueError("raw Nmap host timeout exceeds the existing adapter bound")

    capability = "network.service-discovery" if "-sV" in selected else "network.tcp-connect"

    return str(address), tuple(sorted(ports)), timeout, capability


@dataclass(frozen=True, slots=True)
class RawNmapSelection:
    """Immutable original native tokens and independently derived finite capability inputs."""

    arguments: tuple[str, ...]
    address: str = field(init=False)
    ports: tuple[int, ...] = field(init=False)
    timeout_seconds: int = field(init=False)
    capability: str = field(init=False)

    def __post_init__(self) -> None:
        """Validate original tokens before deriving any scope or adapter request input."""

        values = ParseNativeNmap(self.arguments)

        for name, value in zip(("address", "ports", "timeout_seconds", "capability"),
            values, strict=True):
            object.__setattr__(self, name, value)

    @property
    def Target(self) -> Target:
        """Return the sole literal IP selected by the original native arguments.

        Returns:
            Typed existing IP target without lookup, contact or scope enrollment.
        """

        return Target(TargetKind.IP, self.address)

    def Request(self) -> AdapterRequest:
        """Bind the existing capability request to the actual native target, ports and bound.

        Returns:
            Existing STANDARD request without credentials or additional privileges.
        """

        return AdapterRequest(self.capability, self.Target.Reference(), ImpactLevel.STANDARD,
            {"address": self.address, "ports": self.ports,
                "timeout_seconds": self.timeout_seconds})


class RawNmapAdapter(NmapAdapter):
    """Retain exact native argv while reusing the existing Nmap validation and XML normalizer."""

    def __init__(self, evidence_reader: Callable[[EvidenceReference], bytes],
        selection: RawNmapSelection, executable: str, provider_version: str | None = None) -> None:
        """Freeze a reviewed native selection and explicitly trusted absolute tool path.

        Args:
            evidence_reader: Existing immutable evidence reader used by the inherited parser.
            selection: Exact validated original native argument selection.
            executable: Explicit trusted absolute Nmap binary, never resolved from native flags.
            provider_version: Earlier observed local Nmap version, if known.
        """

        if type(selection) is not RawNmapSelection or type(executable) is not str or (
            not Path(executable).is_absolute()
        ):
            raise ValueError("raw Nmap requires a typed selection and absolute trusted executable")

        self.selection = selection
        super().__init__(evidence_reader, executable, provider_version)

    def PrepareInvocation(self, request: AdapterRequest) -> AdapterInvocation:
        """Validate derived semantics before retaining the original native invocation verbatim.

        Args:
            request: Exact existing request independently derived from the original tokens.

        Returns:
            Actual native argument order, existing limits and observed provider metadata.
        """

        if request != self.selection.Request():
            raise ValueError("raw Nmap request differs from its original native arguments")

        canonical = super().PrepareInvocation(request)

        return replace(canonical, argv=(self._executable, *self.selection.arguments))


def SelectRawNmap(arguments: Sequence[str]) -> RawNmapSelection:
    """Freeze caller-selected native argument tokens without interpreting a shell string.

    Args:
        arguments: Explicit token sequence from the CLI delimiter or a typed SDK caller.

    Returns:
        Validated immutable selection retaining original argument order.
    """

    if isinstance(arguments, (str, bytes)):
        raise ValueError("raw Nmap selection requires explicit tokens rather than a shell string")

    return RawNmapSelection(tuple(arguments))
