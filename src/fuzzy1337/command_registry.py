# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Central command metadata for the 1337 command-line experience."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CommandDescriptor:
    """Describe one user-facing command without coupling it to an implementation."""

    identifier: str
    summary: str
    usage: str
    aliases: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()

    @property
    def Names(self) -> tuple[str, ...]:
        """Return the canonical identifier followed by its accepted aliases.

        Returns:
            Canonical identifier followed by aliases in declaration order.
        """

        return (self.identifier, *self.aliases)


class CommandRegistry:
    """Resolve and discover command descriptors through one immutable registry."""

    def __init__(self, commands: Iterable[CommandDescriptor]) -> None:
        """Index command descriptors and reject ambiguous names.

        Args:
            commands: Descriptors to index in presentation order.

        Raises:
            ValueError: A normalized name is empty, contains whitespace or is duplicated.
        """

        self._commands = tuple(commands)
        self._by_name: dict[str, CommandDescriptor] = {}

        for descriptor in self._commands:
            for name in descriptor.Names:
                normalized = NormalizeName(name)
                if normalized in self._by_name:
                    raise ValueError(f"Duplicate command name: {name}")

                self._by_name[normalized] = descriptor

    @property
    def Commands(self) -> tuple[CommandDescriptor, ...]:
        """Return descriptors in their declared presentation order.

        Returns:
            Immutable descriptors in presentation order.
        """

        return self._commands

    def Resolve(self, name: str) -> CommandDescriptor | None:
        """Return a command by canonical name or alias without guessing invalid input.

        Args:
            name: Canonical command or alias normalized by trimming and lowercasing.

        Returns:
            Matching descriptor, or None for unknown or invalid input.
        """

        try:
            return self._by_name[NormalizeName(name)]

        except (KeyError, ValueError):
            return None

    def Complete(self, prefix: str) -> tuple[CommandDescriptor, ...]:
        """Return commands whose canonical name or alias starts with ``prefix``.

        Args:
            prefix: Case-insensitive prefix, with empty text selecting all commands.

        Returns:
            Matching descriptors in presentation order, each returned at most once.
        """

        normalized = prefix.strip().lower()
        return tuple(
            descriptor
            for descriptor in self._commands
            if not normalized
            or any(name.lower().startswith(normalized) for name in descriptor.Names)
        )

    def Search(self, query: str) -> tuple[CommandDescriptor, ...]:
        """Return a deterministic text search for future palettes and documentation.

        Args:
            query: Case-insensitive substring of names, summaries or capabilities.

        Returns:
            Name-prefix matches first, then other matches, preserving order within each group.
        """

        normalized = query.strip().lower()
        if not normalized:
            return self._commands

        matches: list[tuple[int, CommandDescriptor]] = []
        for descriptor in self._commands:
            fields = (*descriptor.Names, descriptor.summary, *descriptor.capabilities)
            haystack = " ".join(fields).lower()
            if normalized in haystack:
                rank = (
                    0
                    if any(name.lower().startswith(normalized) for name in descriptor.Names)
                    else 1
                )
                matches.append((rank, descriptor))

        return tuple(descriptor for _, descriptor in sorted(matches, key=lambda match: match[0]))


def NormalizeName(name: str) -> str:
    """Normalize an index key while rejecting empty or multi-token names.

    Args:
        name: Index key to strip and lowercase.

    Returns:
        Normalized single-token name.

    Raises:
        ValueError: The normalized name is empty or contains whitespace.
    """

    normalized = name.strip().lower()
    if not normalized or any(character.isspace() for character in normalized):
        raise ValueError("Command names must be non-empty single tokens")

    return normalized


COMMAND_REGISTRY = CommandRegistry(
    (
        CommandDescriptor(
            identifier="doctor",
            summary="Diagnose the local 1337 runtime and optional lab prerequisites.",
            usage="1337 doctor",
            capabilities=("core.diagnostics",),
        ),
        CommandDescriptor(
            identifier="help",
            summary="Show the currently available 1337 commands.",
            usage="1337 help",
            capabilities=("core.help",),
        ),
        CommandDescriptor(
            identifier="version",
            summary="Show the installed 1337 distribution version.",
            usage="1337 --version",
            aliases=("--version",),
            capabilities=("core.version",),
        ),
        CommandDescriptor(
            identifier="shell",
            summary="Start the interactive 1337 workbench shell.",
            usage="1337 shell",
            capabilities=("workbench.interactive",),
        ),
        CommandDescriptor(
            identifier="update",
            summary="Inspect local component health and manual update boundaries.",
            usage="1337 update [--json]",
            capabilities=("core.component-health", "core.update-inspection"),
        ),
        CommandDescriptor(
            identifier="workspace",
            summary="Create or reopen a durable workspace and verify retained evidence.",
            usage="1337 workspace <create|open>",
            capabilities=("workbench.workspace",),
        ),
        CommandDescriptor(
            identifier="scope",
            summary="Record explicit target rules and operator consent.",
            usage="1337 scope create <workspace>",
            capabilities=("workbench.scope",),
        ),
        CommandDescriptor(
            identifier="scan",
            summary="Run governed endpoint or closed synthetic image/configuration workflows.",
            usage="1337 scan <quick|nuclei|image|config> <workspace>",
            capabilities=("http.endpoint-discovery", "image.archive-vulnerabilities",
                          "config.dockerfile-misconfigurations",
                          "config.kubernetes-misconfigurations"),
        ),
        CommandDescriptor(
            identifier="report",
            summary="Export a verified saved model to bounded JSON, SARIF, HTML or JUnit.",
            usage=(
                "1337 report export <workspace> --format <json|sarif|html|junit> "
                "--output <new-file>"
            ),
            capabilities=("workbench.report-export",),
        ),
        CommandDescriptor(
            identifier="intel",
            summary="Import explicit local intelligence and verify or apply selected snapshots.",
            usage="1337 intel <import|inspect|apply> <workspace>",
            capabilities=("intelligence.local-snapshot", "intelligence.finding-enrichment"),
        ),
        CommandDescriptor(
            identifier="demo",
            summary="Run an explicitly approved command-owned local SAFE discovery demo.",
            usage="1337 demo local <new-output-root> [--approve-safe-http]",
            capabilities=("workbench.local-demo",),
        ),
        CommandDescriptor(
            identifier="ci",
            summary="Evaluate an explicit current-run finding predicate with verified reports.",
            usage="1337 ci scan <workspace> --profile <synthetic-dockerfile|synthetic-kubernetes>",
            capabilities=("workbench.selected-finding-gate",),
        ),
        CommandDescriptor(
            identifier="runtime",
            summary="Import explicit owned offline Docker inspect or Kubernetes List evidence.",
            usage="1337 runtime import <docker-inspect|kubernetes-list> <workspace>",
            capabilities=("runtime.owned-offline-import",),
        ),
    )
)
