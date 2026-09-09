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
    def names(self) -> tuple[str, ...]:
        """Return the canonical identifier followed by its accepted aliases."""
        return (self.identifier, *self.aliases)


class CommandRegistry:
    """Resolve and discover command descriptors through one immutable registry."""

    def __init__(self, commands: Iterable[CommandDescriptor]) -> None:
        self._commands = tuple(commands)
        self._by_name: dict[str, CommandDescriptor] = {}

        for descriptor in self._commands:
            for name in descriptor.names:
                normalized = _normalize_name(name)
                if normalized in self._by_name:
                    raise ValueError(f"Duplicate command name: {name}")

                self._by_name[normalized] = descriptor

    @property
    def commands(self) -> tuple[CommandDescriptor, ...]:
        """Return descriptors in their declared presentation order."""
        return self._commands

    def resolve(self, name: str) -> CommandDescriptor | None:
        """Return a command by canonical name or alias without guessing invalid input."""
        try:
            return self._by_name[_normalize_name(name)]
        except (KeyError, ValueError):
            return None

    def complete(self, prefix: str) -> tuple[CommandDescriptor, ...]:
        """Return commands whose canonical name or alias starts with ``prefix``."""
        normalized = prefix.strip().lower()
        return tuple(
            descriptor
            for descriptor in self._commands
            if not normalized or any(name.lower().startswith(normalized) for name in descriptor.names)
        )

    def search(self, query: str) -> tuple[CommandDescriptor, ...]:
        """Return a deterministic text search for future palettes and documentation."""
        normalized = query.strip().lower()
        if not normalized:
            return self._commands

        matches: list[tuple[int, CommandDescriptor]] = []
        for descriptor in self._commands:
            fields = (*descriptor.names, descriptor.summary, *descriptor.capabilities)
            haystack = " ".join(fields).lower()
            if normalized in haystack:
                rank = 0 if any(name.lower().startswith(normalized) for name in descriptor.names) else 1
                matches.append((rank, descriptor))

        return tuple(descriptor for _, descriptor in sorted(matches, key=lambda match: match[0]))


def _normalize_name(name: str) -> str:
    """Normalize an index key while rejecting empty or multi-token names."""
    normalized = name.strip().lower()
    if not normalized or any(character.isspace() for character in normalized):
        raise ValueError("Command names must be non-empty single tokens")

    return normalized


COMMAND_REGISTRY = CommandRegistry(
    (
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
    )
)
