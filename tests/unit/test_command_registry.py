"""Tests for command registry behavior."""

import pytest

from fuzzy1337.command_registry import COMMANDREGISTRY, CommandDescriptor, CommandRegistry


def test_RegistryResolvesCanonicalNamesAndAliases():
    """Verify registry resolves canonical names and aliases."""

    scan = CommandDescriptor(
        identifier="scan",
        summary="Assess an authorized target.",
        usage="1337 scan <target>",
        aliases=("s",),
        capabilities=("scanner.authorized",),
    )
    registry = CommandRegistry((scan,))

    assert scan.Names == ("scan", "s"), (
        "registry resolves canonical names and aliases invariant failed."
    )
    assert registry.Resolve("SCAN") is scan, (
        "registry resolves canonical names and aliases invariant failed."
    )
    assert registry.Resolve(" s ") is scan, (
        "registry resolves canonical names and aliases invariant failed."
    )
    assert registry.Resolve("unknown") is None, (
        "registry resolves canonical names and aliases invariant failed."
    )
    assert registry.Resolve("two words") is None, (
        "registry resolves canonical names and aliases invariant failed."
    )


def test_RegistryRejectsAmbiguousOrInvalidNames():
    """Verify registry rejects ambiguous or invalid names."""

    command = CommandDescriptor("scan", "Assess a target.", "1337 scan <target>")

    with pytest.raises(ValueError, match="Duplicate"):
        CommandRegistry((command, CommandDescriptor("scan", "Again.", "1337 scan")))

    with pytest.raises(ValueError, match="Duplicate"):
        CommandRegistry((command, CommandDescriptor("report", "Report.", "1337 report", ("scan",))))

    with pytest.raises(ValueError, match="single tokens"):
        CommandRegistry((CommandDescriptor(" ", "Invalid.", "1337 invalid"),))


def test_RegistryCompletesAndSearchesDescriptors():
    """Verify registry completes and searches descriptors."""

    scan = CommandDescriptor(
        identifier="scan",
        summary="Assess an authorized target.",
        usage="1337 scan <target>",
        aliases=("s",),
        capabilities=("scanner.authorized",),
    )
    report = CommandDescriptor(
        identifier="report",
        summary="Render a security report.",
        usage="1337 report",
        capabilities=("report.html",),
    )
    registry = CommandRegistry((scan, report))

    assert registry.Complete("sc") == (scan,), (
        "registry completes and searches descriptors invariant failed."
    )
    assert registry.Complete("s") == (scan,), (
        "registry completes and searches descriptors invariant failed."
    )
    assert registry.Complete(" ") == (scan, report), (
        "registry completes and searches descriptors invariant failed."
    )
    assert registry.Complete("missing") == (), (
        "registry completes and searches descriptors invariant failed."
    )
    assert registry.Search("scan") == (scan,), (
        "registry completes and searches descriptors invariant failed."
    )
    assert registry.Search("html") == (report,), (
        "registry completes and searches descriptors invariant failed."
    )
    assert registry.Search("") == (scan, report), (
        "registry completes and searches descriptors invariant failed."
    )
    assert registry.Search("missing") == (), (
        "registry completes and searches descriptors invariant failed."
    )


def test_CoreRegistryDescribesOnlyCurrentlyAvailableCommands():
    """Verify core registry describes only currently available commands."""

    identifiers = [descriptor.identifier for descriptor in COMMANDREGISTRY.Commands]
    assert identifiers == ["doctor", "help", "version", "shell"], (
        "core registry describes only currently available commands invariant failed."
    )
    assert COMMANDREGISTRY.Resolve("--version") is COMMANDREGISTRY.Commands[2], (
        "core registry describes only currently available commands invariant failed."
    )
    assert COMMANDREGISTRY.Resolve("shell") is COMMANDREGISTRY.Commands[3], (
        "core registry describes only currently available commands invariant failed."
    )
