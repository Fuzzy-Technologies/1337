import pytest

from fuzzy1337.command_registry import COMMAND_REGISTRY, CommandDescriptor, CommandRegistry


def test_registry_resolves_canonical_names_and_aliases():
    scan = CommandDescriptor(
        identifier="scan",
        summary="Assess an authorized target.",
        usage="1337 scan <target>",
        aliases=("s",),
        capabilities=("scanner.authorized",),
    )
    registry = CommandRegistry((scan,))

    assert scan.names == ("scan", "s")
    assert registry.resolve("SCAN") is scan
    assert registry.resolve(" s ") is scan
    assert registry.resolve("unknown") is None
    assert registry.resolve("two words") is None


def test_registry_rejects_ambiguous_or_invalid_names():
    command = CommandDescriptor("scan", "Assess a target.", "1337 scan <target>")

    with pytest.raises(ValueError, match="Duplicate"):
        CommandRegistry((command, CommandDescriptor("scan", "Again.", "1337 scan")))

    with pytest.raises(ValueError, match="Duplicate"):
        CommandRegistry((command, CommandDescriptor("report", "Report.", "1337 report", ("scan",))))

    with pytest.raises(ValueError, match="single tokens"):
        CommandRegistry((CommandDescriptor(" ", "Invalid.", "1337 invalid"),))


def test_registry_completes_and_searches_descriptors():
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

    assert registry.complete("sc") == (scan,)
    assert registry.complete("s") == (scan,)
    assert registry.complete(" ") == (scan, report)
    assert registry.complete("missing") == ()
    assert registry.search("scan") == (scan,)
    assert registry.search("html") == (report,)
    assert registry.search("") == (scan, report)
    assert registry.search("missing") == ()


def test_core_registry_describes_only_currently_available_commands():
    assert [descriptor.identifier for descriptor in COMMAND_REGISTRY.commands] == ["help", "version"]
    assert COMMAND_REGISTRY.resolve("--version") is COMMAND_REGISTRY.commands[1]
