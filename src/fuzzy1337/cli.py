"""Минимальная установленная точка входа 1337 Security Workbench."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from importlib.metadata import version

from fuzzy1337.command_registry import COMMANDREGISTRY, CommandRegistry
from fuzzy1337.dev_commands import DescribeCommands
from fuzzy1337.shell import RunInteractiveShell


def GetCommands() -> dict[str, str]:
    """Возвращает описания из детерминированного реестра команд разработчика."""

    return DescribeCommands()


def GetCommandRegistry() -> CommandRegistry:
    """Возвращает централизованный реестр без раскрытия изменяемого состояния."""

    return COMMANDREGISTRY


def CommandEpilog(registry: CommandRegistry) -> str:
    """Формирует список доступных команд из централизованных дескрипторов."""

    lines = ["Currently available commands:"]
    lines.extend(
        f"  {descriptor.usage:<18}{descriptor.summary}"
        for descriptor in registry.Commands
    )
    lines.append("Run '1337 shell' to start the interactive workbench.")
    return "\n".join(lines)


def Main(argv: Sequence[str] | None = None) -> int:
    """Запускает оболочку либо выводит справку и установленную версию."""

    registry = GetCommandRegistry()
    parser = argparse.ArgumentParser(
        prog="1337",
        description="1337 Security Workbench by Fuzzy Technologies",
        epilog=CommandEpilog(registry),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"1337 {version('1337')}")
    parser.add_argument("command", choices=("help", "shell"), nargs="?", help=argparse.SUPPRESS)
    arguments = parser.parse_args(argv)

    if arguments.command == "shell" or (arguments.command is None and sys.stdin.isatty()):
        return RunInteractiveShell()

    parser.print_help()
    return 0
