"""Централизованные метаданные команд интерфейса 1337."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CommandDescriptor:
    """Описывает пользовательскую команду без привязки к реализации."""

    identifier: str
    summary: str
    usage: str
    aliases: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()

    @property
    def Names(self) -> tuple[str, ...]:
        """Возвращает канонический идентификатор и допустимые псевдонимы."""

        return (self.identifier, *self.aliases)


class CommandRegistry:
    """Разрешает и находит дескрипторы команд через неизменяемый реестр."""

    def __init__(self, commands: Iterable[CommandDescriptor]) -> None:
        """Создаёт индекс команд и отклоняет неоднозначные имена."""

        self.commandItems = tuple(commands)
        self.descriptorsByName: dict[str, CommandDescriptor] = {}

        for descriptor in self.commandItems:
            for name in descriptor.Names:
                normalized = NormalizeName(name)
                if normalized in self.descriptorsByName:
                    raise ValueError(f"Duplicate command name: {name}")

                self.descriptorsByName[normalized] = descriptor

    @property
    def Commands(self) -> tuple[CommandDescriptor, ...]:
        """Возвращает дескрипторы в объявленном порядке отображения."""

        return self.commandItems

    def Resolve(self, name: str) -> CommandDescriptor | None:
        """Возвращает команду по имени или псевдониму без угадывания ввода."""

        try:
            return self.descriptorsByName[NormalizeName(name)]

        except (KeyError, ValueError):
            return None

    def Complete(self, prefix: str) -> tuple[CommandDescriptor, ...]:
        """Возвращает команды, имя или псевдоним которых начинается с ``prefix``."""

        normalized = prefix.strip().lower()
        return tuple(
            descriptor
            for descriptor in self.commandItems
            if not normalized
            or any(name.lower().startswith(normalized) for name in descriptor.Names)
        )

    def Search(self, query: str) -> tuple[CommandDescriptor, ...]:
        """Выполняет детерминированный текстовый поиск для палитр и документации."""

        normalized = query.strip().lower()
        if not normalized:
            return self.commandItems

        matches: list[tuple[int, CommandDescriptor]] = []
        for descriptor in self.commandItems:
            fields = (*descriptor.Names, descriptor.summary, *descriptor.capabilities)
            haystack = " ".join(fields).lower()
            if normalized in haystack:
                startsWithQuery = any(
                    name.lower().startswith(normalized) for name in descriptor.Names
                )
                rank = 0 if startsWithQuery else 1
                matches.append((rank, descriptor))

        return tuple(descriptor for _, descriptor in sorted(matches, key=lambda match: match[0]))


def NormalizeName(name: str) -> str:
    """Нормализует ключ индекса и отклоняет пустые или многословные имена."""

    normalized = name.strip().lower()
    if not normalized or any(character.isspace() for character in normalized):
        raise ValueError("Command names must be non-empty single tokens")

    return normalized


COMMANDREGISTRY = CommandRegistry(
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
        CommandDescriptor(
            identifier="shell",
            summary="Start the interactive 1337 workbench shell.",
            usage="1337 shell",
            capabilities=("workbench.interactive",),
        ),
    )
)
