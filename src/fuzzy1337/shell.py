"""Основы интерактивного терминала 1337 Security Workbench."""

from __future__ import annotations

import cmd
import sys
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import TextIO

from fuzzy1337.command_registry import COMMANDREGISTRY, CommandRegistry

DEFAULTLENS = "pentest"
DEFAULTVIEW = "context"
LENSES = ("pentest", "dfir", "devsecops", "purple")
SHELLCOMMANDS = (
    "commands",
    "context",
    "help",
    "history",
    "lens",
    "palette",
    "quit",
    "select",
    "updates",
    "view",
)
VIEWS = ("context", "updates")
HISTORYLIMIT = 100


@dataclass(frozen=True, slots=True)
class ShellState:
    """Хранит минимальный контекст среды до появления Security Object Model."""

    lens: str = DEFAULTLENS
    selectedObject: str | None = None
    view: str = DEFAULTVIEW


@dataclass(frozen=True, slots=True)
class WorkbenchUpdate:
    """Описывает обновление модели, доказательства или прогресса."""

    kind: str
    message: str


@dataclass(frozen=True, slots=True)
class ContextualAction:
    """Описывает кэшированное действие выбранного объекта модели."""

    identifier: str
    summary: str


def FuzzyMatches(query: str, candidates: Iterable[str]) -> tuple[str, ...]:
    """Возвращает совпадения подпоследовательности по компактности и имени."""

    normalized = query.strip().lower()
    ranked: list[tuple[int, str]] = []
    for candidate in candidates:
        score = FuzzyScore(normalized, candidate.lower())
        if score is not None:
            ranked.append((score, candidate))

    return tuple(
        candidate
        for _, candidate in sorted(ranked, key=lambda match: (match[0], match[1]))
    )


def FuzzyScore(query: str, candidate: str) -> int | None:
    """Оценивает совпадение, предпочитая соседние и ранние символы."""

    if not query:
        return 0

    cursor = 0
    previousIndex = -1
    score = 0
    for character in query:
        index = candidate.find(character, cursor)
        if index < 0:
            return None

        score += index - previousIndex - 1
        cursor = index + 1
        previousIndex = index

    return score


class InteractiveShell(cmd.Cmd):
    """Предоставляет клавиатурную оболочку без ложного наличия SOM."""

    intro = "1337 interactive workbench. Type 'help' for commands."
    prompt = "1337> "

    def __init__(
        self,
        registry: CommandRegistry = COMMANDREGISTRY,
        stdin: TextIO | None = None,
        stdout: TextIO | None = None,
    ) -> None:
        """Создаёт изолированное состояние интерактивной оболочки."""

        super().__init__(stdin=stdin, stdout=stdout)
        self.registry = registry
        self.shellState = ShellState()
        self.updates: deque[WorkbenchUpdate] = deque()
        self.history: deque[str] = deque(maxlen=HISTORYLIMIT)
        self.contextActions: dict[str, tuple[ContextualAction, ...]] = {}

    @property
    def State(self) -> ShellState:
        """Возвращает текущий неизменяемый контекст среды."""

        return self.shellState

    def PublishUpdate(self, update: WorkbenchUpdate) -> None:
        """Ставит ограниченное обновление в очередь терминала."""

        self.updates.append(update)

    def SetContextActions(self, objectId: str, actions: Iterable[ContextualAction]) -> None:
        """Кэширует действия без связывания оболочки с будущей SOM."""

        normalizedObjectId = objectId.strip()
        if not normalizedObjectId:
            raise ValueError("Object identifiers must be non-empty")

        self.contextActions[normalizedObjectId] = tuple(actions)

    def onecmd(self, line: str) -> bool:
        """Выполняет команду и сохраняет ограниченную историю оператора."""

        normalized = line.strip()
        command = normalized.split(maxsplit=1)[0].lower() if normalized else ""
        if normalized and command != "history":
            self.history.append(normalized)

        return super().onecmd(line)

    def completenames(self, text: str, *ignored: object) -> list[str]:
        """Предоставляет нечёткий поиск команд для дополнения."""

        return list(FuzzyMatches(text, SHELLCOMMANDS))

    def precmd(self, line: str) -> str:
        """Показывает очередь обновлений перед следующим действием."""

        self.RenderUpdates()
        return line

    def do_commands(self, argument: str) -> None:
        """Показывает интерактивные и верхнеуровневые CLI-команды."""

        if argument.strip():
            self.Write("usage: commands")
            return

        self.Write("Interactive commands: " + ", ".join(SHELLCOMMANDS))
        commands = ", ".join(
            descriptor.identifier for descriptor in self.registry.Commands
        )
        self.Write("CLI commands: " + commands)

    def do_context(self, argument: str) -> None:
        """Показывает выбранную линзу и контекст объекта."""

        if argument.strip():
            self.Write("usage: context")
            return

        selectedObject = self.shellState.selectedObject or "none"
        self.Write(f"Lens: {self.shellState.lens}")
        self.Write(f"View: {self.shellState.view}")
        self.Write(f"Selected object: {selectedObject}")
        self.Write(f"Pending updates: {len(self.updates)}")

    def do_help(self, argument: str) -> None:
        """Показывает краткую справку без внешнего руководства."""

        topic = argument.strip().lower()
        helpText = {
            "": (
                "commands, context, history [query], lens <name>, palette [query], "
                "select <object-id>, updates, view <name>, quit"
            ),
            "commands": "commands: list interactive and current top-level CLI commands.",
            "context": "context: show the current lens and selected object reference.",
            "history": "history [query]: search previous shell commands from newest to oldest.",
            "lens": "lens <name>: select pentest, dfir, devsecops, or purple.",
            "palette": (
                "palette [query]: instantly search local commands and "
                "selected-object actions."
            ),
            "select": "select <object-id>: keep an opaque object reference in the current context.",
            "updates": "updates: render queued progress or future model updates.",
            "view": "view <name>: select context or updates as the current model slice.",
            "quit": "quit: leave the interactive shell.",
        }
        message = helpText.get(topic)
        if message is None:
            self.Write(f"No shell help for: {topic}")
            return

        self.Write(message)

    def do_history(self, argument: str) -> None:
        """Ищет в истории команд в обратном хронологическом порядке."""

        query = argument.strip().lower()
        matches = tuple(
            entry for entry in reversed(self.history) if not query or query in entry.lower()
        )
        if not matches:
            self.Write("No matching history entries.")
            return

        for entry in matches:
            self.Write(entry)

    def do_lens(self, argument: str) -> None:
        """Выбирает одну из исходных линз рабочего процесса."""

        lens = argument.strip().lower()
        if not lens:
            self.Write("Available lenses: " + ", ".join(LENSES))
            return

        if lens not in LENSES:
            self.Write(f"Unknown lens: {lens}. Available lenses: " + ", ".join(LENSES))
            return

        self.shellState = replace(self.shellState, lens=lens)
        self.Write(f"Selected lens: {lens}")

    def do_palette(self, argument: str) -> None:
        """Ищет доступные команды и действия выбранного объекта."""

        query = argument.strip()
        commandMatches = FuzzyMatches(query, SHELLCOMMANDS)
        registryMatches = tuple(
            descriptor.identifier for descriptor in self.registry.Search(query)
            if descriptor.identifier not in commandMatches
        )
        contextualMatches = self.MatchingContextActions(query)

        if not (commandMatches or registryMatches or contextualMatches):
            self.Write("No palette matches.")
            return

        for command in commandMatches:
            self.Write(f"command: {command}")

        for command in registryMatches:
            self.Write(f"cli: {command}")

        for action in contextualMatches:
            self.Write(f"action: {action.identifier} — {action.summary}")

    def do_select(self, argument: str) -> None:
        """Хранит непрозрачную ссылку объекта до появления контракта SOM."""

        objectId = argument.strip()
        if not objectId:
            self.Write("usage: select <object-id>")
            return

        self.shellState = replace(self.shellState, selectedObject=objectId)
        self.Write(f"Selected object: {objectId}")

    def do_updates(self, argument: str) -> None:
        """Показывает обновления без блокировки оболочки."""

        if argument.strip():
            self.Write("usage: updates")
            return

        self.RenderUpdates()

    def do_view(self, argument: str) -> None:
        """Выбирает компактное представление среза модели."""

        view = argument.strip().lower()
        if not view:
            self.Write("Available views: " + ", ".join(VIEWS))
            return

        if view not in VIEWS:
            self.Write(f"Unknown view: {view}. Available views: " + ", ".join(VIEWS))
            return

        self.shellState = replace(self.shellState, view=view)
        self.Write(f"Selected view: {view}")

    def do_quit(self, argument: str) -> bool:
        """Завершает интерактивную оболочку."""

        if argument.strip():
            self.Write("usage: quit")
            return False

        return True

    def do_EOF(self, argument: str) -> bool:
        """Обрабатывает EOF как штатное завершение оболочки."""

        self.Write("")
        return True

    def default(self, line: str) -> None:
        """Отклоняет неизвестные команды без ложного запуска сканера."""

        self.Write(f"Unknown command: {line}. Type 'help' for commands.")

    def RenderUpdates(self) -> None:
        """Выводит ожидающие обновления в порядке поступления."""

        if not self.updates:
            return

        while self.updates:
            update = self.updates.popleft()
            self.Write(f"[{update.kind}] {update.message}")

    def MatchingContextActions(self, query: str) -> tuple[ContextualAction, ...]:
        """Возвращает действия выбранного объекта в заданном порядке."""

        objectId = self.shellState.selectedObject
        if objectId is None:
            return ()

        normalized = query.lower()
        return tuple(
            action
            for action in self.contextActions.get(objectId, ())
            if not normalized
            or normalized in action.identifier.lower()
            or normalized in action.summary.lower()
        )

    def Write(self, message: str) -> None:
        """Записывает строку через настроенный поток ``cmd.Cmd``."""

        self.stdout.write(f"{message}\n")


def RunInteractiveShell() -> int:
    """Запускает оболочку стандартной библиотеки в текущем терминале."""

    shell = InteractiveShell(stdin=sys.stdin, stdout=sys.stdout)
    shell.cmdloop()
    return 0
