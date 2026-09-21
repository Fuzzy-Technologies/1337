"""Interactive terminal foundations for the 1337 Security Workbench."""

from __future__ import annotations

import cmd
import sys
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import TextIO

from fuzzy1337.command_registry import COMMAND_REGISTRY, CommandRegistry

DEFAULT_LENS = "pentest"
DEFAULT_VIEW = "context"
LENSES = ("pentest", "dfir", "devsecops", "purple")
SHELL_COMMANDS = (
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
HISTORY_LIMIT = 100


@dataclass(frozen=True, slots=True)
class ShellState:
    """Keep the minimum live-workbench context before the Security Object Model exists."""

    lens: str = DEFAULT_LENS
    selected_object: str | None = None
    view: str = DEFAULT_VIEW


@dataclass(frozen=True, slots=True)
class WorkbenchUpdate:
    """Describe a future model, evidence, or progress update for the terminal."""

    kind: str
    message: str


@dataclass(frozen=True, slots=True)
class ContextualAction:
    """Describe a cached action that a selected future model object advertises."""

    identifier: str
    summary: str


def FuzzyMatches(query: str, candidates: Iterable[str]) -> tuple[str, ...]:
    """Return deterministic subsequence matches ordered by compactness then name."""

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
    """Score a subsequence match, preferring adjacent and earlier characters."""

    if not query:
        return 0

    cursor = 0
    previous_index = -1
    score = 0
    for character in query:
        index = candidate.find(character, cursor)
        if index < 0:
            return None

        score += index - previous_index - 1
        cursor = index + 1
        previous_index = index

    return score


class InteractiveShell(cmd.Cmd):
    """Provide a keyboard-first shell without claiming a Security Object Model exists."""

    intro = "1337 interactive workbench. Type 'help' for commands."
    prompt = "1337> "

    def __init__(
        self,
        registry: CommandRegistry = COMMAND_REGISTRY,
        stdin: TextIO | None = None,
        stdout: TextIO | None = None,
    ) -> None:
        """Initialize the shell with explicit registries and streams."""

        super().__init__(stdin=stdin, stdout=stdout)
        self._registry = registry
        self._state = ShellState()
        self._updates: deque[WorkbenchUpdate] = deque()
        self._history: deque[str] = deque(maxlen=HISTORY_LIMIT)
        self._context_actions: dict[str, tuple[ContextualAction, ...]] = {}

    @property
    def State(self) -> ShellState:
        """Return the current immutable workbench context."""

        return self._state

    def PublishUpdate(self, update: WorkbenchUpdate) -> None:
        """Queue a bounded update for a future executor or live model provider."""

        self._updates.append(update)

    def SetContextActions(self, object_id: str, actions: Iterable[ContextualAction]) -> None:
        """Cache local contextual actions without coupling the shell to the future SOM."""

        normalized_object_id = object_id.strip()
        if not normalized_object_id:
            raise ValueError("Object identifiers must be non-empty")

        self._context_actions[normalized_object_id] = tuple(actions)

    def onecmd(self, line: str) -> bool:
        """Run a command while retaining bounded operator history for local search."""

        normalized = line.strip()
        command = normalized.split(maxsplit=1)[0].lower() if normalized else ""
        if normalized and command != "history":
            self._history.append(normalized)

        return super().onecmd(line)

    def completenames(self, text: str, *ignored: object) -> list[str]:
        """Offer fuzzy command discovery for keyboard completion."""

        return list(FuzzyMatches(text, SHELL_COMMANDS))

    def precmd(self, line: str) -> str:
        """Render queued updates before accepting the next operator action."""

        self.RenderUpdates()
        return line

    def do_commands(self, argument: str) -> None:
        """Show interactive commands and available top-level CLI commands."""

        if argument.strip():
            self.Write("usage: commands")
            return

        self.Write("Interactive commands: " + ", ".join(SHELL_COMMANDS))
        self.Write(
            "CLI commands: "
            + ", ".join(descriptor.identifier for descriptor in self._registry.Commands)
        )

    def do_context(self, argument: str) -> None:
        """Show the selected lens and object context."""

        if argument.strip():
            self.Write("usage: context")
            return

        selected_object = self._state.selected_object or "none"
        self.Write(f"Lens: {self._state.lens}")
        self.Write(f"View: {self._state.view}")
        self.Write(f"Selected object: {selected_object}")
        self.Write(f"Pending updates: {len(self._updates)}")

    def do_help(self, argument: str) -> None:
        """Show compact contextual help without opening an external manual."""

        topic = argument.strip().lower()
        help_text = {
            "": (
                "commands, context, history [query], lens <name>, palette [query], "
                "select <object-id>, updates, view <name>, quit"
            ),
            "commands": "commands: list interactive and current top-level CLI commands.",
            "context": "context: show the current lens and selected object reference.",
            "history": "history [query]: search previous shell commands from newest to oldest.",
            "lens": "lens <name>: select pentest, dfir, devsecops, or purple.",
            "palette": (
                "palette [query]: instantly search local commands and selected-object actions."
            ),
            "select": "select <object-id>: keep an opaque object reference in the current context.",
            "updates": "updates: render queued progress or future model updates.",
            "view": "view <name>: select context or updates as the current model slice.",
            "quit": "quit: leave the interactive shell.",
        }
        message = help_text.get(topic)
        if message is None:
            self.Write(f"No shell help for: {topic}")
            return

        self.Write(message)

    def do_history(self, argument: str) -> None:
        """Search local command history in reverse chronological order."""

        query = argument.strip().lower()
        matches = tuple(
            entry for entry in reversed(self._history) if not query or query in entry.lower()
        )
        if not matches:
            self.Write("No matching history entries.")
            return

        for entry in matches:
            self.Write(entry)

    def do_lens(self, argument: str) -> None:
        """Select one of the initial workflow lenses."""

        lens = argument.strip().lower()
        if not lens:
            self.Write("Available lenses: " + ", ".join(LENSES))
            return

        if lens not in LENSES:
            self.Write(f"Unknown lens: {lens}. Available lenses: " + ", ".join(LENSES))
            return

        self._state = replace(self._state, lens=lens)
        self.Write(f"Selected lens: {lens}")

    def do_palette(self, argument: str) -> None:
        """Search immediately available commands and cached selected-object actions."""

        query = argument.strip()
        command_matches = FuzzyMatches(query, SHELL_COMMANDS)
        registry_matches = tuple(
            descriptor.identifier for descriptor in self._registry.Search(query)
            if descriptor.identifier not in command_matches
        )
        contextual_matches = self.MatchingContextActions(query)

        if not (command_matches or registry_matches or contextual_matches):
            self.Write("No palette matches.")
            return

        for command in command_matches:
            self.Write(f"command: {command}")

        for command in registry_matches:
            self.Write(f"cli: {command}")

        for action in contextual_matches:
            self.Write(f"action: {action.identifier} — {action.summary}")

    def do_select(self, argument: str) -> None:
        """Store an opaque selected-object reference until the SOM contract exists."""

        object_id = argument.strip()
        if not object_id:
            self.Write("usage: select <object-id>")
            return

        self._state = replace(self._state, selected_object=object_id)
        self.Write(f"Selected object: {object_id}")

    def do_updates(self, argument: str) -> None:
        """Render currently queued updates without blocking the shell."""

        if argument.strip():
            self.Write("usage: updates")
            return

        self.RenderUpdates()

    def do_view(self, argument: str) -> None:
        """Select the small model-slice view used by the shell foundation."""

        view = argument.strip().lower()
        if not view:
            self.Write("Available views: " + ", ".join(VIEWS))
            return

        if view not in VIEWS:
            self.Write(f"Unknown view: {view}. Available views: " + ", ".join(VIEWS))
            return

        self._state = replace(self._state, view=view)
        self.Write(f"Selected view: {view}")

    def do_quit(self, argument: str) -> bool:
        """Leave the interactive shell."""

        if argument.strip():
            self.Write("usage: quit")
            return False

        return True

    def do_EOF(self, argument: str) -> bool:
        """Treat EOF as a normal interactive-shell exit."""

        self.Write("")
        return True

    def default(self, line: str) -> None:
        """Reject unknown commands without implying that a scanner ran."""

        self.Write(f"Unknown command: {line}. Type 'help' for commands.")

    def RenderUpdates(self) -> None:
        """Drain pending updates in arrival order for deterministic terminal output."""

        if not self._updates:
            return

        while self._updates:
            update = self._updates.popleft()
            self.Write(f"[{update.kind}] {update.message}")

    def MatchingContextActions(self, query: str) -> tuple[ContextualAction, ...]:
        """Return local actions for the selected object, preserving configured order."""

        object_id = self._state.selected_object
        if object_id is None:
            return ()

        normalized = query.lower()
        return tuple(
            action
            for action in self._context_actions.get(object_id, ())
            if not normalized
            or normalized in action.identifier.lower()
            or normalized in action.summary.lower()
        )

    def Write(self, message: str) -> None:
        """Write one line through ``cmd.Cmd``'s configured output stream."""

        self.stdout.write(f"{message}\n")


def RunInteractiveShell() -> int:
    """Run the standard-library shell in the current terminal."""

    shell = InteractiveShell(stdin=sys.stdin, stdout=sys.stdout)
    shell.cmdloop()
    return 0
