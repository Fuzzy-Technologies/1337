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
SHELL_COMMANDS = ("commands", "context", "help", "lens", "quit", "select", "updates", "view")
VIEWS = ("context", "updates")


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


def fuzzy_matches(query: str, candidates: Iterable[str]) -> tuple[str, ...]:
    """Return deterministic subsequence matches ordered by compactness then name."""

    normalized = query.strip().lower()
    ranked: list[tuple[int, str]] = []
    for candidate in candidates:
        score = _fuzzy_score(normalized, candidate.lower())
        if score is not None:
            ranked.append((score, candidate))

    return tuple(candidate for _, candidate in sorted(ranked, key=lambda match: (match[0], match[1])))


def _fuzzy_score(query: str, candidate: str) -> int | None:
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
        super().__init__(stdin=stdin, stdout=stdout)
        self._registry = registry
        self._state = ShellState()
        self._updates: deque[WorkbenchUpdate] = deque()

    @property
    def state(self) -> ShellState:
        """Return the current immutable workbench context."""

        return self._state

    def publish_update(self, update: WorkbenchUpdate) -> None:
        """Queue a bounded update for a future executor or live model provider."""

        self._updates.append(update)

    def completenames(self, text: str, *ignored: object) -> list[str]:
        """Offer fuzzy command discovery for keyboard completion."""

        return list(fuzzy_matches(text, SHELL_COMMANDS))

    def precmd(self, line: str) -> str:
        """Render queued updates before accepting the next operator action."""

        self._render_updates()
        return line

    def do_commands(self, argument: str) -> None:
        """Show interactive commands and available top-level CLI commands."""

        if argument.strip():
            self._write("usage: commands")
            return

        self._write("Interactive commands: " + ", ".join(SHELL_COMMANDS))
        self._write("CLI commands: " + ", ".join(descriptor.identifier for descriptor in self._registry.commands))

    def do_context(self, argument: str) -> None:
        """Show the selected lens and object context."""

        if argument.strip():
            self._write("usage: context")
            return

        selected_object = self._state.selected_object or "none"
        self._write(f"Lens: {self._state.lens}")
        self._write(f"View: {self._state.view}")
        self._write(f"Selected object: {selected_object}")
        self._write(f"Pending updates: {len(self._updates)}")

    def do_help(self, argument: str) -> None:
        """Show compact contextual help without opening an external manual."""

        topic = argument.strip().lower()
        help_text = {
            "": "commands, context, lens <name>, select <object-id>, updates, view <name>, quit",
            "commands": "commands: list interactive and current top-level CLI commands.",
            "context": "context: show the current lens and selected object reference.",
            "lens": "lens <name>: select pentest, dfir, devsecops, or purple.",
            "select": "select <object-id>: keep an opaque object reference in the current context.",
            "updates": "updates: render queued progress or future model updates.",
            "view": "view <name>: select context or updates as the current model slice.",
            "quit": "quit: leave the interactive shell.",
        }
        message = help_text.get(topic)
        if message is None:
            self._write(f"No shell help for: {topic}")
            return

        self._write(message)

    def do_lens(self, argument: str) -> None:
        """Select one of the initial workflow lenses."""

        lens = argument.strip().lower()
        if not lens:
            self._write("Available lenses: " + ", ".join(LENSES))
            return

        if lens not in LENSES:
            self._write(f"Unknown lens: {lens}. Available lenses: " + ", ".join(LENSES))
            return

        self._state = replace(self._state, lens=lens)
        self._write(f"Selected lens: {lens}")

    def do_select(self, argument: str) -> None:
        """Store an opaque selected-object reference until the SOM contract exists."""

        object_id = argument.strip()
        if not object_id:
            self._write("usage: select <object-id>")
            return

        self._state = replace(self._state, selected_object=object_id)
        self._write(f"Selected object: {object_id}")

    def do_updates(self, argument: str) -> None:
        """Render currently queued updates without blocking the shell."""

        if argument.strip():
            self._write("usage: updates")
            return

        self._render_updates()

    def do_view(self, argument: str) -> None:
        """Select the small model-slice view used by the shell foundation."""

        view = argument.strip().lower()
        if not view:
            self._write("Available views: " + ", ".join(VIEWS))
            return

        if view not in VIEWS:
            self._write(f"Unknown view: {view}. Available views: " + ", ".join(VIEWS))
            return

        self._state = replace(self._state, view=view)
        self._write(f"Selected view: {view}")

    def do_quit(self, argument: str) -> bool:
        """Leave the interactive shell."""

        if argument.strip():
            self._write("usage: quit")
            return False

        return True

    def do_EOF(self, argument: str) -> bool:
        """Treat EOF as a normal interactive-shell exit."""

        self._write("")
        return True

    def default(self, line: str) -> None:
        """Reject unknown commands without implying that a scanner ran."""

        self._write(f"Unknown command: {line}. Type 'help' for commands.")

    def _render_updates(self) -> None:
        """Drain pending updates in arrival order for deterministic terminal output."""

        if not self._updates:
            return

        while self._updates:
            update = self._updates.popleft()
            self._write(f"[{update.kind}] {update.message}")

    def _write(self, message: str) -> None:
        """Write one line through ``cmd.Cmd``'s configured output stream."""

        self.stdout.write(f"{message}\n")


def run_interactive_shell() -> int:
    """Run the standard-library shell in the current terminal."""

    shell = InteractiveShell(stdin=sys.stdin, stdout=sys.stdout)
    shell.cmdloop()
    return 0
