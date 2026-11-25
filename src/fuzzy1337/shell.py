# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Interactive terminal foundations for the 1337 Security Workbench."""

from __future__ import annotations

import cmd
import json
import os
import shlex
import stat
import sys
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path
from types import ModuleType
from typing import TextIO, cast

from fuzzy1337.command_registry import COMMAND_REGISTRY, CommandRegistry
from fuzzy1337.component_health import RunUpdate
from fuzzy1337.lenses import LENS_CATALOG, LensQuery, ResolveLens
from fuzzy1337.model import CanonicalModelJson, LocalModelStore, ModelState
from fuzzy1337.workspace import RejectWorkspaceConstant, UniqueWorkspaceObject

DEFAULT_LENS = "pentest"
DEFAULT_VIEW = "context"
LENSES = tuple(descriptor.identifier for descriptor in LENS_CATALOG)
SHELL_COMMANDS = (
    "api",
    "bridge",
    "business",
    "ci",
    "commands",
    "context",
    "demo",
    "extension",
    "help",
    "history",
    "image",
    "intel",
    "lens",
    "model",
    "palette",
    "paths",
    "quit",
    "raw",
    "report",
    "runtime",
    "sbom",
    "scan",
    "scope",
    "select",
    "trace",
    "update",
    "updates",
    "view",
    "workspace",
)
VIEWS = ("context", "updates", "model")
HISTORY_LIMIT = 100
MAX_LENS_QUERY_BYTES = 64 * 1024


def ReadLensQuery(path: Path) -> LensQuery:
    """Read one bounded literal query file through the existing typed lens decoder.

    Args:
        path: Explicit regular UTF-8 JSON file, without a final symbolic link.

    Returns:
        Immutable replacement query with the standard six LensQuery fields.

    Raises:
        OSError: The selected file cannot be opened for reading.
        ValueError: Input is not a regular bounded file or a strict typed query.
    """

    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("lens query must be a regular file without a symbolic link")

    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0))

    with os.fdopen(os.open(path, flags), "rb") as stream:
        metadata = os.fstat(stream.fileno())

        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_LENS_QUERY_BYTES:
            raise ValueError("lens query must be a regular file of at most 65536 bytes")

        payload = stream.read(MAX_LENS_QUERY_BYTES + 1)

    if len(payload) > MAX_LENS_QUERY_BYTES:
        raise ValueError("lens query exceeds 65536 bytes")

    try:
        document = json.loads(payload.decode("utf-8"), object_pairs_hook=UniqueWorkspaceObject,
                              parse_constant=RejectWorkspaceConstant)

        return LensQuery.FromDict(document)

    except (UnicodeError, RecursionError) as error:
        raise ValueError("lens query must be bounded valid UTF-8 JSON") from error


@dataclass(frozen=True, slots=True)
class ShellState:
    """Keep lens selection and presentation separate from canonical security state."""

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
    """Return deterministic subsequence matches ordered by compactness then name.

    Args:
        query: Case-insensitive subsequence, with empty text matching all candidates
        candidates: Candidate names whose spelling is preserved.

    Returns:
        Matches sorted by gap score, then candidate name.
    """

    normalized = query.strip().lower()
    ranked: list[tuple[int, str]] = []
    for candidate in candidates:
        score = FuzzyScore(normalized, candidate.lower())
        if score is not None:
            ranked.append((score, candidate))

    return tuple(
        candidate for _, candidate in sorted(ranked, key=lambda match: (match[0], match[1]))
    )


def FuzzyScore(query: str, candidate: str) -> int | None:
    """Score a subsequence match, preferring adjacent and earlier characters.

    Args:
        query: Subsequence to locate, normalized by callers when needed
        candidate: Text searched for query characters in order.

    Returns:
        Gap score, zero for empty query, or None when unmatched.
    """

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


@dataclass(slots=True)
class NativeInputHistory:
    """Track only an owned terminal loop's new entries without changing readline settings."""

    editor: ModuleType
    last_index: int

    @classmethod
    def Open(cls, editor: ModuleType) -> NativeInputHistory:
        """Pin native absolute indexing before accepting input, including capped GNU histories.

        Args:
            editor: Existing standard-library readline backend in the owned terminal process.

        Returns:
            Loop-local cursor; no prior history content is retained or rewritten.

        Raises:
            RuntimeError: Bounded public-API lookup cannot identify the native history safely.
        """

        count = int(editor.get_current_history_length())

        if not count:
            return cls(editor, 0)

        for firstIndex in range(1, HISTORY_LIMIT + 1):
            if editor.get_history_item(firstIndex) is None:
                continue

            lastIndex = firstIndex + count - 1

            if (
                editor.get_history_item(lastIndex) is not None
                and editor.get_history_item(lastIndex + 1) is None
            ):
                return cls(editor, lastIndex)

        raise RuntimeError("Native terminal history cannot be identified safely.")

    def Reconcile(self, shell: InteractiveShell, line: str | None) -> None:
        """Replace only subsequent protected input entries, preserving caller history and settings.

        Args:
            shell: Owning loop whose actual parser classifies the protected namespaces.
            line: Actual input for exact matching, empty for observation, or None for exit cleanup.

        Raises:
            RuntimeError: Native indexing, retirement or growth cannot be identified safely.
        """

        count = int(self.editor.get_current_history_length())

        if not count and not self.last_index:
            return

        entries: list[tuple[int, str]] = []

        for index in range(self.last_index + 1, self.last_index + HISTORY_LIMIT + 2):
            value = self.editor.get_history_item(index)

            if value is None:
                if entries:
                    break

                continue

            if not isinstance(value, str) or index - self.last_index > HISTORY_LIMIT:
                raise RuntimeError("Native terminal history changed outside its owned boundary.")

            entries.append((index, value))

        lastIndex = entries[-1][0] if entries else self.last_index

        if (
            not entries and line == "" and self.last_index
            and self.editor.get_history_item(self.last_index) is None
        ):
            for previousIndex in range(
                self.last_index - 1, max(0, self.last_index - HISTORY_LIMIT - 1), -1
            ):
                if self.editor.get_history_item(previousIndex) is not None:
                    lastIndex = previousIndex
                    break

        firstIndex = lastIndex - count + 1

        if (
            count <= 0 or firstIndex <= 0
            or self.editor.get_history_item(firstIndex) is None
            or self.editor.get_history_item(lastIndex) is None
            or self.editor.get_history_item(lastIndex + 1) is not None
            or int(self.editor.get_current_history_length()) != count
        ):
            raise RuntimeError("Native terminal history cannot be identified safely.")

        for index, value in entries:
            if line is not None and value != line:
                continue

            parsed, _, _ = shell.parseline(value)
            command = parsed.lower() if parsed else ""

            if command in {
                "workspace", "scope", "scan", "report", "demo", "intel", "ci", "runtime",
                "paths", "sbom", "api", "trace", "raw", "image", "extension", "business",
                "bridge"
            }:
                position = index - firstIndex

                if not 0 <= position < count:
                    raise RuntimeError("Native terminal input no longer has an owned position.")

                self.editor.replace_history_item(position, command)

        self.last_index = lastIndex


class InteractiveShell(cmd.Cmd):
    """Provide a keyboard-first shell with explicit read-only model snapshot views."""

    intro = "1337 interactive workbench. Type 'help' for commands."
    prompt = "1337> "

    def __init__(
        self,
        registry: CommandRegistry = COMMAND_REGISTRY,
        stdin: TextIO | None = None,
        stdout: TextIO | None = None,
    ) -> None:
        """Initialize the shell with explicit registries and streams.

        Args:
            registry: Top-level command metadata used for help and palette discovery
            stdin: Optional input stream forwarded to cmd.Cmd
            stdout: Optional output stream forwarded to cmd.Cmd.
        """

        super().__init__(stdin=stdin, stdout=stdout)
        self._registry = registry
        self._state = ShellState()
        self._updates: deque[WorkbenchUpdate] = deque()
        self._history: deque[str] = deque(maxlen=HISTORY_LIMIT)
        self._context_actions: dict[str, tuple[ContextualAction, ...]] = {}
        self._model: ModelState | None = None
        self._native_history: NativeInputHistory | None = None

    def CommandLoop(self, intro: str | None = None) -> None:
        """Own only native entries created by this loop while preserving framework completion.

        Args:
            intro: Optional framework intro override, without implicit input or history files.

        Raises:
            KeyboardInterrupt: Terminal interruption after scoped cleanup and completer restore.
            RuntimeError: Native history cannot be identified safely before accepting input.
        """

        if self.use_rawinput and sys.stdin.isatty() and sys.stdout.isatty():
            try:
                import readline

            except ImportError:
                pass

            else:
                self._native_history = NativeInputHistory.Open(readline)

        try:
            super().cmdloop(intro=intro)

        finally:
            try:
                if self._native_history is not None:
                    self._native_history.Reconcile(self, None)

            finally:
                self._native_history = None

    cmdloop = CommandLoop

    def AfterCommand(self, stop: bool, line: str) -> bool:
        """Observe command-time additions without treating them as input owned by this loop.

        Args:
            stop: Framework termination result to preserve unchanged.
            line: Framework command text; it never supplies native history ownership.

        Returns:
            Original framework termination result.
        """

        if self._native_history is not None:
            self._native_history.Reconcile(self, "")

        return stop

    postcmd = AfterCommand

    def BindModel(self, state: ModelState) -> None:
        """Bind an immutable shared snapshot without authorizing, executing, or persisting work.

        Args:
            state: Validated canonical model snapshot supplied by a workspace owner.

        Raises:
            ValueError: The snapshot is not a ModelState.
        """

        if not isinstance(state, ModelState):
            raise ValueError("state must be a ModelState")

        self._model = state

    @property
    def State(self) -> ShellState:
        """Return the current immutable workbench context.

        Returns:
            Current immutable lens, selected-object reference and view state.
        """

        return self._state

    def PublishUpdate(self, update: WorkbenchUpdate) -> None:
        """Queue an update for a future executor or live model provider.

        Appends to the in-memory queue; callers must bound producer volume between drains. No
        executor is started and no security state is persisted.

        Args:
            update: Message to queue for the next rendering phase.
        """

        self._updates.append(update)

    def SetContextActions(self, object_id: str, actions: Iterable[ContextualAction]) -> None:
        """Cache local contextual actions without coupling the shell to the future SOM.

        Replaces local shell metadata only; it does not authorize or execute advertised actions.

        Args:
            object_id: Nonempty opaque object identifier trimmed of surrounding whitespace
            actions: Cached descriptors in declaration order.

        Raises:
            ValueError: The object identifier is empty.
        """

        normalizedObjectId = object_id.strip()
        if not normalizedObjectId:
            raise ValueError("Object identifiers must be non-empty")

        self._context_actions[normalizedObjectId] = tuple(actions)

    def onecmd(self, line: str) -> bool:
        """Run a command while retaining bounded operator history for local search.

        Records ordinary nonempty commands except history in bounded local history.
        Product commands retain only their namespace, excluding rejected arguments.
        Classification uses the dispatch parser before either history or replay state is retained.

        Args:
            line: Operator command line to dispatch through cmd.Cmd.

        Returns:
            Whether the dispatched command requests shell termination.
        """

        normalized = line.strip()
        parsedCommand, argument, _ = self.parseline(normalized)
        command = parsedCommand.lower() if parsedCommand else ""

        if normalized and command != "history":
            self._history.append(
                command if command in {
                    "workspace", "scope", "scan", "report", "demo", "intel", "ci", "runtime",
                    "paths", "sbom", "api", "trace", "raw", "image", "extension", "business",
                    "bridge"
                }
                else normalized
            )

        if command in {
            "workspace", "scope", "scan", "report", "demo", "intel", "ci", "runtime",
            "paths", "sbom", "api", "trace", "response", "raw", "image", "extension", "business",
            "bridge"
        }:
            handlers = {"business": self.do_business,
                        "workspace": self.do_workspace, "scope": self.do_scope,
                        "scan": self.do_scan, "report": self.do_report, "demo": self.do_demo,
                        "ci": self.do_ci,
                        "image": self.do_image,
                        "extension": self.do_extension,
                        "runtime": self.do_runtime,
                        "paths": self.do_paths,
                        "sbom": self.do_sbom,
                        "api": self.do_api,
                        "response": self.do_response,
                        "raw": self.do_raw,
                        "trace": self.do_trace,
                        "bridge": self.do_bridge,
                        "intel": self.do_intel}
            self.lastcmd = command

            try:
                handlers[command](argument or "")

                return False

            finally:
                # The framework must never retain raw product arguments for empty-line replay.
                self.lastcmd = command

                if self._native_history is not None:
                    self._native_history.Reconcile(self, "")

        try:
            return super().onecmd(line)

        finally:
            if self._native_history is not None:
                self._native_history.Reconcile(self, "")

    def completenames(self, text: str, *ignored: object) -> list[str]:
        """Offer fuzzy command discovery for keyboard completion.

        Args:
            text: Partial command name to match by subsequence
            ignored: Unused framework completion arguments.

        Returns:
            Ranked interactive command names.
        """

        return list(FuzzyMatches(text, SHELL_COMMANDS))

    def precmd(self, line: str) -> str:
        """Protect owned native input history and render queued updates before the next action.

        Args:
            line: Operator line to return unchanged for dispatch.

        Returns:
            Original line after pending updates have been rendered.
        """

        if self._native_history is not None:
            self._native_history.Reconcile(self, line)

        self.RenderUpdates()
        return line

    def do_commands(self, argument: str) -> None:
        """Show interactive commands and available top-level CLI commands.

        Args:
            argument: Empty input expected, otherwise usage is printed.
        """

        if argument.strip():
            self.Write("usage: commands")
            return

        self.Write("Interactive commands: " + ", ".join(SHELL_COMMANDS))
        self.Write(
            "CLI commands: "
            + ", ".join(descriptor.identifier for descriptor in self._registry.Commands)
        )

    def do_context(self, argument: str) -> None:
        """Show the selected lens and object context.

        Args:
            argument: Empty input expected, otherwise usage is printed.
        """

        if argument.strip():
            self.Write("usage: context")
            return

        selectedObject = self._state.selected_object or "none"
        self.Write(f"Lens: {self._state.lens}")
        self.Write(f"View: {self._state.view}")
        self.Write(f"Selected object: {selectedObject}")
        self.Write(f"Pending updates: {len(self._updates)}")

    def do_help(self, argument: str) -> None:
        """Show compact contextual help without opening an external manual.

        Args:
            argument: Optional topic, with empty input listing help topics.
        """

        topic = argument.strip().lower()
        helpText = {
            "": (
                "api import graphql-introspection, bridge sarif <import|inspect>, "
                "business inspect, ci scan, commands, "
                "context, demo local, "
                "history [query], image export-local, extension validate, "
                "lens [<name>] [--json], "
                "intel <import|inspect|preview|apply>, model <workspace-path>, palette [query], "
                "paths analyze, raw <plan|run|replay>, report export, "
                "runtime import <docker-inspect|kubernetes-list>, "
                "trace ioc <import|inspect|export-bundle|verify-bundle>, "
                "select <object-id>, "
                "sbom <image|import spdx-graph|import cyclonedx>, "
                "scan <quick|crawl|ports|web|nuclei|image|config>, "
                "scope create, "
                "workspace <create|open>, "
                "update [--json], updates, view <name> [--query <file>] [--json], quit"
            ),
            "api": (
                "api import graphql-introspection <workspace>: import one explicit owned offline "
                "file or retained original manifest with endpoint/scope and exact revision bases."
            ),
            "business": (
                "business inspect <workspace>: verify one retained owner declaration and "
                "its saved critical Assets with explicit original and model pins."
            ),
            "extension": (
                "extension validate <manifest>: validate metadata offline without activation."
            ),
            "image": "image export-local <workspace>: plan or explicitly approve local export; "
                     "archive scanning requires separate scope and approval.",
            "commands": "commands: list interactive and current top-level CLI commands.",
            "ci": (
                "ci scan <workspace>: run the explicitly selected closed image/configuration "
                "profile, "
                "finding predicate and new JSON/SARIF/JUnit exports."
            ),
            "context": "context: show the current lens and selected object reference.",
            "demo": (
                "demo local <new-output-root> [--approve-safe-http]: "
                "run only the explicitly approved command-owned localhost demo."
            ),
            "history": "history [query]: search previous shell commands from newest to oldest.",
            "intel": (
                "intel <import|inspect|preview|apply> <workspace>: select local source files, "
                "verified snapshots/receipts, or one finding's enrichment."
            ),
            "lens": (
                "lens [<name>] [--json]: select pentest, dfir, devsecops, or purple; "
                "--json describes the selected lens."
            ),
            "model": "model <workspace-path>: open an existing read-only workspace model snapshot.",
            "palette": (
                "palette [query]: instantly search local commands and selected-object actions."
            ),
            "select": "select <object-id>: keep an opaque object reference in the current context.",
            "paths": (
                "paths analyze <workspace>: explain an exact saved-model selection using original "
                "assessment manifests, an explicit analysis clock and finite search/cut budgets."
            ),
            "raw": (
                "raw <plan|run|replay> <workspace>: use explicit governed native Nmap profiles; "
                "separate exact native tokens with --; replay verifies original custody offline."
            ),
            "report": (
                "report export <workspace>: verify and export saved JSON, SARIF, HTML or JUnit."
            ),
            "runtime": (
                "runtime import <docker-inspect|kubernetes-list> <workspace>: import one explicit "
                "owned file or retained manifest with existing HOST/cluster, scope and exact bases."
            ),
            "sbom": (
                "sbom image <workspace>: inspect verified saved inventory by exact digest/kind; "
                "sbom import <spdx-graph|cyclonedx> <workspace>: import an owned file or replay "
                "original product custody with explicit image/scope/run and both revision bases; "
                "CycloneDX file mode requires --expected-sha256."
            ),
            "bridge": (
                "bridge sarif <import|inspect> <workspace>: retain an explicit saved file or "
                "verify original/receipt/SHA pins; source URI/path strings are never opened."
            ),
            "trace": (
                "trace ioc <import|inspect|export-bundle|verify-bundle>: import selected "
                "candidates, inspect originals or transfer and verify one explicit evidence bundle."
            ),
            "scan": (
                "scan <quick|crawl|ports|web|nuclei|image|config> <workspace>: run governed scans; "
                "crawl requires explicit selected URLs/policy and --approve-safe-crawl; "
                "config requires explicit synthetic/native profile and selected source/consent; "
                "native Kubernetes input must already be rendered."
            ),
            "scope": "scope create <workspace>: record explicit targets, rules and consent.",
            "workspace": "workspace <create|open>: initialize or verify durable shared state.",
            "update": "update [--json]: inspect local component health without installing updates.",
            "updates": "updates: render queued progress or future model updates.",
            "view": (
                "view <name> [--query <file>] [--json]: select context, updates, or model; "
                "query and JSON require model. Query replaces the lens preset for this view only."
            ),
            "quit": "quit: leave the interactive shell.",
        }
        message = helpText.get(topic)
        if message is None:
            self.Write(f"No shell help for: {topic}")
            return

        self.Write(message)

    def RunLocalCommand(self, command: str, argument: str) -> None:
        """Dispatch the same explicit foreground product commands as the CLI.

        Args:
            command: Product namespace; shell context never supplies implicit authority.
            argument: Quoted operator argument line, parsed without a subprocess shell.
        """

        try:
            arguments = shlex.split(argument)
            separator = (arguments.index("--") if command == "raw" and "--" in arguments
                         else len(arguments))
            prefix, native = arguments[:separator], arguments[separator:]
            jsonOutput = "--json" in prefix
            arguments = [item for item in prefix if item != "--json"] + native

            if command == "business":
                from fuzzy1337.business_commands import RunBusinessCommands

                status = RunBusinessCommands(arguments, cast(TextIO, self.stdout),
                                             machine=jsonOutput)

            elif command == "extension":
                from fuzzy1337.extension_commands import RunExtensionCommands

                status = RunExtensionCommands(arguments, cast(TextIO, self.stdout),
                                              jsonOutput=jsonOutput)

            elif command == "raw":
                from fuzzy1337.raw_commands import RunRawCommands

                status = RunRawCommands(arguments, cast(TextIO, self.stdout),
                                        json_output=jsonOutput)

            elif command == "image":
                from fuzzy1337.local_image_commands import RunLocalImageCommands

                status = RunLocalImageCommands(arguments, cast(TextIO, self.stdout),
                                               json_output=jsonOutput)

            elif command == "paths":
                from fuzzy1337.path_commands import RunPathCommands

                status = RunPathCommands(arguments, cast(TextIO, self.stdout),
                                         json_output=jsonOutput)

            elif command == "sbom":
                from fuzzy1337.sbom_commands import RunSbomCommands

                status = RunSbomCommands(arguments, cast(TextIO, self.stdout),
                                         json_output=jsonOutput)

            elif command == "api":
                from fuzzy1337.api_commands import RunApiCommands

                status = RunApiCommands(arguments, cast(TextIO, self.stdout),
                                        json_output=jsonOutput)

            elif command == "response":
                from fuzzy1337.response_commands import RunResponseCommands

                status = RunResponseCommands(arguments, cast(TextIO, self.stdout),
                                             json_output=jsonOutput)

            elif command == "runtime":
                from fuzzy1337.runtime_commands import RunRuntimeCommands

                status = RunRuntimeCommands(arguments, cast(TextIO, self.stdout),
                                            json_output=jsonOutput)

            elif command == "bridge":
                from fuzzy1337.bridge_commands import RunBridgeCommands

                status = RunBridgeCommands(arguments, cast(TextIO, self.stdout),
                                           jsonOutput=jsonOutput)

            elif command == "trace":
                from fuzzy1337.ioc_commands import RunIocCommands

                status = RunIocCommands(arguments, cast(TextIO, self.stdout),
                                        json_output=jsonOutput)

            elif command == "ci":
                from fuzzy1337.ci_commands import RunCiCommands

                status = RunCiCommands(arguments, cast(TextIO, self.stdout),
                                       json_output=jsonOutput)

            elif command == "intel":
                from fuzzy1337.intelligence_commands import RunIntelCommands

                status = RunIntelCommands(arguments, cast(TextIO, self.stdout),
                                          json_output=jsonOutput)

            elif command == "report":
                from fuzzy1337.report_commands import RunReportCommands

                status = RunReportCommands(arguments, cast(TextIO, self.stdout),
                                           json_output=jsonOutput)

            elif command == "demo":
                from fuzzy1337.demo_commands import RunDemoCommands

                status = RunDemoCommands(arguments, cast(TextIO, self.stdout),
                                         json_output=jsonOutput)

            else:
                from fuzzy1337.scan_commands import RunCommands

                status = RunCommands(command, arguments, cast(TextIO, self.stdout),
                                     json_output=jsonOutput)

            if status:
                self.Write(f"Command exit status: {status}")

        except ValueError:
            self.Write("Invalid quoted command arguments.")

        except SystemExit as error:
            if error.code:
                self.Write(f"usage: {command} --help")

    def do_workspace(self, argument: str) -> None:
        """Create or reopen a workspace through the explicit product command.

        Args:
            argument: Workspace action and its full explicit CLI argument list.
        """

        self.RunLocalCommand("workspace", argument)

    def do_scope(self, argument: str) -> None:
        """Record target rules and consent through the explicit product command.

        Args:
            argument: Scope action and its full explicit CLI argument list.
        """

        self.RunLocalCommand("scope", argument)

    def do_business(self, argument: str) -> None:
        """Inspect explicit retained owner declarations without deriving facts from shell context.

        Args:
            argument: Inspect action, workspace, original definition, scope and complete model pins.
        """

        self.RunLocalCommand("business", argument)

    def do_extension(self, argument: str) -> None:
        """Validate one explicit local manifest without resolving or activating its entry points.

        Args:
            argument: Validate action, manifest path and optional JSON presentation.
        """

        self.RunLocalCommand("extension", argument)

    def do_image(self, argument: str) -> None:
        """Plan or export a local reference with the same explicit CLI authority requirements.

        Args:
            argument: Export action and full explicit selected inputs and authority arguments.
        """

        self.RunLocalCommand("image", argument)

    def do_scan(self, argument: str) -> None:
        """Run foreground endpoint or closed synthetic scans with explicit authorization.

        Args:
            argument: Scan action and its full explicit CLI argument list.
        """

        self.RunLocalCommand("scan", argument)

    def do_raw(self, argument: str) -> None:
        """Run a foreground exact-native profile or offline replay without implicit authority.

        Args:
            argument: Explicit wrapper arguments and untouched separated native token tail.
        """

        self.RunLocalCommand("raw", argument)

    def do_report(self, argument: str) -> None:
        """Export an explicitly selected saved workspace; shell context is never implicit input.

        Args:
            argument: Report action, workspace, selected format and new output path.
        """

        self.RunLocalCommand("report", argument)

    def do_bridge(self, argument: str) -> None:
        """Import or inspect saved external reports without deriving source or execution authority.

        Args:
            argument: Explicit saved-report action, file or original custody and SHA selections.
        """

        self.RunLocalCommand("bridge", argument)

    def do_trace(self, argument: str) -> None:
        """Use explicitly owned local IOC candidates without deriving authority from shell state.

        Args:
            argument: IOC action, owning workspace, source selections or independent anchors.
        """

        self.RunLocalCommand("trace", argument)

    def do_ci(self, argument: str) -> None:
        """Run an explicit current-execution finding predicate and verified report exports.

        Args:
            argument: Explicit profile, inputs, authority, criterion and three new output paths.
        """

        self.RunLocalCommand("ci", argument)

    def do_paths(self, argument: str) -> None:
        """Analyze explicit retained paths without deriving scope or selection from shell context.

        Args:
            argument: Analyze action, saved-model pins, original selections, clock and budgets.
        """

        self.RunLocalCommand("paths", argument)

    def do_sbom(self, argument: str) -> None:
        """Inspect saved inventory or import owned SPDX/CycloneDX without implicit authority.

        Args:
            argument: Explicit view/import profile, original source, image identity and owner bases.
        """

        self.RunLocalCommand("sbom", argument)

    def do_api(self, argument: str) -> None:
        """Import an explicit offline API source without deriving authority from shell context.

        Args:
            argument: Import profile, source, exact endpoint/scope and owner revision bases.
        """

        self.RunLocalCommand("api", argument)

    def do_response(self, argument: str) -> None:
        """Capture originals, separately check headers or replay without implicit authority.

        Args:
            argument: Capture, header-check or historical replay with complete explicit inputs.
        """

        self.RunLocalCommand("response", argument)

    def do_runtime(self, argument: str) -> None:
        """Import explicitly owned offline source without deriving authority from shell context.

        Args:
            argument: Import profile, selected source, existing HOST/scope and exact owner bases.
        """

        self.RunLocalCommand("runtime", argument)

    def do_intel(self, argument: str) -> None:
        """Use explicit local intelligence selections without deriving them from shell context.

        Args:
            argument: Import, inspect, preview, or apply action with complete explicit arguments.
        """

        self.RunLocalCommand("intel", argument)

    def do_demo(self, argument: str) -> None:
        """Run the explicit local demo without deriving approval from selected shell context.

        Args:
            argument: Demo action, new output root and the separate explicit SAFE approval.
        """

        self.RunLocalCommand("demo", argument)

    def do_history(self, argument: str) -> None:
        """Search local command history in reverse chronological order.

        Args:
            argument: Optional case-insensitive substring to filter local history.
        """

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
        """Select one of the initial workflow lenses.

        Args:
            argument: Supported lens name or --json; empty input lists lenses.
        """

        parts = argument.strip().lower().split()
        jsonOutput = bool(parts and parts[-1] == "--json")

        if jsonOutput:
            parts.pop()

        if len(parts) > 1:
            self.Write("usage: lens [<name>] [--json]")

            return

        lens = parts[0] if parts else ""

        if not lens and jsonOutput:
            self.Write(CanonicalModelJson(ResolveLens(self._state.lens).ToDict()).decode("utf-8"))

            return

        if not lens:
            self.Write("Available lenses: " + ", ".join(LENSES))
            return

        if lens not in LENSES:
            self.Write(f"Unknown lens: {lens}. Available lenses: " + ", ".join(LENSES))
            return

        self._state = replace(self._state, lens=lens)

        if jsonOutput:
            self.Write(CanonicalModelJson(ResolveLens(lens).ToDict()).decode("utf-8"))

            return

        self.Write(f"Selected lens: {lens}")

        if self._state.view == "model":
            self.RenderModel()

    def do_model(self, argument: str) -> None:
        """Open an explicitly named existing workspace without creating or saving model state.

        Args:
            argument: Workspace directory path; whitespace inside paths is retained.
        """

        path = argument.strip()

        if not path:
            self.Write("usage: model <workspace-path>")

            return

        try:
            state = LocalModelStore(Path(path)).Open()

        except (OSError, ValueError) as error:
            self.Write(f"Could not open model: {error}")

            return

        self.BindModel(state)
        self.Write(f"Loaded model: {state.workspace_id} at revision {state.revision}")

    def do_palette(self, argument: str) -> None:
        """Search immediately available commands and cached selected-object actions.

        Args:
            argument: Optional query over commands and cached contextual actions.
        """

        query = argument.strip()
        commandMatches = FuzzyMatches(query, SHELL_COMMANDS)
        registryMatches = tuple(
            descriptor.identifier
            for descriptor in self._registry.Search(query)
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
        """Store an opaque selected-object reference until the SOM contract exists.

        Args:
            argument: Nonempty opaque object identifier to retain in local shell state.
        """

        objectId = argument.strip()
        if not objectId:
            self.Write("usage: select <object-id>")
            return

        self._state = replace(self._state, selected_object=objectId)
        self.Write(f"Selected object: {objectId}")

    def do_updates(self, argument: str) -> None:
        """Render currently queued updates without blocking the shell.

        Args:
            argument: Empty input expected, otherwise usage is printed.
        """

        if argument.strip():
            self.Write("usage: updates")
            return

        self.RenderUpdates()

    def do_update(self, argument: str) -> None:
        """Inspect component health without conflating it with queued Workbench events.

        Args:
            argument: Empty input for human output, or --json for the versioned report.
        """

        option = argument.strip()

        if option not in ("", "--json"):
            self.Write("usage: update [--json]")

            return

        RunUpdate(self.stdout, json_output=option == "--json")

    def do_view(self, argument: str) -> None:
        """Select a presentation view and render an explicitly bound model snapshot.

        Args:
            argument: View name with optional --query file and --json for model output.
        """

        usage = "usage: view <name> [--query <file>] [--json]"

        try:
            parts = shlex.split(argument)

        except ValueError:
            self.Write(usage)

            return

        view = parts[0].lower() if parts else ""
        options = parts[1:]
        jsonOutput = False
        queryPath = None

        while options:
            option = options.pop(0).lower()

            if option == "--json" and not jsonOutput:
                jsonOutput = True

            elif (option == "--query" and queryPath is None and options
                  and options[0] and not options[0].startswith("--")):
                queryPath = Path(options.pop(0))

            else:
                self.Write(usage)

                return

        if view.startswith("--") or ((jsonOutput or queryPath is not None) and view != "model"):
            self.Write(usage)

            return

        if not view:
            self.Write("Available views: " + ", ".join(VIEWS))
            return

        if view not in VIEWS:
            self.Write(f"Unknown view: {view}. Available views: " + ", ".join(VIEWS))
            return

        if view == "model" and self._model is None:
            self.Write("No model loaded. Use model <workspace-path>.")

            return

        query = None

        if queryPath is not None:
            try:
                query = ReadLensQuery(queryPath)

            except (OSError, ValueError) as error:
                self.Write(f"Could not open lens query: {error}")

                return

        self._state = replace(self._state, view=view)

        if view == "model":
            self.RenderModel(json_output=jsonOutput, query=query)

            return

        self.Write(f"Selected view: {view}")

    def RenderModel(self, *, json_output: bool = False, query: LensQuery | None = None) -> None:
        """Render a read-only reference view; model records remain with the shared snapshot.

        Args:
            json_output: Emit the versioned reference document instead of compact terminal rows.
            query: Explicit per-render replacement; None uses the descriptor's default query.
        """

        if self._model is None:
            self.Write("No model loaded. Use model <workspace-path>.")

            return

        descriptor = ResolveLens(self._state.lens)
        projected = descriptor.Project(self._model, query)

        if json_output:
            self.Write(CanonicalModelJson(projected).decode("utf-8"))

            return

        self.Write(
            f"{descriptor.title}: {self._model.workspace_id} at revision {self._model.revision}"
        )
        references = set(projected["object_references"])

        for item in self._model.objects:
            if item.Reference() in references:
                key = "".join(
                    character if character.isprintable() else f"\\u{ord(character):04x}"
                    for character in item.identity.key
                )
                self.Write(f"{item.identity.kind.value}: {key} [{item.Reference()}]")

        self.Write(
            f"Relations: {len(projected['relation_references'])}; "
            f"observations: {len(projected['observation_references'])}"
        )

    def do_quit(self, argument: str) -> bool:
        """Leave the interactive shell.

        Args:
            argument: Empty input exits, otherwise usage is printed.

        Returns:
            True for empty input, or False when usage is printed.
        """

        if argument.strip():
            self.Write("usage: quit")
            return False

        return True

    def do_EOF(self, argument: str) -> bool:
        """Treat EOF as a normal interactive-shell exit.

        Args:
            argument: Ignored framework argument when end-of-input closes the shell.

        Returns:
            True to request normal shell termination.
        """

        self.Write("")
        return True

    def default(self, line: str) -> None:
        """Reject unknown commands without implying that a scanner ran.

        Args:
            line: Unrecognized command line included in the diagnostic.
        """

        self.Write(f"Unknown command: {line}. Type 'help' for commands.")

    def RenderUpdates(self) -> None:
        """Drain pending updates in arrival order for deterministic terminal output."""

        if not self._updates:
            return

        while self._updates:
            update = self._updates.popleft()
            self.Write(f"[{update.kind}] {update.message}")

    def MatchingContextActions(self, query: str) -> tuple[ContextualAction, ...]:
        """Return local actions for the selected object, preserving configured order.

        Args:
            query: Case-insensitive substring of action identifiers or summaries.

        Returns:
            Cached matches in configured order, or empty when no object is selected.
        """

        objectId = self._state.selected_object
        if objectId is None:
            return ()

        normalized = query.lower()
        return tuple(
            action
            for action in self._context_actions.get(objectId, ())
            if not normalized
            or normalized in action.identifier.lower()
            or normalized in action.summary.lower()
        )

    def Write(self, message: str) -> None:
        """Write one line through ``cmd.Cmd``'s configured output stream.

        Args:
            message: Text to write followed by one newline to the output stream.
        """

        self.stdout.write(f"{message}\n")


def RunInteractiveShell() -> int:
    """Run the standard-library shell in the current terminal.

    Reads the current terminal and writes output. Shell commands manage local context and
    discovery.

    Returns:
        Zero after the command loop exits normally.
    """

    shell = InteractiveShell(stdin=sys.stdin, stdout=sys.stdout)
    shell.cmdloop()
    return 0
