# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Tests for cli behavior."""

import json
import runpy
import sys
from importlib.metadata import version
from types import ModuleType

import pytest

from fuzzy1337 import cli
from fuzzy1337.cli import GetCommandRegistry, GetCommands, Main


def test_DeveloperCommandsAreRegistered():
    """Verify developer commands are registered."""

    commands = GetCommands()

    assert set(commands) == {
        "setup",
        "unit",
        "test",
        "lint",
        "typecheck",
        "performance",
        "compile",
        "build",
        "check",
    }, "developer commands are registered invariant failed."
    assert "mypy" in commands["check"], "developer commands are registered invariant failed."
    assert commands["unit"].startswith("python -m pytest tests/unit"), (
        "developer commands are registered invariant failed."
    )
    assert "fuzzy1337.coverage_gate" in commands["test"], (
        "developer commands are registered invariant failed."
    )
    assert commands["setup"] == "uv sync --locked --extra dev", (
        "developer commands are registered invariant failed."
    )
    commands["test"] = "changed by a consumer"
    assert GetCommands()["test"] != commands["test"], (
        "developer commands are registered invariant failed."
    )


def test_NoArgumentsDescribeBootstrap(capsys):
    """Verify no arguments describe bootstrap."""

    assert Main([]) == 0, "no arguments describe bootstrap invariant failed."
    output = capsys.readouterr()
    assert "1337 Security Workbench" in output.out, (
        "no arguments describe bootstrap invariant failed."
    )
    assert "1337 help" in output.out, "no arguments describe bootstrap invariant failed."
    assert "1337 --version" in output.out, "no arguments describe bootstrap invariant failed."
    assert "1337 shell" in output.out, "no arguments describe bootstrap invariant failed."
    assert "1337 doctor" in output.out, "no arguments describe bootstrap invariant failed."
    assert "1337 demo local" in output.out, "Help must expose the actual local demo command."
    assert "1337 runtime import <docker-inspect|kubernetes-list>" in output.out, (
        "Help must expose explicit owned import profiles"
    )
    assert not output.err, "no arguments describe bootstrap invariant failed."


def test_HelpCommandUsesTheCommandRegistry(capsys):
    """Verify help command uses the command registry."""

    assert Main(["help"]) == 0, "help command uses the command registry invariant failed."

    output = capsys.readouterr()
    assert "Currently available commands:" in output.out, (
        "help command uses the command registry invariant failed."
    )
    assert GetCommandRegistry().Resolve("help") is not None, (
        "help command uses the command registry invariant failed."
    )


def test_ExplicitShellCommandStartsTheInteractiveWorkbench(monkeypatch):
    """Verify explicit shell command starts the interactive workbench."""

    monkeypatch.setattr(cli, "RunInteractiveShell", lambda: 0)

    assert Main(["shell"]) == 0, (
        "explicit shell command starts the interactive workbench invariant failed."
    )


def test_DoctorCommandRunsTheDiagnosticEntrypoint(monkeypatch, capsys):
    """Verify the doctor command delegates to its diagnostic entry point."""

    def RunDoctor(output):
        """Provide deterministic doctor output without probing the host."""

        output.write("doctor output\n")
        return 0

    monkeypatch.setattr(cli, "RunDoctor", RunDoctor)

    assert Main(["doctor"]) == 0, "doctor command invariant failed."
    assert capsys.readouterr().out == "doctor output\n", "doctor command invariant failed."


@pytest.mark.parametrize(
    "arguments, code",
    [(["--version"], 0), (["--help"], 0), (["scan"], 2)],
)
def test_CliOptions(arguments, code, capsys):
    """Verify cli options."""

    with pytest.raises(SystemExit) as caught:
        Main(arguments)

    assert caught.value.code == code, "cli options invariant failed."
    output = capsys.readouterr()
    if arguments == ["--version"]:
        assert output.out.strip() == f"1337 {version('1337')}", "cli options invariant failed."


def test_PythonModuleEntrypoint(monkeypatch, capsys):
    """Verify python module entrypoint."""

    monkeypatch.setattr(sys, "argv", ["1337", "--version"])
    with pytest.raises(SystemExit) as caught:
        runpy.run_module("fuzzy1337", run_name="__main__")
    assert caught.value.code == 0, "python module entrypoint invariant failed."
    assert capsys.readouterr().out.strip() == f"1337 {version('1337')}", (
        "python module entrypoint invariant failed."
    )


@pytest.mark.parametrize("arguments", [
    ["workspace", "create"], ["workspace", "open"], ["scope", "create"], ["scan", "quick"],
    ["help", "unexpected"], ["--json", "help"],
])
def test_LocalProductNamespacesRequireExplicitInputs(arguments):
    """Missing workspace, authority or target inputs fail before a provider can start."""

    with pytest.raises(SystemExit) as caught:
        Main(arguments)

    assert caught.value.code == 2, "Incomplete operator inputs must remain parse errors."


def test_WorkspaceAndScopeCommandsNeverInferConsent(tmp_path, capsys):
    """Exercise product creation, explicit registration and authoritative reopen offline."""

    import json

    from fuzzy1337.scope import AuthorizationState, LocalScopeStore

    root = tmp_path / "workspace"
    assert Main(["workspace", "create", str(root), "--id", "fixture", "--name", "Fixture"]) == 0, (
        'Exercise product creation, explicit registration and authoritative reopen offline '
        'invariant failed.'
    )
    assert "succeeded" in capsys.readouterr().out, (
        'Exercise product creation, explicit registration and authoritative reopen offline '
        'invariant failed.'
    )
    assert Main([
        "scope", "create", str(root), "--id", "local", "--allow-url", "http://127.0.0.1/",
        "--allow-ip", "127.0.0.1", "--json",
    ]) == 0, (
        'Exercise product creation, explicit registration and authoritative reopen offline '
        'invariant failed.'
    )
    scope_document = json.loads(capsys.readouterr().out)
    assert scope_document["authorization"]["state"] == "unknown", (
        'Exercise product creation, explicit registration and authoritative reopen offline '
        'invariant failed.'
    )
    assert LocalScopeStore(root).Open("local").authorization.state is AuthorizationState.UNKNOWN, (
        'Exercise product creation, explicit registration and authoritative reopen offline '
        'invariant failed.'
    )
    assert Main(["workspace", "open", str(root), "--json"]) == 0, (
        'Exercise product creation, explicit registration and authoritative reopen offline '
        'invariant failed.'
    )
    reopened = json.loads(capsys.readouterr().out)
    assert reopened["object_counts"]["host"] == 0, "Offline creation must not invent hosts."
    assert reopened["verified_evidence_records"] == 0, (
        'Exercise product creation, explicit registration and authoritative reopen offline '
        'invariant failed.'
    )


@pytest.mark.parametrize("url", [
    "http://localhost/", "http://127.0.0.1/?token=synthetic",
    "http://operator:synthetic@127.0.0.1/", "http://127.0.0.1/#synthetic",
])
def test_ScopeCommandRejectsImplicitOrCredentialBearingEndpointRules(tmp_path, capsys, url):
    """Do not write hostname inference or credential-bearing requests into authoritative scope."""

    root = tmp_path / "workspace"
    assert Main(["workspace", "create", str(root), "--id", "fixture", "--name", "Fixture"]) == 0, (
        'Do not write hostname inference or credential-bearing requests into authoritative '
        'scope invariant failed.'
    )
    capsys.readouterr()
    assert Main(["scope", "create", str(root), "--id", "local", "--allow-url", url]) == 2, (
        'Do not write hostname inference or credential-bearing requests into authoritative '
        'scope invariant failed.'
    )
    output = capsys.readouterr().out
    assert "invalid_configuration" in output, (
        'Do not write hostname inference or credential-bearing requests into authoritative '
        'scope invariant failed.'
    )
    assert "synthetic" not in output, "Untrusted URL details must not enter diagnostics."
    assert not (root / "state" / "scopes" / "local.json").exists(), (
        'Do not write hostname inference or credential-bearing requests into authoritative '
        'scope invariant failed.'
    )


def test_ExplicitConsentRequiresActorRecordAndValidityBeforeMutation(tmp_path):
    """A grant flag without its concrete authorization metadata cannot create local state."""

    root = tmp_path / "absent"

    with pytest.raises(SystemExit) as caught:
        Main(["scope", "create", str(root), "--id", "local", "--allow-ip", "127.0.0.1",
              "--grant-consent"])

    assert caught.value.code == 2, (
        'A grant flag without its concrete authorization metadata cannot create local state '
        'invariant failed.'
    )
    assert not root.exists(), "Incomplete consent must not mutate even an absent workspace."


def test_MissingWorkspaceAndInvalidScanBoundsAreTruthfulStructuredErrors(tmp_path, capsys):
    """Preserve failed local setup and reject scanner resource controls before acquisition."""

    assert Main(["workspace", "open", str(tmp_path / "absent"), "--json"]) in (2, 4), (
        'Preserve failed local setup and reject scanner resource controls before '
        'acquisition invariant failed.'
    )
    assert '"state": "failed"' in capsys.readouterr().out, (
        'Preserve failed local setup and reject scanner resource controls before '
        'acquisition invariant failed.'
    )
    root = tmp_path / "workspace"
    assert Main(["workspace", "create", str(root), "--id", "fixture", "--name", "Fixture"]) == 0, (
        'Preserve failed local setup and reject scanner resource controls before '
        'acquisition invariant failed.'
    )
    capsys.readouterr()
    assert Main([
        "scope", "create", str(root), "--id", "local", "--allow-url", "http://127.0.0.1/",
        "--allow-ip", "127.0.0.1",
    ]) == 0, (
        'Preserve failed local setup and reject scanner resource controls before '
        'acquisition invariant failed.'
    )
    capsys.readouterr()
    assert Main([
        "scan", "quick", str(root), "--scope", "local", "--owner", "operator:fixture",
        "--target", "http://127.0.0.1/", "--max-endpoints", "100", "--json",
    ]) == 2, (
        'Preserve failed local setup and reject scanner resource controls before '
        'acquisition invariant failed.'
    )
    assert "invalid_configuration" in capsys.readouterr().out, (
        'Preserve failed local setup and reject scanner resource controls before '
        'acquisition invariant failed.'
    )


def test_QuickScanOutputModesCannotBeAmbiguous(tmp_path):
    """Select one summary or JSON-line protocol before any provider or workspace read."""

    with pytest.raises(SystemExit) as caught:
        Main([
            "scan", "quick", str(tmp_path / "absent"), "--scope", "local", "--owner", "operator:x",
            "--target", "http://127.0.0.1/", "--json", "--events-json",
        ])

    assert caught.value.code == 2, (
        'Select one summary or JSON-line protocol before any provider or workspace read '
        'invariant failed.'
    )


@pytest.mark.parametrize("foreign", [False, True])
def test_ProductReopenRejectsTamperedOrForeignAcquisition(tmp_path, capsys, foreign):
    """Authoritative reopening must verify actual retained bytes and their workspace ownership."""

    from dataclasses import replace
    from datetime import UTC, datetime

    from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
    from fuzzy1337.workspace import LocalWorkspaceStore

    root = tmp_path / "workspace"
    assert Main(["workspace", "create", str(root), "--id", "fixture", "--name", "Fixture"]) == 0, (
        "The isolated product workspace must be initialized before acquisition testing."
    )
    capsys.readouterr()
    now = datetime.now(UTC).isoformat()
    record = LocalEvidenceStore(root / "evidence").Put(
        b"safe-fixture", "stdout", "text/plain", EvidenceProvenance(
            "foreign" if foreign else "fixture", "scope:local", "native.http", "1", "1", now, now,
        ),
    )
    store = LocalWorkspaceStore(root)
    store.Save(replace(store.Open(), evidence_record_references=(record.evidence_id,)))

    if not foreign:
        (root / "evidence" / record.reference.locator).write_bytes(b"tampered-fixture")

    assert Main(["workspace", "open", str(root), "--json"]) in (2, 4), (
        "Corrupt bytes or foreign workspace provenance must block successful product reopen."
    )
    assert '"state": "failed"' in capsys.readouterr().out, (
        "Integrity failure must remain an explicit machine-readable failure."
    )


@pytest.mark.parametrize("arguments, expected", [
    (["scan", "quick", "--help"], "--approve-safe-http"),
    (["scope", "create", "--help"], "--grant-consent"),
    (["workspace", "create", "--help"], "--name"),
])
def test_ProductHelpDescribesSelectedActionWithoutReadingWorkspace(arguments, expected, capsys):
    """Nested help must expose actual bounded command arguments before local setup or execution."""

    with pytest.raises(SystemExit) as caught:
        Main(arguments)

    assert caught.value.code == 0, "Command help must exit normally before any local state read."
    assert expected in capsys.readouterr().out, "Help must describe the selected product action."


def test_LocalDemoTopLevelDispatchHasExplicitApprovalAndSelectedHelp(tmp_path, capsys):
    """CLI help and a denied plan must remain useful without starting or creating resources."""

    assert Main(["demo", "local", "--help"]) == 0, "Demo help must be available before setup."
    assert "--approve-safe-http" in capsys.readouterr().out, "Help must name the separate approval."
    root = tmp_path / "demo"
    assert Main(["demo", "local", str(root), "--json"]) == 3, "Default demo must fail closed."
    assert '"state": "denied"' in capsys.readouterr().out, "JSON must describe the actual denial."
    assert not root.exists(), "A displayed plan must not create a filesystem root."


@pytest.mark.parametrize("help_requested", [False, True])
def test_TraceNamespaceForwardsOnlyExplicitSelectionsAndPreservesStatus(monkeypatch,
                                                                      help_requested, capsys):
    """The central route adds no source, receipt, scope or consent defaults to IOC dispatch."""

    module = ModuleType("fuzzy1337.ioc_commands")
    calls = []

    def ObserveInvocation(arguments, output, *, json_output=False):
        """Record the exact route-owned argv and return a consumer interruption status."""

        calls.append((arguments, json_output))
        output.write("owned-summary-only\n")

        return 130

    module.RunIocCommands = ObserveInvocation
    monkeypatch.setitem(sys.modules, module.__name__, module)
    selected = ["ioc", "inspect", "Owned Workspace", "--snapshot", "sha256:" + "1" * 64,
                "--receipt", "sha256:" + "2" * 64]
    argv = ["trace", *selected, "--json"]

    if help_requested:
        argv.append("--help")

    assert Main(argv) == 130, "The central route must retain the IOC consumer's actual status."
    assert calls == [(selected + (["--help"] if help_requested else []), True)], (
        "IOC dispatch receives only explicitly selected arguments and the requested output mode."
    )
    assert capsys.readouterr().out == "owned-summary-only\n", (
        "The central route cannot reconstruct or decorate candidate acquisition output."
    )


@pytest.mark.parametrize("status", [0, 2, 4, 130])
def test_RuntimeRoutePreservesExplicitArgumentsOutputAndHandlerStatus(monkeypatch, capsys, status):
    """Actual top-level registration delegates exact supplied values without ambient authority."""

    from fuzzy1337 import runtime_commands

    calls = []

    def RunRuntimeCommands(arguments, output, *, json_output):
        """Observe exact registration forwarding without opening a workspace or source."""

        calls.append((arguments, json_output))
        output.write("owned-runtime-outcome\n")

        return status

    monkeypatch.setattr(runtime_commands, "RunRuntimeCommands", RunRuntimeCommands)
    assert Main(["runtime", "import", "docker-inspect", "explicit workspace", "--json"]) == (
        status
    ), "Registered runtime route replaced the actual handler status"
    assert calls == [(["import", "docker-inspect", "explicit workspace"], True)], (
        "Registration inferred, omitted or reordered explicit caller selections"
    )
    assert capsys.readouterr().out == "owned-runtime-outcome\n", "Registered outcome was changed"


def test_RuntimeRegisteredHelpAndGrammarRefusalNeedNoLocalState(capsys):
    """Static import help and safe invalid grammar are available before workspace setup."""

    assert Main(["runtime", "import", "--help"]) == 0, "Runtime static help failed"
    help_text = capsys.readouterr().out
    assert "--read-consent-reference" in help_text and "--expected-workspace-revision" in (
        help_text
    ), "Runtime help omitted the explicit original source and owner bases"
    assert Main(["runtime", "SYNTHETIC_PRIVATE_MARKER", "--json"]) == 2, "Unknown profile passed"
    output = capsys.readouterr()
    assert json.loads(output.out)["failure"] == "configuration" and not output.err and (
        "SYNTHETIC_PRIVATE_MARKER" not in output.out
    ), "Registered grammar refusal exposed rejected values"


@pytest.mark.parametrize("status", [0, 2, 4, 130])
def test_ApiRoutePreservesExplicitArgumentsOutputAndHandlerStatus(monkeypatch, capsys, status):
    """Actual top-level registration delegates exact supplied values without ambient authority."""

    from fuzzy1337 import api_commands

    calls = []

    def RunApiCommands(arguments, output, *, json_output):
        """Observe exact registration forwarding without opening a workspace or source."""

        calls.append((arguments, json_output))
        output.write("owned-api-outcome\n")

        return status

    monkeypatch.setattr(api_commands, "RunApiCommands", RunApiCommands)
    assert Main(["api", "import", "graphql-introspection", "explicit workspace", "--json"]) == (
        status
    ), "Registered api route replaced the actual handler status"
    assert calls == [(["import", "graphql-introspection", "explicit workspace"], True)], (
        "Registration inferred, omitted or reordered explicit caller selections"
    )
    assert capsys.readouterr().out == "owned-api-outcome\n", "Registered outcome was changed"



def test_ApiRegisteredHelpAndGrammarRefusalNeedNoLocalState(capsys):
    """The original source and exact owner bases remain visible before workspace setup."""

    assert Main(["api", "import", "--help"]) == 0, "API static help failed"
    help_text = capsys.readouterr().out
    assert "--read-consent-reference" in help_text and "--expected-workspace-revision" in (
        help_text
    ) and "--endpoint" in help_text, "API help omitted original source or selected owner bases"
    assert Main(["api", "SYNTHETIC_PRIVATE_MARKER", "--json"]) == 2, "Unknown API grammar passed"
    output = capsys.readouterr()
    assert json.loads(output.out)["failure"] == "configuration" and not output.err and (
        "SYNTHETIC_PRIVATE_MARKER" not in output.out
    ), "API grammar refusal exposed rejected source selections"


@pytest.mark.parametrize("status", [0, 2, 4, 130])
def test_SbomRoutePreservesExplicitArgumentsOutputAndHandlerStatus(monkeypatch, capsys, status):
    """Actual top-level registration delegates exact supplied values without ambient authority."""

    from fuzzy1337 import sbom_commands

    calls = []

    def RunSbomCommands(arguments, output, *, json_output):
        """Observe exact registration forwarding without opening a workspace or source."""

        calls.append((arguments, json_output))
        output.write("owned-sbom-outcome\n")

        return status

    monkeypatch.setattr(sbom_commands, "RunSbomCommands", RunSbomCommands)
    assert Main(["sbom", "import", "spdx-graph", "explicit workspace", "--json"]) == (
        status
    ), "Registered sbom route replaced the actual handler status"
    assert calls == [(["import", "spdx-graph", "explicit workspace"], True)], (
        "Registration inferred, omitted or reordered explicit caller selections"
    )
    assert capsys.readouterr().out == "owned-sbom-outcome\n", "Registered outcome was changed"


def test_SbomRegisteredHelpAndGrammarRefusalNeedNoLocalState(capsys):
    """Original source and declared image semantics are visible before local workspace setup."""

    assert Main(["sbom", "import", "--help"]) == 0, "SBOM static help failed"
    help_text = capsys.readouterr().out
    assert "--read-consent-reference" in help_text and "--expected-workspace-revision" in (
        help_text
    ) and "--image-digest-kind" in help_text, "SBOM help omitted explicit source or image bases"
    assert Main(["sbom", "SYNTHETIC_PRIVATE_MARKER", "--json"]) == 2, "Unknown SBOM grammar passed"
    output = capsys.readouterr()
    assert json.loads(output.out)["failure"] == "configuration" and not output.err and (
        "SYNTHETIC_PRIVATE_MARKER" not in output.out
    ), "SBOM grammar refusal exposed rejected source values"
