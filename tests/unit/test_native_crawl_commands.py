# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Shared CLI/shell crawl enrollment with real SDK owners and controlled executor transport."""

from __future__ import annotations

import io
import json
import shlex

import pytest

from fuzzy1337 import native_crawl_workflow as product
from fuzzy1337.adapters import SerializeContract
from fuzzy1337.cli import Main
from fuzzy1337.command_registry import COMMAND_REGISTRY
from fuzzy1337.model import LocalModelStore
from fuzzy1337.shell import InteractiveShell
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.unit.test_native_crawl_workflow import AT, SEED, URLS
from tests.unit.test_native_crawl_workflow import owned as owned


def Arguments(root):
    """Select all original explicit inputs without implicit shell state or approval."""

    values = ["scan", "crawl", str(root), "--seed", SEED]

    for url in URLS:
        values.extend(("--selected", url))

    return [*values, "--scope", "local", "--owner", "actor:operator",
            "--policy", str(root / "current-policy.json")]


@pytest.fixture
def crawl_cli(owned, monkeypatch):
    """Delegate actual SDK calls with only the same deterministic clock as the executor double."""

    (owned.root / "current-policy.json").write_text(SerializeContract(owned.policy),
                                                  encoding="utf-8")
    plan, run = product.PlanNativeCrawl, product.RunNativeCrawl

    def Plan(*args, **kwargs):
        """Preserve actual original planning with a deterministic current decision clock."""

        kwargs["clock"] = lambda: AT

        return plan(*args, **kwargs)

    async def Run(*args, **kwargs):
        """Delegate actual SDK/job/model/evidence behavior without a fabricated success."""

        kwargs["clock"] = lambda: AT

        return await run(*args, **kwargs)

    monkeypatch.setattr(product, "PlanNativeCrawl", Plan)
    monkeypatch.setattr(product, "RunNativeCrawl", Run)

    return owned


@pytest.mark.parametrize("flag", ("--seed", "--selected", "--scope", "--owner", "--policy"))
def test_CrawlRequiresEveryExplicitInputBeforeWorkspaceRead(tmp_path, flag):
    """No current permission, seed or admitted set may come from a shell-selected object."""

    root = tmp_path / "absent"
    args = Arguments(root)

    while flag in args:
        index = args.index(flag)
        del args[index:index + 2]

    with pytest.raises(SystemExit) as caught:
        Main(args)

    assert caught.value.code == 2 and not root.exists(), (
        "Missing independent crawl inputs must refuse before acquisition or persistent state."
    )


def test_InstalledCommandHelpRegistryAndShellListTheActualCrawlAction(capsys):
    """All foreground discoverability owners describe the same selected action and approval."""

    with pytest.raises(SystemExit) as caught:
        Main(["scan", "crawl", "--help"])

    assert caught.value.code == 0, "Nested crawl help must need no workspace or policy."
    help_text = capsys.readouterr().out
    assert all(flag in help_text for flag in (
        "--seed", "--selected", "--approve-safe-crawl", "--policy", "--request-timeout-ms",
    )), "Selected action help must describe independent authority and finite limits."
    descriptor = COMMAND_REGISTRY.Resolve("scan")
    assert "crawl" in descriptor.usage and "http.owned-loopback-crawl" in descriptor.capabilities, (
        "Registry and installed CLI must expose the same existing owned-loopback capability."
    )
    output = io.StringIO()
    InteractiveShell(stdout=output).onecmd("help scan")
    assert "crawl" in output.getvalue() and "--approve-safe-crawl" in output.getvalue(), (
        "The foreground shell must advertise the explicit crawl opt-in without executing it."
    )


def test_ActualCliPlanIsReadOnlyAndDoesNotIssueGrant(crawl_cli, monkeypatch, capsys):
    """CLI plans join current complete authority but never call the execution grant owner."""

    def Grant(*args, **kwargs):
        """Reject any attempted execution permission in a descriptive CLI planning call."""

        pytest.fail("Crawl --plan must not issue an execution grant")

    from fuzzy1337.policy import PolicyEngine

    monkeypatch.setattr(PolicyEngine, "Authorize", Grant)
    assert Main([*Arguments(crawl_cli.root), "--plan", "--json"]) == 0, (
        "An explicit current scope/policy selection must produce a descriptive plan."
    )
    document = json.loads(capsys.readouterr().out)
    assert document["state"] == "planned" and not document["execution_authorized"], document
    assert len(document["invocations"]) == len(URLS) and not crawl_cli.calls, (
        "Planning the admitted selection must not schedule any source, reachable or otherwise."
    )
    assert LocalWorkspaceStore(crawl_cli.root).Open() == crawl_cli.workspace, (
        "CLI planning must preserve the original canonical workspace revision."
    )


@pytest.mark.parametrize("mode", ("json", "text", "events"))
def test_ActualCliAndForegroundShellUseTheSameSafeSdkBoundary(crawl_cli, capsys, mode):
    """Real command routing preserves sorted source-only SDK persistence and original records."""

    options = ["--events-json"] if mode == "events" else ["--json"] if mode == "json" else []
    assert Main([*Arguments(crawl_cli.root), "--approve-safe-crawl", *options]) == 0, (
        "Explicit approved crawl must traverse through the real SDK/model/evidence owners."
    )
    rendered = capsys.readouterr().out

    if mode == "json":
        document = json.loads(rendered)

    elif mode == "events":
        lines = [json.loads(line) for line in rendered.splitlines()]
        assert all(item["type"] == "event" for item in lines[:-1]), (
            "Structured output preserves original safe ordered events before one final summary."
        )
        document = lines[-1]["summary"]

    else:
        assert "Native crawl completed; committed pages 4" in rendered, rendered
        document = None

    if document is not None:
        assert document["state"] == "completed" and len(document["completed_urls"]) == 4, document
        assert "findings" not in document and document["custody_status"] == "complete", (
            "Source-only acquisition cannot claim a security assessment or fabricate Findings."
        )

    output = io.StringIO()
    shell = InteractiveShell(stdout=output)
    shell.onecmd(shlex.join([*Arguments(crawl_cli.root), "--approve-safe-crawl"]))
    assert "Native crawl completed" in output.getvalue(), output.getvalue()
    assert LocalModelStore(crawl_cli.root).Open().revision == crawl_cli.model.revision + 8, (
        "CLI and shell each commit exactly the same four actual source pages."
    )
    assert LocalWorkspaceStore(crawl_cli.root).Open().revision == 2, (
        "Each foreground SDK attempt must use one original workspace Save."
    )


@pytest.mark.parametrize("mode,status", (
    ("no-approval", 3), ("invalid-limit", 2), ("missing-policy", 3), ("missing-workspace", 2),
))
def test_CliRefusesMissingApprovalInvalidBoundsAndUnavailablePolicy(
    crawl_cli, capsys, mode, status,
):
    """Safe defaults cannot become execution permission or a silent alternate provider."""

    args = Arguments(crawl_cli.root)

    if mode != "no-approval":
        args.append("--approve-safe-crawl")

    if mode == "invalid-limit":
        args.extend(("--max-body-bytes", "65537"))

    if mode == "missing-policy":
        args[args.index("--policy") + 1] = str(crawl_cli.root / "absent.json")

    if mode == "missing-workspace":
        args[2] = str(crawl_cli.root / "absent")

    assert Main([*args, "--json"]) == status, "Each refusal must preserve its owning exit category."
    document = json.loads(capsys.readouterr().out)
    assert document["state"] == "failed" and not crawl_cli.calls, document
    assert LocalModelStore(crawl_cli.root).Open() == crawl_cli.model, (
        "Invalid or denied command inputs must leave canonical model state unchanged."
    )


@pytest.mark.parametrize("flags", (
    ("--plan", "--approve-safe-crawl"), ("--plan", "--events-json"),
    ("--events-json", "--json"), ("--target", "private-rejected-marker"),
))
def test_AmbiguousOrForeignFlagsRefuseWithoutEchoOrContact(crawl_cli, capsys, flags):
    """No plan/grant ambiguity, raw secret-bearing diagnostic or legacy check flag is accepted."""

    with pytest.raises(SystemExit) as caught:
        Main([*Arguments(crawl_cli.root), *flags])

    output = capsys.readouterr()
    assert caught.value.code == 2 and not crawl_cli.calls, (
        "Ambiguous/foreign product arguments must be rejected before planning or acquisition."
    )
    assert "private-rejected-marker" not in output.out + output.err, (
        "Sanitized product diagnostics cannot reflect a rejected source-like raw argument."
    )


def test_ActualWorkspaceIoFailureRemainsStorageWithoutRawDiagnostic(crawl_cli, monkeypatch, capsys):
    """Unavailable canonical I/O differs from a missing/invalid workspace configuration."""

    def Open(_self):
        """Model an actual current workspace read failure without changing canonical files."""

        raise OSError("private-storage-diagnostic")

    monkeypatch.setattr(LocalWorkspaceStore, "Open", Open)
    assert Main([*Arguments(crawl_cli.root), "--approve-safe-crawl", "--json"]) == 4, (
        "Actual canonical storage I/O failure must retain its existing storage exit category."
    )
    output = capsys.readouterr().out
    assert json.loads(output)["failure"]["code"] == "storage" and not crawl_cli.calls, output
    assert "private-storage-diagnostic" not in output, (
        "Raw I/O diagnostics must not enter summaries."
    )
