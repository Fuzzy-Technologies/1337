# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise first-party web detection through the actual CLI and foreground shell."""

from __future__ import annotations

import hashlib
import json
import shlex
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import StringIO
from pathlib import Path
from threading import Thread

import pytest

from fuzzy1337.adapters import ImpactLevel, SerializeContract
from fuzzy1337.adapters.native_web import (
    NATIVE_DIRECTORY_INDEX_CAPABILITY,
    NATIVE_FILE_CANARY_CAPABILITY,
    NATIVE_FILE_CANARY_CHECK_ID,
    NATIVE_HTML_REFLECTION_CAPABILITY,
    NATIVE_HTML_REFLECTION_CHECK_ID,
    NATIVE_PROMETHEUS_CAPABILITY,
    NATIVE_SQL_BOOLEAN_SAMPLE_CAPABILITY,
    NATIVE_SQL_BOOLEAN_SAMPLE_CHECK_ID,
)
from fuzzy1337.cli import Main
from fuzzy1337.findings import Findings
from fuzzy1337.model import LocalModelStore
from fuzzy1337.native_web import NATIVE_WEB_CAPABILITY, NATIVE_WEB_PROVIDER_ID
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy
from fuzzy1337.scan_commands import RunCommands
from fuzzy1337.shell import InteractiveShell
from tests.web_file_access_helpers import OwnedWebFileAccessTarget
from tests.web_vulnerability_helpers import Oracle, OwnedWebVulnerabilityTarget


def Setup(root: Path, url: str, *, check: str = "git-head-exposure") -> list[str]:
    """Create explicit local scope and serialized capability policy through product commands."""

    output = StringIO()
    assert RunCommands("workspace", ["create", str(root), "--id", "native-cli",
        "--name", "Owned native CLI acceptance"], output) == 0, "Workspace creation failed."
    now = datetime.now(UTC)
    scopeFlag = "--allow-canary-url" if check == "file-canary-disclosure" else "--allow-url"
    scopeArguments = ["create", str(root), "--id", "local", scopeFlag, url,
        "--allow-ip", "127.0.0.1", "--grant-consent", "--owner", "operator:owned",
        "--consent-reference", "consent:owned-native-cli",
        "--valid-from", (now - timedelta(minutes=1)).isoformat(),
        "--valid-until", (now + timedelta(minutes=10)).isoformat()]
    assert RunCommands("scope", scopeArguments, output) == 0, "Explicit scope creation failed."
    capability = {
        "git-head-exposure": NATIVE_WEB_CAPABILITY,
        "file-canary-disclosure": NATIVE_FILE_CANARY_CAPABILITY,
        "prometheus-exposition": NATIVE_PROMETHEUS_CAPABILITY,
        "directory-index": NATIVE_DIRECTORY_INDEX_CAPABILITY,
        "html-reflection": NATIVE_HTML_REFLECTION_CAPABILITY,
        "sql-boolean-sample": NATIVE_SQL_BOOLEAN_SAMPLE_CAPABILITY,
    }[check]
    policy = ImpactPolicy("owned-native-web", maximum_impact=ImpactLevel.STANDARD,
        permissions=(CapabilityPermission(capability, NATIVE_WEB_PROVIDER_ID,
                                           ImpactLevel.STANDARD),))
    policyPath = root / "native-policy.json"
    policyPath.write_text(SerializeContract(policy), encoding="utf-8")

    return ["web", str(root), "--check", check, "--scope", "local",
        "--owner", "operator:owned", "--target", url, "--policy", str(policyPath)]


def Plan(arguments: list[str]) -> dict:
    """Obtain the real read-only plan with a machine-readable intent digest."""

    output = StringIO()
    assert RunCommands("scan", [*arguments, "--plan"], output) == 0, "Planning failed."

    return json.loads(output.getvalue())


def Confirm(arguments: list[str], plan: dict) -> list[str]:
    """Use the existing policy intent hash and a separate explicit confirmation reference."""

    return [*arguments, "--confirm-plan", plan["policy_plan"]["intent_sha256"],
        "--confirmation-reference", "approval:owned-native-cli"]


def AssertNativeResponseHtml(root: Path, expected: str, capsys) -> None:
    """Exercise offline product export with a real stored response and verified artifacts."""

    capsys.readouterr()
    destination = root.parent / f"{root.name}.html"
    assert Main(["report", "export", str(root), "--format", "html",
                 "--output", str(destination), "--json"]) == 0, (
        "The product could not export its retained native response."
    )
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["verified_retained_acquisitions"] == 2, (
        "Report export must verify both retained worker streams."
    )
    rendered = destination.read_text(encoding="utf-8")
    assert "<h3>Selected native response observations</h3>" in rendered and expected in rendered, (
        "The offline report must expose the exact supported observation in the default view."
    )


def test_CanaryScopeFlagsKeepExplicitAllowAndExclusion(tmp_path):
    """Dedicated registration preserves full query targets and explicit exclusion rules."""

    root = tmp_path / "workspace"
    output = StringIO()
    assert RunCommands("workspace", ["create", str(root), "--id", "native-cli",
        "--name", "Closed scope registration"], output) == 0, "Workspace creation failed."
    output.seek(0)
    output.truncate()
    url = "http://127.0.0.1/files/vulnerable?name=..%2Fprivate%2Fcanary.txt"
    assert RunCommands("scope", ["create", str(root), "--id", "local",
        "--allow-canary-url", url, "--exclude-canary-url", url], output,
        json_output=True) == 0, (
            "Dedicated closed-profile registration failed."
        )
    scope = json.loads(output.getvalue())
    expected = [{"kind": "url", "value": url}]
    assert scope["targets"] == scope["allow"] == scope["exclusions"] == expected, (
        "Registration changed the exact selected allow/exclusion URL."
    )


@pytest.mark.parametrize("flag", ["--allow-canary-url", "--exclude-canary-url",
                                  "--allow-url", "--exclude-url"])
@pytest.mark.parametrize("url", [
    "http://127.0.0.1/files/vulnerable?name=..%2fprivate%2fcanary.txt",
    "http://192.0.2.1/files/vulnerable?name=..%2Fprivate%2Fcanary.txt",
    "http://127.0.0.1/other?name=..%2Fprivate%2Fcanary.txt",
])
def test_CanaryScopeFlagsRefuseOutOfProfileAndKeepGenericQueryRefusal(tmp_path, flag, url):
    """New flags stay closed while generic flags continue refusing every supplied query."""

    root = tmp_path / "workspace"
    output = StringIO()
    assert RunCommands("workspace", ["create", str(root), "--id", "native-cli",
        "--name", "Closed scope rejection"], output) == 0, "Workspace creation failed."
    assert RunCommands("scope", ["create", str(root), "--id", "local",
        "--allow-ip", "127.0.0.1", flag, url], output) == 2, (
            "Scope registration admitted an unsupported raw query URL."
        )


def test_NativeWebCliRequiresConfirmationThenPersistsARealFinding(tmp_path, capsys):
    """Deny before contact, then execute the first-party worker and reopen its canonical Finding."""

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as service:
        root = tmp_path / "workspace with spaces"
        arguments = Setup(root, service.Url("git-exposed"))
        before = service.Observe()
        plan = Plan(arguments)
        assert service.Observe() == before, "Read-only planning contacted the target."
        assert Main(["scan", *arguments, "--json"]) == 3, "Unconfirmed STANDARD work ran."
        denied = json.loads(capsys.readouterr().out)
        assert denied["state"] == "failed", "Denial must retain a truthful failure state."
        assert service.Observe() == before, "Missing confirmation allowed a network request."
        assert Main(["scan", *Confirm(arguments, plan), "--json"]) == 0, (
            "The confirmed first-party CLI failed its owned positive case."
        )
        summary = json.loads(capsys.readouterr().out)
        assert summary["state"] == "completed", "A successful worker did not complete its job."
        findings = Findings(LocalModelStore(root).Open())
        assert len(findings) == 1 and findings[0].check_id == "native.git-head-exposure", (
            "Native detection must create the canonical first-party Finding."
        )
        assert Main(["workspace", "open", str(root), "--json"]) == 0, (
            "Actual workspace reopening failed to verify retained acquisitions."
        )
        capsys.readouterr()


def test_NativeWebForegroundShellUsesTheSamePlanAndExecution(tmp_path):
    """The foreground shell dispatches the same first-party check without a second scan engine."""

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as service:
        root = tmp_path / "workspace"
        arguments = Setup(root, service.Url("git-fixed"))
        plan = Plan(arguments)
        output = StringIO()
        shell = InteractiveShell(stdin=StringIO(), stdout=output)
        assert not shell.onecmd(shlex.join(["scan", *Confirm(arguments, plan), "--json"])), (
            "The foreground scan must keep the interactive shell alive."
        )
        summary = json.loads(output.getvalue())
        assert summary["state"] == "completed" and not Findings(LocalModelStore(root).Open()), (
            "The fixed route must complete the finite predicate without a false Finding."
        )
        assert shell.lastcmd == "scan", "Shell history must retain only the scan namespace."


def test_CanaryCliRequiresExactConfirmationAndReopensItsFinding(tmp_path, capsys):
    """The installed CLI exposes the closed owned check through the existing confirmation owner."""

    with OwnedWebFileAccessTarget(tmp_path / "target") as service:
        root = tmp_path / "workspace"
        arguments = Setup(root, service.Url("private-traversal"), check="file-canary-disclosure")
        before = service.Observe()
        plan = Plan(arguments)
        assert plan["check_id"] == NATIVE_FILE_CANARY_CHECK_ID, "CLI selected a different check."
        assert service.Observe() == before, "CLI planning contacted the owned target."
        assert Main(["scan", *arguments, "--json"]) == 3, "Unconfirmed local canary work ran."
        capsys.readouterr()
        assert service.Observe() == before, "Missing confirmation caused target contact."
        assert Main(["scan", *Confirm(arguments, plan), "--json"]) == 0, (
            "The explicitly confirmed closed canary CLI failed."
        )
        result = json.loads(capsys.readouterr().out)
        assert result["check_id"] == NATIVE_FILE_CANARY_CHECK_ID, "Summary lost check identity."
        findings = Findings(LocalModelStore(root).Open())
        assert len(findings) == 1 and findings[0].check_id == NATIVE_FILE_CANARY_CHECK_ID, (
            "Actual canary execution did not persist its canonical Finding."
        )
        assert Main(["workspace", "open", str(root), "--json"]) == 0, (
            "CLI reopen failed to verify the original canary execution evidence."
        )
        capsys.readouterr()


@pytest.mark.parametrize("mutation", ["lowercase-escape", "extra-query", "other-path", "remote"])
def test_CanaryCliRefusesRawInputsBeforeCanonicalizationOrContact(tmp_path, capsys, mutation):
    """Raw malformed spelling and out-of-pack destinations cannot hide behind Target rewriting."""

    with OwnedWebFileAccessTarget(tmp_path / "target") as service:
        original = service.Url("private-traversal")
        arguments = Setup(tmp_path / "workspace", original, check="file-canary-disclosure")
        changed = original

        if mutation == "lowercase-escape":
            changed = original.replace("%2F", "%2f")

        elif mutation == "extra-query":
            changed += "&extra=hello.txt"

        elif mutation == "other-path":
            changed = original.replace("/files/vulnerable", "/other")

        else:
            changed = original.replace("127.0.0.1", "192.0.2.1")

        arguments[arguments.index("--target") + 1] = changed
        before = service.Observe()
        assert Main(["scan", *arguments, "--plan", "--json"]) == 2, (
            "The raw CLI admitted an input outside its exact local request profile."
        )
        capsys.readouterr()
        assert service.Observe() == before, "Refused raw input caused an owned target request."


@pytest.mark.parametrize("extra", [
    ["--confirm-plan", "a" * 64],
    ["--confirmation-reference", "approval:owned"],
    ["--plan", "--confirm-plan", "a" * 64, "--confirmation-reference", "approval:owned"],
    ["--plan", "--events-json"],
    ["--events-json", "--json"],
])
def test_NativeWebCliRejectsAmbiguousConfirmationWithoutContact(tmp_path, extra):
    """Reject incomplete or conflicting confirmation/output modes at the argument boundary."""

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as service:
        arguments = Setup(tmp_path / "workspace", service.Url("git-exposed"))
        before = service.Observe()

        with pytest.raises(SystemExit) as error:
            Main(["scan", *arguments, *extra])

        assert error.value.code == 2, "Invalid command combinations must exit with usage status."
        assert service.Observe() == before, "Invalid CLI arguments must prevent target contact."


def test_NativeWebCliStreamsActualEventsAndTerminalSummary(tmp_path):
    """Separate event records from the terminal summary without copying transient HTTP bytes."""

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as service:
        arguments = Setup(tmp_path / "workspace", service.Url("git-exposed"))
        output = StringIO()
        assert RunCommands("scan", [*Confirm(arguments, Plan(arguments)), "--events-json"],
                           output) == 0, "The confirmed event-stream workflow failed."
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        assert records[-1]["type"] == "summary", "The stream lost its terminal summary."
        assert records[-1]["summary"]["state"] == "completed", "Terminal state is inconsistent."
        assert any(record["type"] == "event" for record in records), "No real job events emitted."
        assert "refs/heads/owned-fixture" not in output.getvalue(), (
            "Transient Git HEAD response material leaked into CLI presentation."
        )


@pytest.mark.parametrize("url", ["http://127.0.0.1", "http://127.0.0.1:80/",
                                "HTTP://127.0.0.1/"])
def test_NativeWebCliRefusesCanonicalizingRawSelectedUrls(tmp_path, url):
    """Raw operator spelling must be validated before Target canonicalization can hide drift."""

    arguments = Setup(tmp_path / "workspace", "http://127.0.0.1/")
    arguments[arguments.index("--target") + 1] = url
    output = StringIO()
    assert RunCommands("scan", [*arguments, "--plan"], output) == 2, (
        "The native CLI silently canonicalized an unsupported selected URL spelling."
    )
    assert json.loads(output.getvalue())["failure"]["code"] == "invalid_configuration", (
        "Raw spelling refusal must retain the invalid-input classification."
    )


@pytest.mark.parametrize("case", [case for case in Oracle()["cases"]
                                  if case["family"] == "reflection"], ids=lambda case: case["id"])
def test_NativeReflectionRecordsOnlyTheOwnedLexicalObservation(tmp_path, capsys, case):
    """Exercise the real worker and persist an observation independently of XSS confirmation."""

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as service:
        root = tmp_path / "workspace"
        args = Setup(root, service.Url(case), check="html-reflection")
        plan = Plan(args)
        assert not service.Observe()["requests"], "Read-only planning contacted the target."
        assert Main(["scan", *args, "--json"]) == 3, "Unconfirmed HTML reflection ran."
        capsys.readouterr()
        assert not service.Observe()["requests"], "Denied work contacted the target."
        assert Main(["scan", *Confirm(args, plan), "--json"]) == 0, (
            "Confirmed native reflection must complete on valid owned HTML."
        )
        result = json.loads(capsys.readouterr().out)
        assert result["check_id"] == NATIVE_HTML_REFLECTION_CHECK_ID, "Check identity drifted."
        model = LocalModelStore(root).Open()
        assert not Findings(model), "An inert lexical probe cannot establish an XSS Finding."
        observed = [item for item in model.observations
                    if item.kind == "native.web-response-check"]
        assert len(observed) == 1 and observed[0].attributes["matched"] is case["expected_match"], (
            "The owned positive, fixed and decoy oracles must match the recorded observation."
        )
        assert service.Observe()["requests"] == [case["route"]], "One exact contact is required."
        assert Main(["workspace", "open", str(root), "--json"]) == 0, (
            "Reopening must verify the original worker acquisitions."
        )
        expected = "Lexical marker observed" if case["expected_match"] else (
            "Lexical marker not observed"
        )
        AssertNativeResponseHtml(root, expected, capsys)
        assert service.Observe()["requests"] == [case["route"]], (
            "Offline export contacted the target."
        )


@pytest.mark.parametrize(("prefix", "suffix", "matched"), [
    (b"<script><!--<script></script>", b"</script>", False),
    (b"<script><!-- ordinary text --></script>", b"", True),
    (b"<frameset><frame></frameset>", b"", False),
    (b"<!-- <frameset> -->", b"", True),
], ids=["marker-in-script-data", "marker-after-script", "marker-after-frameset",
        "marker-after-comment"])
def test_NativeReflectionDistinguishesSupportedElementContent(
    tmp_path, capsys, prefix, suffix, matched,
):
    """Compare real loopback responses that place the marker in supported or excluded contexts."""

    route = next(case["route"] for case in Oracle()["cases"] if case["id"] == "reflection-raw")
    body = prefix + b"<fuzzy1337-probe>owned</fuzzy1337-probe>" + suffix
    requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        """Serve one deterministic HTML response on the explicitly allowed route."""

        timeout = 2

        def Get(self) -> None:
            """Send the control bytes and retain the exact target contact."""

            requests.append(self.path)

            if self.path != route:
                self.send_error(404)

                return

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = Get

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        thread.start()

        try:
            root = tmp_path / "workspace"
            url = f"http://127.0.0.1:{server.server_port}{route}"
            args = Setup(root, url, check="html-reflection")
            plan = Plan(args)
            assert not requests, "Reflection planning contacted the loopback target."
            assert Main(["scan", *Confirm(args, plan), "--json"]) == 0, (
                "The worker failed to acquire the complete HTML response."
            )
            capsys.readouterr()
            assert requests == [route], "Only the approved request is allowed."
            model = LocalModelStore(root).Open()
            observed = [item for item in model.observations
                        if item.kind == "native.web-response-check"]
            assert len(observed) == 1 and observed[0].attributes["matched"] is matched, (
                "The stored lexical observation disagreed with the HTML context control."
            )
            assert not Findings(model), "Neither control establishes a browser-confirmed Finding."
            assert Main(["workspace", "open", str(root), "--json"]) == 0, (
                "Reopening must verify the worker evidence for the script control."
            )

        finally:
            server.shutdown()
            thread.join(timeout=3)
            assert not thread.is_alive(), "The loopback script control leaked its server thread."


@pytest.mark.parametrize("case", Oracle()["failure_cases"], ids=lambda case: case["route"])
@pytest.mark.parametrize("check", ["html-reflection", "sql-boolean-sample"])
def test_NativeAssessmentFailsClosedOnBrokenOwnedTargets(tmp_path, capsys, case, check):
    """Retain a failed job and its original worker error without a clean observation."""

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as service:
        root = tmp_path / "workspace"
        args = Setup(root, service.base_url + case["route"], check=check)
        assert Main(["scan", *Confirm(args, Plan(args)), "--json"]) == 4, (
            "Broken transport must fail the assessment instead of becoming a clean response."
        )
        result = json.loads(capsys.readouterr().out)
        assert result["state"] == "failed", "Target failure must leave a failed job."
        model = LocalModelStore(root).Open()
        assert not model.observations and not Findings(model), (
            "Failed acquisition must create neither a clean observation nor a Finding."
        )
        errors = [json.loads(value.read_bytes()) for value in (root / "evidence").rglob("*")
                  if value.is_file() and value.read_bytes().startswith(b'{"error":')]
        assert errors == [{"error": case["expected_error"], "schema_version": 1}], (
            "The exact original worker failure must survive the job."
        )
        assert service.Observe()["requests"] == [case["route"]], "Only one contact is allowed."
        assert Main(["workspace", "open", str(root), "--json"]) == 0, (
            "Failed jobs and acquired diagnostics must remain readable."
        )
        capsys.readouterr()
        args = Setup(tmp_path / "recovery", service.Url("git-exposed"))
        assert Main(["scan", *Confirm(args, Plan(args)), "--json"]) == 0, (
            "A subsequent valid scan must still work against the same listener."
        )


@pytest.mark.parametrize("mode", ["vulnerable", "fixed"])
def test_OwnedSqlBooleanSamplingCapturesSeparateActualResponses(tmp_path, capsys, mode):
    """Plan each SQLite sample independently and compare its evidence with the owned oracle."""

    cases = [case for case in Oracle()["sql_boolean_cases"] if case["mode"] == mode]

    with OwnedWebVulnerabilityTarget(tmp_path / "target") as service:
        digests = []

        for index, case in enumerate([*cases, cases[0]]):
            root = tmp_path / f"sample-{index}"
            args = Setup(root, service.base_url + case["route"], check="sql-boolean-sample")
            before = service.Observe()
            plan = Plan(args)
            assert service.Observe() == before, "Planning must never send a SQL sample."
            assert Main(["scan", *args, "--json"]) == 3, "Each sample needs exact approval."
            capsys.readouterr()
            assert service.Observe() == before, "A sample escaped its approval boundary."
            assert Main(["scan", *Confirm(args, plan), "--json"]) == 0, (
                "An admitted owned SQL sample should complete."
            )
            result = json.loads(capsys.readouterr().out)
            assert result["check_id"] == NATIVE_SQL_BOOLEAN_SAMPLE_CHECK_ID, (
                "SQL sampling must bind its own capability and invocation."
            )
            model = LocalModelStore(root).Open()
            observations = [item for item in model.observations
                            if item.kind == "native.web-response-check"]
            expectedBody = json.dumps({"rows": case["rows"]},
                                       separators=(",", ":")).encode()
            assert not Findings(model) and len(observations) == 1, (
                "Individual SQL samples cannot create a differential Finding."
            )
            attributes = observations[0].attributes
            assert attributes["matched"] is None, "Sampling must remain distinct from a verdict."
            digest = hashlib.sha256(expectedBody).hexdigest()
            assert attributes["body_sha256"] == digest, "The response digest must bind real rows."
            digests.append(digest)

            if index == 0:
                AssertNativeResponseHtml(root, "Response captured; assessment pending", capsys)

        baseline, trueControl, falseControl, repeatedBaseline = digests
        assert baseline == repeatedBaseline, "The fixture baseline must be independently stable."
        assert (baseline == trueControl != falseControl if mode == "vulnerable"
                else trueControl == falseControl != baseline), (
            "The actual samples must distinguish the vulnerable and parameterized queries."
        )
        assert [item["parameterized"] for item in service.Observe()["queries"]] == [
            mode == "fixed"
        ] * 4, "SQLite execution must use the actual declared parameterization."
