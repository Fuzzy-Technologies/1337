# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Run the copied installed Finding-to-Intel walkthrough without a live external service."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import subprocess
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path

from tests.e2e.test_operator_onboarding import installed_onboarding as installed_onboarding

ROOT = Path(__file__).resolve().parents[2]
GUIDE = ROOT / "docs/GUIDED_ASSESSMENT.md"
TRAINING = ROOT / "docs/examples/guided-assessment.cve.json"
FINDING_RECIPE = ROOT / "docs/OWNED_GIT_HEAD_RECIPE.md"


class DisclosureParser(HTMLParser):
    """Inspect rendered disclosure boundaries without executing or fetching report content."""

    def __init__(self) -> None:
        """Collect readable text and count technical blocks outside native disclosures."""

        super().__init__()
        self.details_depth = 0
        self.visible_text: list[str] = []
        self.unfolded_json = 0
        self.scripts = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Track native disclosures and refuse active markup in the standalone report."""

        if tag == "details":
            self.details_depth += 1

        elif tag == "pre" and self.details_depth == 0:
            self.unfolded_json += 1

        elif tag == "script":
            self.scripts += 1

    def handle_endtag(self, tag: str) -> None:
        """Restore the outside-disclosure view at the matching native element boundary."""

        if tag == "details":
            self.details_depth -= 1

    def handle_data(self, data: str) -> None:
        """Retain only primary report text outside technical disclosures."""

        if self.details_depth == 0:
            self.visible_text.append(data)


def Statements(text: str, language: str) -> list[list[str]]:
    """Read only explicit product commands, preserving caller variables and receipt destinations."""

    return [shlex.split(line) for block in re.findall(
        rf"```{language}\n(.*?)```", text, re.DOTALL,
    ) for line in block.replace("\\\n", " ").splitlines() if line.startswith("1337 ")]


def Files(root: Path) -> dict[str, bytes]:
    """Capture owned bytes to detect implicit writes by read-only operations or exact replay."""

    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*") if path.is_file()}


def test_GuidedSourceIsExactAndShellProductCommandsAgree() -> None:
    """The copyable fictional data and both supported command sequences must remain identical."""

    guide = GUIDE.read_text(encoding="utf-8")
    copied, = re.findall(r"```json\n(.*?)```", guide, re.DOTALL)
    assert copied == TRAINING.read_text(encoding="utf-8"), (
        "The copied training record must remain byte-identical to its maintained UTF-8 source"
    )
    document = json.loads(copied)
    assert document["cveMetadata"]["cveId"] == "CVE-1900-9999" and (
        document["containers"]["cna"]["affected"][0]["defaultStatus"] == "unknown"
    ), "The training source must remain explicitly fictional and cannot imply applicability"
    assert Statements(guide, "bash") == Statements(guide, "powershell"), (
        "PowerShell and Bash must execute the same explicit product operations and receipt paths"
    )
    assert len(Statements(guide, "bash")) == 6, (
        "The guide must retain import, selected inspect, apply, reopen and both offline exports"
    )


def test_InstalledGuidedAssessmentKeepsDetectionSourceAndInterpretationSeparate(
    installed_onboarding: Path, tmp_path: Path,
) -> None:
    """Run real approval, detection, fixed control, verified Intel and offline installed exports."""

    finding_recipe = FINDING_RECIPE.read_text(encoding="utf-8")
    guide = GUIDE.read_text(encoding="utf-8")
    script = tmp_path / "owned_git_head_demo.py"
    script.write_bytes((ROOT / "docs/examples/owned_git_head_demo.py").read_bytes())
    parent = tmp_path / "git-head-demo"
    parent.mkdir()
    policy, = re.findall(r"```json\n(.*?)```", finding_recipe, re.DOTALL)
    (parent / "policy.json").write_text(policy, encoding="utf-8")
    process = subprocess.Popen(
        [str(installed_onboarding), "-I", str(script), "--port", "0", "--seconds", "60"],
        cwd=tmp_path, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    transcript = []
    now = datetime.now(UTC)
    replacements = {"$HEAD_FROM": (now - timedelta(seconds=1)).isoformat(),
                    "$HEAD_UNTIL": (now + timedelta(minutes=10)).isoformat()}
    imports = []
    inspected = []
    exports = []

    def Execute(arguments: list[str], expected: int = 0) -> dict | str:
        """Keep actual installed-process streams and failures instead of substituting model APIs."""

        result = subprocess.run(
            [str(installed_onboarding), "-I", "-m", "fuzzy1337", *arguments], cwd=tmp_path,
            capture_output=True, text=True, timeout=30, check=False,
        )
        transcript.append({"arguments": arguments, "exit_status": result.returncode,
                           "stdout": result.stdout, "stderr": result.stderr})
        assert result.returncode == expected and not result.stderr, transcript[-1]

        return json.loads(result.stdout) if "--json" in arguments else result.stdout.strip()

    try:
        assert process.stdout is not None, "The owned target must expose its original readiness"
        ready = json.loads(process.stdout.readline())
        assert ready["state"] == "serving" and ready["host"] == "127.0.0.1", (
            "The guided scan must use only the actual owned loopback listener"
        )
        stopped = None

        for statement in Statements(finding_recipe, "bash"):
            arguments = [replacements.get(value, value).replace(":8765", f":{ready['port']}")
                         for value in statement[1:]]

            if arguments[:2] == ["workspace", "open"]:
                remaining, errors = process.communicate(timeout=10)
                stopped = json.loads(remaining)
                assert process.returncode == 0 and not errors, (
                    "The original target must terminate before the offline guide begins"
                )

            outcome = Execute(arguments)

            if arguments[0] == "scan" and "--plan" in arguments:
                assert isinstance(outcome, dict), (
                    "Planning must provide an actual structured intent"
                )
                target = arguments[arguments.index("--target") + 1]
                kind = "FIXED" if "/fixed/" in target else "EXPOSED"
                replacements[f"{kind}_INTENT_SHA256"] = outcome["policy_plan"]["intent_sha256"]
                denied = Execute([value for value in arguments if value != "--plan"], 3)
                assert isinstance(denied, dict) and denied["state"] == "failed", (
                    "Neither endpoint may execute without its own exact invocation confirmation"
                )

            elif arguments[0] == "scan":
                assert isinstance(outcome, dict) and outcome["state"] == "completed" and (
                    outcome["object_counts"]["finding"] == 1
                ), "The fixed control must add no Finding and cannot erase the original detection"

        assert stopped == {"schema_version": 1, "state": "stopped",
                           "requests": ["exposed", "fixed"], "listener_closed": True}, (
            "Planning and missing confirmation cannot consume either of the two owned requests"
        )
        original = json.loads((parent / "model.json").read_bytes())
        original_finding, = original["findings"]
        replacements.update({"$FINDING": original_finding["reference"],
                             "$REVISION": str(original["model_revision"])})
        (parent / "training.cve.json").write_bytes(TRAINING.read_bytes())

        for statement in Statements(guide, "bash"):
            redirect = statement.index(">") if ">" in statement else len(statement)
            arguments = [replacements.get(value, value) for value in statement[1:redirect]]
            before = Files(parent / "workspace")
            outcome = Execute(arguments)
            assert isinstance(outcome, dict), (
                "Every copied guided command must report structured truth"
            )

            if redirect < len(statement):
                (tmp_path / statement[redirect + 1]).write_text(
                    transcript[-1]["stdout"], encoding="utf-8",
                )

            if arguments[:2] == ["intel", "import"]:
                imports.append(outcome)
                assert outcome["acquisition_state"] == "succeeded", (
                    "The selected fictional source must traverse real immutable local acquisition"
                )
                replacements.update({"$SNAPSHOT": outcome["snapshot_id"],
                                     "$RECEIPT": outcome["receipt_id"],
                                     "$AS_OF": (datetime.fromisoformat(outcome["finished_at"]) + (
                                         timedelta(seconds=1))).isoformat()})

            elif arguments[:2] == ["intel", "inspect"]:
                inspected.append(outcome)
                details = outcome["details"]
                assert details["target_applicability"] == "not-evaluated" and (
                    details["publisher_authentication"] == "not-assessed"
                ), "Selected source inspection cannot authenticate the publisher or match a target"
                assert details["source"]["origin"] == "synthetic" and (
                    details["records"][0]["data"]["cvss"][0]["base_score"] == 8.1
                ), "The inspected score must remain attributed to the fictional source"
                products = details["cve_source_profiles"]["applicability"]["containers"][0][
                    "affected"
                ]
                assert products[0]["defaultStatus"] == "unknown", (
                    "Source inspection must preserve an unknown product declaration as unknown"
                )
                assert Files(parent / "workspace") == before, (
                    "Detailed source inspection must not mutate model, receipts or raw evidence"
                )

            elif arguments[:2] == ["intel", "apply"]:
                assert outcome["model_commit"] == "confirmed" and (
                    outcome["model_revision"] == original["model_revision"] + 1
                ), "Explicit candidate association must acknowledge exactly one durable revision"
                apply_arguments = arguments

            elif arguments[0] == "report":
                exports.append(outcome)
                assert outcome["output_published"] is True, (
                    "Both guided offline exports must acknowledge their actual complete publication"
                )

        assert len(imports) == len(inspected) == 1 and len(exports) == 2, (
            "The copied guide must exercise one explicit source and both saved report formats"
        )
        report = json.loads((parent / "assessment.json").read_bytes())
        assert report["findings"] == original["findings"], (
            "Candidate intelligence cannot rewrite detector identity, severity or triage"
        )
        observations = [item for item in report["model"]["observations"]
                        if item["kind"] == "finding-intelligence"]
        observation, = observations
        source_assertion, = observation["attributes"]["source_assertions"]
        assert source_assertion["association_state"] == "candidate" and (
            source_assertion["source"]["origin"] == "synthetic"
        ), "The training association must remain synthetic and unreviewed"
        assert source_assertion["record"]["identifier"] == "CVE-1900-9999", (
            "The saved observation must retain only the selected fictional identifier"
        )
        assert report["scan_completeness"] == "not-assessed" and (
            report["summary"]["findings"] == report["summary"]["active_findings"] == 1
        ), "Offline reports cannot turn the fixed control into complete coverage or resolved triage"
        html = (parent / "assessment.html").read_text(encoding="utf-8")
        displayed = DisclosureParser()
        displayed.feed(html)
        primary_text = " ".join(displayed.visible_text)
        assert all(value in html for value in (
            "native.git-head-exposure", "CVE-1900-9999", "8.1", "FuzzyRoutines", "synthetic",
        )), "HTML must show the detector and separately attributed fuzzy source interpretation"
        assert all(value in primary_text for value in ("CVE-1900-9999", "8.1", "candidate")), (
            "Readers must see the source meaning and association limit without expanding raw JSON"
        )
        assert displayed.unfolded_json == displayed.scripts == 0, (
            "Technical JSON belongs inside disclosures and the offline report contains no scripts"
        )
        assert {item["snapshot_sha256"] for item in exports} == {report["snapshot_sha256"]}, (
            "Both offline presentations must bind the exact same saved model snapshot"
        )
        stale = Execute(apply_arguments, 4)
        assert isinstance(stale, dict) and stale["failure"] == "revision-conflict", (
            "A stale revision must refuse instead of overwriting newer retained model state"
        )
        apply_arguments[apply_arguments.index("--expected-revision") + 1] = str(
            report["model_revision"],
        )
        before = Files(parent / "workspace")
        replay = Execute(apply_arguments)
        assert isinstance(replay, dict) and (
            replay["model_revision"] == report["model_revision"]
            and Files(parent / "workspace") == before
        ), "Exact interpretation replay must be a byte-preserving no-op at the current revision"
        duplicate = Execute([
            "report", "export", "git-head-demo/workspace", "--format", "html", "--output",
            "git-head-demo/assessment.html", "--json",
        ], 2)
        assert isinstance(duplicate, dict) and duplicate["output_published"] is False and (
            (parent / "assessment.html").read_text(encoding="utf-8") == html
        ), "Existing human-readable results must be preserved by the no-clobber export boundary"
        (tmp_path / "guided-rehearsal.json").write_text(json.dumps({
            "schema_version": 1, "fixture": stopped, "commands": transcript,
            "training_sha256": hashlib.sha256(TRAINING.read_bytes()).hexdigest(),
            "snapshot_sha256": report["snapshot_sha256"],
            "model_revision": report["model_revision"],
        }, indent=2), encoding="utf-8")

    finally:
        if process.poll() is None:
            process.terminate()
            process.communicate(timeout=10)
