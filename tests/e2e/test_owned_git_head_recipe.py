# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Execute copied core-only Finding onboarding against a constant owned loopback fixture."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import socket
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from tests.e2e.test_operator_onboarding import installed_onboarding as installed_onboarding

ROOT = Path(__file__).resolve().parents[2]
RECIPE = ROOT / "docs/OWNED_GIT_HEAD_RECIPE.md"


def test_CopiedRecipeCreatesOneFindingAndExportsOfflineFromInstalledWheel(
    installed_onboarding: Path, tmp_path: Path,
) -> None:
    """Run copied commands, real plans, denied opt-in and the independently fixed control."""

    text = RECIPE.read_text(encoding="utf-8")
    copied, = re.findall(r"```python\n(.*?)```", text, re.DOTALL)
    assert copied == (ROOT / "docs/examples/owned_git_head_demo.py").read_text(encoding="utf-8"), (
        'The copyable documentation fixture must exactly match the maintained standalone source'
    )
    script = tmp_path / "owned_git_head_demo.py"
    script.write_text(copied, encoding="utf-8")
    policy, = re.findall(r"```json\n(.*?)```", text, re.DOTALL)
    parent = tmp_path / "git-head-demo"
    parent.mkdir()
    (parent / "policy.json").write_text(policy, encoding="utf-8")
    statements = [shlex.split(line) for block in re.findall(r"```bash\n(.*?)```", text, re.DOTALL)
                  for line in block.replace("\\\n", " ").splitlines() if line.startswith("1337 ")]
    process = subprocess.Popen(
        [str(installed_onboarding), "-I", str(script), "--port", "0", "--seconds", "60"],
        cwd=tmp_path, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    transcript = []
    exports = []
    plans = {}
    stopped = None
    now = datetime.now(UTC)
    replacements = {"$HEAD_FROM": (now - timedelta(seconds=1)).isoformat(),
                    "$HEAD_UNTIL": (now + timedelta(minutes=10)).isoformat()}

    def Execute(arguments: list[str], expected: int = 0) -> dict | str:
        """Retain isolated installed CLI streams and status for each actual command."""

        result = subprocess.run(
            [str(installed_onboarding), "-I", "-m", "fuzzy1337", *arguments], cwd=tmp_path,
            capture_output=True, text=True, timeout=30, check=False,
        )
        transcript.append({"arguments": arguments, "exit_status": result.returncode,
                           "stdout": result.stdout, "stderr": result.stderr})
        assert result.returncode == expected and not result.stderr, transcript[-1]
        return json.loads(result.stdout) if "--json" in arguments else result.stdout.strip()

    try:
        assert process.stdout is not None, (
            'The owned fixture must expose its original readiness stream for target admission'
        )
        ready = json.loads(process.stdout.readline())
        assert ready["state"] == "serving" and ready["host"] == "127.0.0.1", (
            'The fixture must acknowledge a serving listener bound only to owned loopback'
        )
        port = ready["port"]

        for statement in statements:
            arguments = [replacements.get(value, value).replace(":8765", f":{port}")
                         for value in statement[1:]]
            if arguments[:2] == ["workspace", "open"]:
                remaining, error = process.communicate(timeout=10)
                stopped = json.loads(remaining)
                assert (
                    process.returncode == 0 and not error and stopped["listener_closed"] is True
                ), (
                    'The original fixture process must exit cleanly and acknowledge listener '
                    'closure before offline work'
                )

            outcome = Execute(arguments)

            if arguments[0] == "scan" and "--plan" in arguments:
                assert isinstance(outcome, dict), (
                    'An actual scan plan must return its structured policy intent rather than '
                    'unparsed output'
                )
                target = arguments[arguments.index("--target") + 1]
                kind = "FIXED" if "/fixed/" in target else "EXPOSED"
                intent = outcome["policy_plan"]["intent_sha256"]
                replacements[f"{kind}_INTENT_SHA256"] = intent
                plans[kind] = outcome

                if kind == "EXPOSED":
                    denied = Execute([value for value in arguments if value != "--plan"], 3)
                    assert isinstance(denied, dict) and denied["state"] == "failed", (
                        'Execution without exact plan confirmation must remain a structured '
                        'failed attempt'
                    )

            elif arguments[0] == "scan":
                assert isinstance(outcome, dict) and outcome["state"] == "completed", (
                    'An independently approved selected web check must acknowledge completed '
                    'execution'
                )
                assert outcome["object_counts"]["finding"] == 1, (
                    'The fixed control must preserve the single positive Finding without adding '
                    'another'
                )

            elif arguments[:2] == ["workspace", "open"]:
                assert isinstance(outcome, dict) and outcome["object_counts"]["finding"] == 1, (
                    'Offline workspace reopen must retain the positive Finding after the '
                    'fixture stops'
                )

            elif arguments[0] == "report":
                assert isinstance(outcome, dict) and outcome["output_published"] is True, (
                    'Every requested offline export must acknowledge publication of its fresh '
                    'destination'
                )
                exports.append(outcome)

        assert stopped is not None, (
            'The owned fixture must produce an original terminal acknowledgement before acceptance'
        )
        assert stopped == {"schema_version": 1, "state": "stopped",
                           "requests": ["exposed", "fixed"], "listener_closed": True}, (
            "Planning, missing confirmation and offline export cannot add a target request"
        )
        assert plans["EXPOSED"]["policy_plan"]["intent_sha256"] != (
            plans["FIXED"]["policy_plan"]["intent_sha256"]
        ), "The fixed endpoint requires its own exact approval"
        assert len(exports) == 3 and len({item["snapshot_sha256"] for item in exports}) == 1, (
            'JSON, HTML and SARIF exports must all bind the same saved model snapshot'
        )
        assert len({item["model_revision"] for item in exports}) == 1, (
            'Every offline export must bind the same acknowledged model revision'
        )
        report = json.loads((parent / "model.json").read_bytes())
        assert (
            report["summary"]["findings"] == 1 and report["scan_completeness"] == "not-assessed"
        ), (
            'The saved report must retain one Finding and explicitly unassessed scan completeness'
        )
        finding, = report["findings"]
        assert finding["normalized"]["check_id"] == "native.git-head-exposure", (
            'The positive result must identify the native Git HEAD exposure check'
        )
        assert finding["normalized"]["severity"] == "low", (
            'The owned Git HEAD exposure must retain its declared LOW severity'
        )
        assert finding["normalized"]["status"] == "open", (
            'The observed positive Finding must remain open rather than silently resolved'
        )
        subject, = [item for item in report["model"]["objects"] if item["reference"] == (
            finding["normalized"]["subject_reference"])]
        assert subject["attributes"]["url"] == ready["exposed_url"], (
            'The Finding subject must resolve to the actual exposed fixture URL'
        )
        sarif = json.loads((parent / "model.sarif").read_bytes())
        assert len(sarif["runs"][0]["results"]) == 1, (
            'SARIF must contain exactly the one attributable positive Finding'
        )
        assert "native.git-head-exposure" in (parent / "model.html").read_text(), (
            'HTML must render the same native Git HEAD check represented in JSON and SARIF'
        )

        with socket.socket() as probe:
            probe.settimeout(0.1)
            assert probe.connect_ex(("127.0.0.1", port)) != 0, (
                'The acknowledged stopped fixture must no longer accept a loopback connection'
            )

        # Reopen once more after independently acknowledging the actual stopped fixture process.
        reopened = Execute(["workspace", "open", "git-head-demo/workspace", "--json"])
        assert isinstance(reopened, dict) and reopened["object_counts"]["finding"] == 1, (
            'A second offline reopen after independent process teardown must retain the '
            'positive Finding'
        )
        wheel, = (installed_onboarding.parents[2] / "wheel").glob("*.whl")
        evidence = {"schema_version": 1,
                    "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                    "wheel_filename": wheel.name, "fixture": stopped, "commands": transcript,
                    "model_revision": report["model_revision"],
                    "snapshot_sha256": report["snapshot_sha256"],
                    "verified_evidence_records": reopened["verified_evidence_records"]}
        (tmp_path / "recipe-rehearsal.json").write_text(json.dumps(evidence, indent=2))

    finally:
        if process.poll() is None:
            process.terminate()
            process.communicate(timeout=10)
