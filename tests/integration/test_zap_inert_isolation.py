# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Opt-in genuine inert namespace/custody proof; no engine or Java enrollment."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
REQUIRED = os.environ.get("FUZZY1337_RUN_ZAP_INERT_ACCEPTANCE") == "1"


def Owner():
    """Require the reviewed explicit genuine lane before importing kernel ownership code."""

    if not REQUIRED:
        pytest.skip("Optional inert proof was not explicitly enabled; this is not acceptance")

    if sys.platform != "linux" or not os.environ.get("FUZZY1337_ZAP_INERT_MATERIAL"):
        pytest.fail("Required genuine inert prerequisites are missing before payload launch")

    path = ROOT / "tests/fixtures/zap_inert/owner.py"
    spec = importlib.util.spec_from_file_location("integration_inert_owner", path)
    assert spec is not None and spec.loader is not None, (
        "Closed inert acceptance invariant failed"
    )
    owner = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = owner
    spec.loader.exec_module(owner)

    return owner


def RunCase(tmp_path, case, mode):
    """Run one closed real case and preserve actual outcome as bounded test evidence."""

    owner = Owner()
    material = Path(os.environ["FUZZY1337_ZAP_INERT_MATERIAL"]).resolve()
    runner = asyncio.Runner()

    try:
        outcome = runner.run(asyncio.wait_for(
            owner.Run(tmp_path.resolve() / case, material, mode, case), 32))

    except BaseException:
        runner.close()

        raise

    copied_originals = False

    try:
        result = outcome.execution
        evidence = {"case": case,
            "termination": None if result is None else result.termination.value,
            "state": "unknown" if result is None else result.execution.state.value,
            "exit_code": None if result is None else result.execution.exit_code,
            "cleanup_confirmed": outcome.cleanup_confirmed,
            "custody_complete": outcome.complete,
            "failure": outcome.failure, "observations": outcome.observations,
            "stdout": None if result is None else result.stdout.decode("ascii"),
            "stderr": None if result is None else result.stderr.decode("ascii"),
            "observed_stdout_prefix": outcome.observed_stdout_prefix.decode("ascii")}
        destination = Path("functional-evidence/zap-inert") / case
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "actual.json").write_text(json.dumps(evidence, indent=2) + "\n")

        if outcome.report is not None:
            (destination / "original-report.bin").write_bytes(outcome.report)

        if outcome.setup is not None:
            (destination / "original-setup.bin").write_bytes(outcome.setup)

        copied_originals = outcome.report is not None

        return owner, outcome

    finally:
        if outcome.cleanup_confirmed:
            if outcome._retained_directory is None or copied_originals:
                outcome.CloseRecovery()

            runner.close()

        else:
            outcome._retained_runner = runner


def AssertOutcome(case, owner, outcome):
    """Require exact real stages, operations, termination and post-cleanup custody facts."""

    assert outcome.execution is not None and outcome.cleanup_confirmed, (
        "Actual execution or owned cleanup remains explicitly unknown")
    observed = outcome.observations
    termination = outcome.execution.termination.value
    state = outcome.execution.execution.state.value
    stdout = outcome.execution.stdout
    assert observed.get("host_sink_contacts") == 0, "The owned host sink received a contact"
    assert observed.get("final_ready_verified") is True, "Original final READY was not verified"
    assert observed.get("original_peer_exited_after_cleanup") is True, (
        "Original direct peer exit was not observed after owned cleanup")
    assert outcome.setup == owner.CONTRACT.SETUP_BYTES, "Original setup custody is incomplete"

    if case == "deny":
        assert observed.get("intentional_authority_revocation") is True, (
            "The intended current-authority revocation was not performed")
        assert observed.get("current_authority_refused") is True, (
            "The original current authority did not refuse workload release")
        assert observed.get("ack_sent") is False, "Revoked authority must never ACK workload"
        assert not outcome.complete and outcome.report is None and (
            outcome.failure == "ValueError"
        ), (
            "Intentional pre-ACK refusal cannot claim late-file custody")
        assert b"LATE " not in stdout and b"ACK_WITHOUT_REPORT" not in stdout, (
            "A denied request started post-ACK work")
        assert (termination, state) == ("cancellation", "cancelled"), (
            "Pre-ACK denial must retain actual cooperative cancellation")

        return

    assert observed.get("ack_sent") is True, "The original bound ACK was not sent"

    if case == "missing":
        assert stdout.splitlines() == [b"ACK_WITHOUT_REPORT"], (
            "Missing report proof requires the actual post-ACK pause marker")
        assert not outcome.complete and outcome.report is None and (
            outcome.failure == "missing-late-report"
        ), "Sentinel-only retention must remain explicitly incomplete"
        assert observed.get("cooperative_cancel_requested") is True and (
            termination, state
        ) == ("cancellation", "cancelled"), "Post-ACK pause was not actually cancelled"

        return

    assert outcome.failure is None and outcome.complete, "Original late-file custody failed"
    assert outcome.report == owner.CONTRACT.REPORT_BYTES, "Original late report bytes differ"
    assert observed.get("live_private_listener_host_refused") is True, (
        "Host refusal must be observed while the original private listener is alive")
    assert b"NETWORK host-refused private-connected" in stdout.splitlines(), (
        "Actual private loopback connectivity was not proved")
    denials = [line.split() for line in stdout.splitlines() if line.startswith(b"DENIED ")]
    expected = {b"quota-remount", b"new-tmpfs", b"new-userns", b"new-mountns", b"new-netns",
        b"root-write", b"input-write"}
    assert len(denials) == 7 and all(len(item) == 3 for item in denials) and {
        item[1] for item in denials
    } == expected, "The seven exact denied operations were not all observed"

    for _, operation, errno in denials:
        allowed = {1, 13, 28} if operation == b"new-userns" else (
            {1, 13, 30} if operation in {b"root-write", b"input-write"} else {1, 13})
        assert int(errno) in allowed, "An invalid or unrelated errno substituted for actual denial"

    if case in {"normal", "bytes", "inodes"}:
        assert observed.get("work_complete_observed") is True and (
            observed.get("normal_release_requested") is True
            and stdout.splitlines().count(b"WORK_COMPLETE") == 1
        ), "Normal completion needs the actual work marker and one original-pidfd release"
        assert (termination, state, outcome.execution.execution.exit_code) == (
            "process_exit", "succeeded", 0
        ), "The normal/quota workload did not actually complete successfully"

    if case in {"bytes", "inodes"}:
        quota = [line.split() for line in stdout.splitlines() if line.startswith(b"QUOTA ")]
        role = b"bytes" if case == "bytes" else b"inodes"
        ceiling = 67108864 if case == "bytes" else 1024
        assert len(quota) == 1 and len(quota[0]) == 4 and quota[0][1] == role and (
            quota[0][3] == b"ENOSPC" and 0 < int(quota[0][2]) <= ceiling
        ), "A different or unbounded quota result substituted for the selected operation"

    if case in {"timeout", "cancel", "kill"}:
        assert observed.get("normal_release_requested") is False, (
            "A normal release must not replace the selected timeout/cancel/kill")
        children = [line.split() for line in stdout.splitlines()
            if line.startswith(b"OWNED_CHILD ")]
        assert len(children) == 1 and len(children[0]) == 2 and int(children[0][1]) > 0, (
            "The actual post-setsid owned-child readiness handshake is absent")

    if case == "timeout":
        assert (termination, state) == ("timeout", "timed_out"), (
            "A different stop mechanism substituted for the actual executor timeout")
        assert observed.get("cooperative_cancel_requested") is False, (
            "A cancellation request substituted for the original timeout")

    if case == "cancel":
        assert observed.get("cooperative_cancel_requested") is True and (
            termination, state
        ) == ("cancellation", "cancelled"), "The selected cooperative cancellation did not occur"

    if case == "kill":
        assert observed.get("direct_peer_sigkill_requested") is True and (
            observed.get("direct_peer_exit_observed") is True
        ), "Direct original peer SIGKILL and exit were not both observed"
        natural = (termination, state, outcome.execution.execution.exit_code) == (
            "process_exit", "failed", 137)
        cancelled = observed.get("cooperative_cancel_requested") is True and (
            termination, state) == ("cancellation", "cancelled")
        assert natural or cancelled, "An unrelated stop substituted for the direct peer SIGKILL"


def test_NormalGenuineCapabilityCase(tmp_path):
    """Require the actual serial capability proof before scheduling other cases."""

    owner, outcome = RunCase(tmp_path, "normal", "normal")
    AssertOutcome("normal", owner, outcome)


@pytest.mark.parametrize("case,mode", (("bytes", "byte-limit"), ("inodes", "inode-limit"),
    ("timeout", "wait"), ("cancel", "wait"), ("kill", "wait"), ("deny", "normal"),
    ("missing", "before-report")))
def test_GenuineClosedFailureAndQuotaCases(tmp_path, case, mode):
    """Retain truthful failure and post-cleanup late custody for each fixed operation."""

    owner, outcome = RunCase(tmp_path, case, mode)
    AssertOutcome(case, owner, outcome)
