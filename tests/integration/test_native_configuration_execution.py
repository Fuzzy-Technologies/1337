# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Real owned executor composition with an inert provider, separate from Trivy acceptance."""

from __future__ import annotations

import hashlib
import json
import os
import sys

import pytest

from fuzzy1337 import native_configuration_evidence as evidence_module
from fuzzy1337 import native_configuration_material_worker as worker_module
from fuzzy1337.executors import ExecutionTermination, LocalExecutionError, LocalExecutor
from fuzzy1337.executors.owned_process import RequireLinuxOwnership
from fuzzy1337.jobs import JobState
from fuzzy1337.native_configuration_workflow import ScanNativeConfiguration
from tests.unit.test_native_configuration_workflow import (
    configuration_runner as configuration_runner,
)
from tests.unit.test_native_configuration_workflow import controlled_runtime as controlled_runtime

ORIGINAL_EXECUTE = LocalExecutor.Execute


@pytest.mark.integration
def test_RealOwnedExecutorRetainsBothFreshAuthorityCheckpoints(
    controlled_runtime, configuration_runner, monkeypatch
):
    """An actual harmless provider process crosses READY and both original live authority checks."""

    if sys.platform != "linux":
        pytest.skip("Actual Linux descendant ownership is unavailable on this platform")

    try:
        RequireLinuxOwnership()

    except LocalExecutionError:
        if os.environ.get("FUZZY1337_REQUIRE_OWNED_CONFIGURATION_EXECUTION") == "1":
            pytest.fail("Required real owned configuration executor boundary is unavailable")

        pytest.skip("Real owned configuration executor is UNRUN without its Linux child interface")
    root, selection, context, settings = controlled_runtime
    report = {"SchemaVersion": 2, "Results": [{"Target": "Dockerfile", "Class": "config",
        "Type": "dockerfile", "Misconfigurations": [{"ID": "DS-0002", "Status": "FAIL",
            "Severity": "HIGH", "Title": "Inert owned unit check", "Resolution": "Select a user",
            "CauseMetadata": {"StartLine": 2, "EndLine": 2}}]}]}
    script = ("#!" + sys.executable + "\nimport json, sys\n"
        "if '--version' in sys.argv:\n    print(json.dumps({'Version': '0.75.0'}))\n"
        "else:\n    print(" + repr(json.dumps(report)) + ")\n"
        "    sys.stderr.write('Embedded libraries are loaded count=1\\n"
        "Embedded checks are loaded count=1\\n')\n").encode()
    selection.executable.write_bytes(script)
    selection.executable.chmod(0o700)
    pin = hashlib.sha256(script).hexdigest()
    monkeypatch.setattr(worker_module, "NATIVE_CONFIGURATION_EXECUTABLE_SHA256", pin)
    monkeypatch.setattr(evidence_module, "NATIVE_CONFIGURATION_EXECUTABLE_SHA256", pin)
    checkpoints = []
    originals = []

    async def Audit(self, request, **options):
        """Observe the original executor without replacing its process, result or callbacks."""

        original_check = options["pre_launch"]

        def Check(actual):
            """Retain each real initial/READY boundary and delegate unchanged fresh authority."""

            checkpoints.append(request.invocation.request.parameters["operation"])

            return original_check(actual)

        options["pre_launch"] = Check
        outcome = await ORIGINAL_EXECUTE(self, request, **options)
        originals.append(outcome)

        return outcome

    monkeypatch.setattr(LocalExecutor, "Execute", Audit)
    summary = configuration_runner.run(ScanNativeConfiguration(root, "native-scope", "owner:unit",
        selection, lambda: context.policy, approve_safe_configuration=True))
    assert summary.snapshot.state is JobState.COMPLETED, summary.ToDict()
    assert checkpoints == ["version", "version", "scan", "scan"], (
        "Both actual initial and READY-to-worker boundaries must revalidate each original grant"
    )
    assert len(originals) == 2 and len(summary.captures) == 2, (
        "The native collector must retain both actual original owned process results"
    )

    for original, captured in zip(originals, summary.captures, strict=True):
        assert original is captured.outcome and (
            original.termination is ExecutionTermination.PROCESS_EXIT
        ), (
            "Actual owned result identity and termination cannot be replaced by a specimen"
        )
