# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Keep finite native-check truth independent and failed assessments unscored."""

from __future__ import annotations

import pytest

from fuzzy1337.functional_metrics import BuildReport, RunStatus
from tests.functional.native_web_metrics import NativeCheckRun, NativeScenario
from tests.web_vulnerability_helpers import Oracle


def test_NativeGitMatrixRetainsIndependentPositiveAndNegativeTruth():
    """Reuse the unchanged handwritten target matrix without deriving truth from native matches."""

    metadata = Oracle()
    cases = [case for case in metadata["cases"] if case["family"] == "git"]
    scenarios = tuple(NativeScenario(metadata, case) for case in cases)
    assert [(item.identifier, item.checks[0].expected) for item in scenarios] == [
        ("git-exposed", True), ("git-fixed", False), ("git-decoy", False),
        ("git-redirect", False),
    ], "Native acceptance must retain the independently authored TP1/TN3 finite matrix."
    assert all(item.target_pack == "first-party.web-vulnerable" and
               item.target_version == "1" and item.complete for item in scenarios), (
        "A native check must not replace original target provenance or expand oracle completeness."
    )
    assert all(item.checks[0].capability == "fuzzy1337-git-head-exposure"
               for item in scenarios), "The oracle describes the finite Git response predicate."


@pytest.mark.parametrize("status", [RunStatus.CRASHED, RunStatus.TIMED_OUT])
def test_FailedNativeAssessmentNeverCountsAsTrueNegative(status):
    """A failed provider with no findings is incomplete, rather than a successful clean result."""

    metadata = Oracle()
    case = next(item for item in metadata["cases"] if item["id"] == "git-fixed")
    report = BuildReport((NativeScenario(metadata, case),), (
        NativeCheckRun(case["id"], "1", status, 0.0, (), ()),
    ))
    metrics = report["runs"][0]["metrics"]
    assert metrics["accuracy_available"] is False and metrics["tn"] is None, (
        "Timeout or failed native acquisition must never inflate the negative-control count."
    )
    assert metrics["tp"] is metrics["fp"] is metrics["fn"] is None, (
        "No accuracy count is available for an incomplete native assessment."
    )
    assert metrics["evidence_completeness"] == 0, (
        "Absent original native execution proof must remain visible in the metrics."
    )
