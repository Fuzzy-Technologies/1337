# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Check cross-report joins using inert fixtures without granting scanner execution credit."""

from __future__ import annotations

import pytest

from tests.contract.test_external_benchmark import (
    ContractNucleiObservation,
    ContractObservation,
    WriteContractEvidence,
    WriteNucleiContractEvidence,
)
from tests.functional.external_benchmark import BuildComparison, LoadPack
from tests.functional.external_scanner_comparison_view import JoinVerifiedReports

HEAD = "b" * 40


def SeparateContractReports(tmpPath):
    """Build two valid synthetic report cohorts with separate original-byte roots."""

    pack, target = LoadPack()
    nativeRoot, nucleiRoot = tmpPath / "native", tmpPath / "nuclei"
    native, nuclei = [], []

    for case in pack["cases"]:
        caseId = case["id"]
        row = ContractObservation(pack, target, nativeRoot, case_id=caseId,
                                  matched=case["expected"])
        row["execution"]["target_instance"] += "-" + caseId
        WriteContractEvidence(row["execution"], nativeRoot)
        native.append(row)

        for track in ("whole1337", "external-nuclei"):
            row = ContractNucleiObservation(pack, target, nucleiRoot, case_id=caseId,
                                            track=track, matched=case["expected"])
            row["execution"]["target_instance"] += "-" + caseId
            row["execution"]["effective_budget"]["operation_timeout_seconds"] = 3
            WriteNucleiContractEvidence(row, nucleiRoot)
            nuclei.append(row)

    return pack, (BuildComparison(pack, target, native, nativeRoot),
                  BuildComparison(pack, target, nuclei, nucleiRoot))


def test_JoinedViewKeepsNativeAndNucleiOutcomesAndBudgetDifferences(tmp_path):
    """The common positive and the two independently classified controls remain distinct."""

    pack, reports = SeparateContractReports(tmp_path)
    view = JoinVerifiedReports(pack, reports, HEAD)
    exposed, jsonControl, htmlControl = (item["tracks"] for item in view["cases"])
    assert {result["score"] for result in exposed.values()} == {"tp"}, (
        "Every completed known positive must retain its own true positive result."
    )

    for control in (jsonControl, htmlControl):
        assert control["native-engine"]["score"] == "tn" and all(
            (control[track]["status"], control[track]["score"]) == ("unproven", None)
            for track in ("whole1337", "external-nuclei")
        ), "Completed native negatives cannot supply missing response proof to Nuclei."

    assert view["equal_effective_budgets"] is False and (
        view["whole_application_accuracy"] is None
    ), "Different effective budgets and an incomplete app oracle must remain visible."
    assert [view["tracks"][track]["engine"] for track in (
        "native-engine", "whole1337", "external-nuclei",
    )] == ["1337Scope", "Nuclei", "Nuclei"], "Both Nuclei modes use a single detector engine."


@pytest.mark.parametrize("field,value,error", [
    ("reset_contract_sha256", "e" * 64, "target/reset"),
    ("target_instance", "reuse", "distinct instances"),
    ("product_revision", "e" * 40, "selected product source"),
    ("scanner_sha256", "e" * 64, "same binary"),
])
def test_JoinedViewRejectsIncompatibleCrossReportEvidence(
    tmp_path, field, value, error,
):
    """Individually selected reports must still satisfy the shared cross-track evidence basis."""

    pack, (native, nuclei) = SeparateContractReports(tmp_path)

    if field == "scanner_sha256":
        for row in nuclei["observations"]:
            if row["scanner_track"] == "external-nuclei":
                row["execution"][field] = value

    else:
        nuclei["observations"][0]["execution"][field] = (
            native["observations"][0]["execution"][field] if value == "reuse" else value
        )

    with pytest.raises(ValueError, match=error):
        JoinVerifiedReports(pack, (native, nuclei), HEAD)
