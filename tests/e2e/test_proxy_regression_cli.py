# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Installed product Quick Scan through an owned plaintext proxy with independent backend truth."""

from __future__ import annotations

import pytest

from tests.proxy_regression_helpers import (
    Oracle,
    OwnedProxy,
    Product,
    Scan,
    Setup,
    Verify,
)


@pytest.mark.parametrize("case", Oracle()["cases"], ids=lambda case: case["id"])
def test_InstalledQuickScanPreservesFrontendTruthAndOriginalEvidence(tmp_path, case):
    """Actual console/governor/store flow distinguishes proxy status from backend authority."""

    with OwnedProxy() as lab:
        root = tmp_path / "Owned Proxy Workspace"
        Setup(root, (lab.Url(case),), installed=True)
        status, summary = Product(Scan(root, (lab.Url(case),)), installed=True)
        Verify(root, summary, case, lab)
        assert status == case["exit_code"], "Installed proxy regression lost its actual exit status"
        before = lab.Observe()
        status, reopened = Product(["workspace", "open", str(root)], installed=True)
        assert status == 0 and reopened["verified_evidence_records"] == case["evidence_records"], (
            "Installed workspace reopen lost the original successful/failed worker acquisition"
        )
        assert lab.Observe() == before, "Read-only workspace reopen contacted proxy or backend"
