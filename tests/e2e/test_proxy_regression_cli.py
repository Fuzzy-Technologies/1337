# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Installed Quick Scan through owned proxy/TLS barriers with independent target truth."""

from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from tests.proxy_regression_helpers import (
    ROOT,
    Oracle,
    OwnedProxy,
    OwnedTls,
    Product,
    Scan,
    Setup,
    TlsOracle,
    Verify,
    VerifyTls,
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


@pytest.mark.parametrize("case", TlsOracle()["cases"], ids=lambda case: case["id"])
def test_InstalledQuickScanKeepsTlsNegotiationFailuresAndRedirectsTruthful(tmp_path, case):
    """Real packaged TLS negotiation preserves fixed failure evidence without weakening trust."""

    with OwnedTls(case["mode"]) as tls, OwnedProxy(
        tls_redirect_port=tls.listener.getsockname()[1],
    ) as proxy:
        root = tmp_path / "Owned TLS Workspace"
        url = tls.Url() if case["scheme"] == "https" else proxy.Url(case)
        Setup(root, (url,), installed=True)
        status, summary = Product(Scan(root, (url,), request_timeout=2), installed=True)
        VerifyTls(root, summary, case, proxy, tls)
        schema = json.loads((ROOT / "contracts/quick-scan-summary.schema.json").read_text())
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(summary)
        assert status == case["exit_code"], "TLS failure/redirect lost its actual CLI exit status"
        before = (tls.Observe(), proxy.Observe())
        status, reopened = Product(["workspace", "open", str(root)], installed=True)
        assert status == 0 and reopened["verified_evidence_records"] == 1 and (
            before == (tls.Observe(), proxy.Observe())
        ), "Reopen failed to verify TLS acquisition without contacting either owned listener"
