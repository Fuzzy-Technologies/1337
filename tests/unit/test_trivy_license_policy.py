# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Focused native policy allocation and exact original-role admission boundaries."""

from __future__ import annotations

from dataclasses import replace

import pytest

from fuzzy1337 import trivy_license_policy as projection
from fuzzy1337.evidence import LocalEvidenceStore
from tests.integration.test_trivy_license_policy_persistence import (
    Evaluate,
    Owned,
    Package,
    Payload,
)


@pytest.mark.parametrize("case", ["count", "type", "role", "media", "stdout-size",
                                  "stderr-size", "version-size"])
def test_SuppliedRoleMediaAndBudgetsRefuseBeforeEagerGet(tmp_path, monkeypatch, case):
    """Unadmitted selected-role references never reach any raw evidence allocation."""

    root, _, _, _, records, _ = Owned(tmp_path)

    if case == "count":
        records = records[:2]

    elif case == "type":
        records = (None, *records[1:])

    else:
        index = {"stderr-size": 1, "version-size": 2}.get(case, 0)
        original = records[index]
        changes = {
            "role": {"role": "native-scan-receipt"}, "media": {"media_type": "text/plain"},
            "stdout-size": {"size_bytes": 4 * 1024 * 1024 + 1},
            "stderr-size": {"size_bytes": 1024 * 1024 + 1},
            "version-size": {"size_bytes": 16 * 1024 + 1},
        }[case]
        altered = replace(original, reference=replace(original.reference, **changes))
        records = tuple(altered if item is original else item for item in records)

    def Refuse(*args, **kwargs):
        """Fail if a malformed supplied record reaches the eager store boundary."""

        raise AssertionError("Malformed record reached eager Get.")

    monkeypatch.setattr(projection.SelectedEvidenceStore, "Get", Refuse)

    with pytest.raises(ValueError):
        projection.PreflightRecords(records, root)


def test_ActualReaderRefusesExtraNativeRoleBeforeRawRead(tmp_path, monkeypatch):
    """A six-role receipt cannot enter this selected three-role projection through eager Get."""

    root, _, _, _, records, _ = Owned(tmp_path)
    record = LocalEvidenceStore(root / "evidence").Put(
        b"receipt", "native-scan-receipt", "application/json", records[2].provenance,
    )

    def Refuse(*args, **kwargs):
        """Fail if selected-role denial reaches physical blob allocation."""

        raise AssertionError("Unexpected actual manifest role reached physical raw read.")

    monkeypatch.setattr(LocalEvidenceStore, "Read", Refuse)

    with pytest.raises(ValueError, match="invalid-trivy-license-policy-records"):
        projection.SelectedEvidenceStore(root / "evidence").Get(record.evidence_id)


def test_ActualStoredRoleBudgetIsCheckedBeforeRawRead(tmp_path, monkeypatch):
    """A valid original stderr manifest over this role's ceiling refuses before body allocation."""

    root, _, _, _, records, _ = Owned(tmp_path)
    record = LocalEvidenceStore(root / "evidence").Put(
        b"x" * (1024 * 1024 + 1), "stderr", "text/plain", records[1].provenance,
    )

    def Refuse(*args, **kwargs):
        """Fail if the actual oversized reference reaches the base raw reader."""

        raise AssertionError("Oversized actual manifest reached physical raw read.")

    monkeypatch.setattr(LocalEvidenceStore, "Read", Refuse)

    with pytest.raises(ValueError, match="role budget"):
        projection.SelectedEvidenceStore(root / "evidence").Get(record.evidence_id)


def test_OutputGrowthStopsDuringOneLargePackage(tmp_path, monkeypatch):
    """The independent output ceiling stops before evaluating every source occurrence."""

    context = Owned(tmp_path, Payload([Package(["X" * 2048] * 1000)]))
    original = projection.EvaluateLicenseExpression
    calls = []

    def EvaluateOne(text, policy):
        """Observe bounded matcher work while preserving its exact deterministic result."""

        calls.append(text)
        assert len(calls) < 600, "The output budget waited for a complete oversized package."

        return original(text, policy)

    monkeypatch.setattr(projection, "EvaluateLicenseExpression", EvaluateOne)

    with pytest.raises(ValueError, match="trivy-license-policy-limit"):
        Evaluate(context)

    assert 1 < len(calls) < 600, "Incremental output refusal did not bound source projection."


def test_PackageMetadataAndEmptyAssertionBudgetAreBothChecked(tmp_path, monkeypatch):
    """Empty-source rows cannot bypass either enclosing metadata or assertion byte accounting."""

    context = Owned(tmp_path, Payload([Package([])]))
    result = Evaluate(context)
    from fuzzy1337.model import CanonicalModelJson

    exact = len(CanonicalModelJson(result))
    monkeypatch.setattr(projection, "MAX_TRIVY_LICENSE_POLICY_BYTES", exact)
    assert Evaluate(context) == result, "Exact inclusive output-byte ceiling changed the result."
    monkeypatch.setattr(projection, "MAX_TRIVY_LICENSE_POLICY_BYTES", exact - 1)

    with pytest.raises(ValueError, match="trivy-license-policy-limit"):
        Evaluate(context)

    monkeypatch.setattr(projection, "MAX_TRIVY_LICENSE_POLICY_BYTES", 1)

    with pytest.raises(ValueError, match="trivy-license-policy-limit"):
        Evaluate(context)


def test_ManifestEqualityRefusesChangedSuppliedAcquisition(tmp_path, monkeypatch):
    """The verified returned manifest must be exactly equal to the original supplied acquisition."""

    root, _, _, _, records, _ = Owned(tmp_path)
    original = projection.SelectedEvidenceStore.Get

    def Alter(self, evidence_id):
        """Return a different valid source attribution after the true owner has verified bytes."""

        record = original(self, evidence_id)

        return replace(record, provenance=replace(record.provenance, source_version="2"))

    monkeypatch.setattr(projection.SelectedEvidenceStore, "Get", Alter)

    with pytest.raises(ValueError, match="manifest-mismatch"):
        projection.PreflightRecords(records, root)
