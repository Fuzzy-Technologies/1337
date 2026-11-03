# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal original native Trivy license-occurrence projection over verified local evidence."""

from __future__ import annotations

import json
from pathlib import Path

from fuzzy1337.adapters import AdapterReport, EvidenceReference, SerializeContract
from fuzzy1337.adapters.trivy import ParseJson
from fuzzy1337.evidence import EvidenceRecord
from fuzzy1337.images import (
    IMAGE_IMPORT_MAX_BYTES,
    ApplyVerifiedTrivyImages,
    ImageIdentity,
    Items,
    PackageRecord,
    Record,
    Text,
    VerifyRecords,
)
from fuzzy1337.license_policy import EvaluateLicenseExpression, LicensePolicy
from fuzzy1337.model import CanonicalModelJson, ModelProvenance, ModelState
from fuzzy1337.native_image_admission import CheckReference, NativeEvidenceStore

__all__: tuple[str, ...] = ()
TRIVY_LICENSE_POLICY_PROFILE = "trivy-0.75-original-license-policy-v1"
MAX_TRIVY_LICENSE_ROWS = 4096
MAX_TRIVY_LICENSE_POLICY_BYTES = 1024 * 1024
_SELECTED_ROLES = frozenset({"stdout", "stderr", "provider-version"})


class SelectedEvidenceStore(NativeEvidenceStore):
    """Restrict actual stored references to this three-role historical projection before reads."""

    def Read(self, reference: EvidenceReference) -> bytes:
        """Refuse every nonselected original role before the existing bounded native reader.

        Args:
            reference: Actual store-owned reference encountered during eager manifest verification.

        Returns:
            Original bytes after selected-role and native media/size/integrity checks.

        Raises:
            ValueError: Actual source role differs from this historical three-role projection.
            EvidenceError: The original native evidence reader refuses unverified source bytes.
        """

        if reference.role not in _SELECTED_ROLES:
            raise ValueError("invalid-trivy-license-policy-records")

        return super().Read(reference)


def PreflightRecords(records: tuple[EvidenceRecord, ...], workspace_root: Path) -> None:
    """Bound supplied and actual original manifests before any owning eager raw allocation.

    Args:
        records: Exact original stdout, stderr and provider-version acquisition records.
        workspace_root: Owning local workspace whose evidence store retains original manifests.

    Raises:
        ValueError: Selected roles, native media/size budgets or exact manifest equality fail.
        EvidenceError: Original immutable manifests or bounded source bytes cannot be verified.
    """

    if len(records) != 3 or any(type(item) is not EvidenceRecord for item in records) or {
        item.reference.role for item in records
    } != _SELECTED_ROLES:
        raise ValueError("invalid-trivy-license-policy-records")

    for record in records:
        CheckReference(record.reference)

    store = SelectedEvidenceStore(workspace_root / "evidence")

    for record in records:
        # Get checks the manifest identity, then its overridden Read bounds the actual reference.
        if store.Get(record.evidence_id) != record:
            raise ValueError("trivy-license-policy-manifest-mismatch")


def EvaluateVerifiedTrivyLicenses(
    state: ModelState, report: AdapterReport, provenance: ModelProvenance,
    records: tuple[EvidenceRecord, ...], workspace_root: Path, policy: LicensePolicy,
) -> dict[str, object]:
    """Verify one complete native image report and evaluate independent original license strings.

    Args:
        state: Exact existing owning model snapshot; no candidate is persisted.
        report: Exact successful native Trivy archive report admitted by the original owner.
        provenance: Exact source, scope, time, invocation and execution attribution.
        records: Three immutable original stdout, stderr and provider-version manifests.
        workspace_root: Owning local workspace, including relocated evidence stores.
        policy: Explicit caller-authored exact-atom preferences, without a default allow decision.

    Returns:
        Detached original coordinates, source identities and independent bounded policy results.
        Omitted, null and empty source lists remain distinct unknown information states.

    Raises:
        ValueError: Typed inputs, original owner admission or row/output budgets fail.
        EvidenceError: Original manifest or source bytes fail owning integrity verification.

    This Internal function performs local reads only. Whole-source admission precedes projection;
    no source roles, aggregated verdict, current authority, legal compliance or model write follows.
    """

    if type(state) is not ModelState or type(report) is not AdapterReport or (
        type(provenance) is not ModelProvenance or type(records) is not tuple
        or type(policy) is not LicensePolicy or not isinstance(workspace_root, Path)
    ):
        raise ValueError("invalid-trivy-license-policy-input")

    PreflightRecords(records, workspace_root)
    raw = VerifyRecords(state, provenance, records, workspace_root, report)
    ApplyVerifiedTrivyImages(state, report, provenance, records, workspace_root)
    payload = ParseJson(raw["stdout"], IMAGE_IMPORT_MAX_BYTES)
    metadata = Record(payload["Metadata"])
    image = ImageIdentity(Text(metadata["ImageID"]))
    os_fields = Record(metadata.get("OS", {}))
    results = Items(payload.get("Results", []))
    count = 0

    for value in results:
        native = Record(value)

        for item in Items(native.get("Packages") or []):
            package = Record(item)
            count += max(1, len(Items(package.get("Licenses") or [])))

            if count > MAX_TRIVY_LICENSE_ROWS:
                raise ValueError("trivy-license-policy-limit")

    stdout = next(record for record in records if record.reference.role == "stdout")
    result: dict[str, object] = {
        "profile": TRIVY_LICENSE_POLICY_PROFILE, "policy": policy.Description(),
        "image_reference": image.Object(state.workspace_id).Reference(),
        "image_digest": image.digest, "image_digest_kind": "config",
        "source_sha256": stdout.reference.sha256,
        "evidence_ids": {record.reference.role: record.evidence_id for record in records},
        "provider_version": provenance.provider_version,
        "invocation": json.loads(SerializeContract(report.invocation)),
        "execution": json.loads(SerializeContract(report.execution)),
        "provenance": json.loads(CanonicalModelJson(provenance)), "packages": [],
    }
    projected: list[dict[str, object]] = []
    # The exact final list size is empty-list bytes plus each independently serialized row/comma.
    size = len(CanonicalModelJson(result))

    if size > MAX_TRIVY_LICENSE_POLICY_BYTES:
        raise ValueError("trivy-license-policy-limit")

    for result_index, value in enumerate(results):
        native = Record(value)
        ecosystem = Text(native["Type"])

        for package_index, item in enumerate(Items(native.get("Packages") or [])):
            package = Record(item)
            identity = PackageRecord(package, ecosystem, os_fields)
            row: dict[str, object] = {
                "result_index": result_index, "package_index": package_index,
                "package_reference": identity.Object(state.workspace_id).Reference(),
                "assertions": [],
            }
            size += len(CanonicalModelJson(row)) + bool(projected)

            if size > MAX_TRIVY_LICENSE_POLICY_BYTES:
                raise ValueError("trivy-license-policy-limit")

            assertions: list[dict[str, object]] = []
            licenses = Items(package.get("Licenses") or [])

            for license_index, text in enumerate(licenses):
                assertion = {"license_index": license_index, "source_field": "Licenses",
                    "source_text": text, "source_role": "not-classified",
                    "evaluation": EvaluateLicenseExpression(text, policy)}
                size += len(CanonicalModelJson(assertion)) + bool(assertions)

                if size > MAX_TRIVY_LICENSE_POLICY_BYTES:
                    raise ValueError("trivy-license-policy-limit")

                assertions.append(assertion)

            if not licenses:
                information_state = "omitted" if "Licenses" not in package else (
                    "null" if package["Licenses"] is None else "empty"
                )
                assertion = {"license_index": None, "source_field": "Licenses",
                    "source_text": None, "source_role": "not-classified",
                    "information_state": information_state,
                    "evaluation": {"status": "unknown", "reason": "source-" + information_state,
                                   "atoms": []}}
                size += len(CanonicalModelJson(assertion))

                if size > MAX_TRIVY_LICENSE_POLICY_BYTES:
                    raise ValueError("trivy-license-policy-limit")

                assertions.append(assertion)

            row["assertions"] = assertions
            projected.append(row)

    result["packages"] = projected

    return result
