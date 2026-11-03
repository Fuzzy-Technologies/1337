# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal read-only policy matching for independent original CycloneDX license occurrences."""

from __future__ import annotations

import json
from pathlib import Path

from fuzzy1337.adapters.trivy import ParseJson
from fuzzy1337.evidence import EvidenceRecord
from fuzzy1337.images import (
    IMAGE_IMPORT_MAX_BYTES,
    ApplyVerifiedCycloneDx,
    ImageIdentity,
    Items,
    PackageIdentity,
    Record,
    VerifyRecords,
)
from fuzzy1337.license_policy import (
    EvaluateLicenseExpression,
    LicenseIdentifier,
    LicensePolicy,
    UnsupportedLicenseExpression,
)
from fuzzy1337.model import CanonicalModelJson, ModelProvenance, ModelState

__all__: tuple[str, ...] = ()
CYCLONEDX_LICENSE_POLICY_PROFILE = "cyclonedx-1.6-original-license-policy-v1"
MAX_CYCLONEDX_LICENSE_ROWS = 4096
MAX_CYCLONEDX_LICENSE_POLICY_BYTES = 1024 * 1024


def LicenseChoice(choice: dict[str, object], policy: LicensePolicy) -> dict[str, object]:
    """Evaluate one original accepted occurrence without combining sibling license choices.

    Args:
        choice: Original choice already admitted by the unchanged CycloneDX inventory owner.
        policy: Exact caller-authored policy; unconfigured atoms remain unknown.

    Returns:
        Original selected text and source field with a separate syntax-policy result. Additional
        source fields and compound license IDs remain unknown; no source role is inferred.
    """

    if "expression" in choice:
        field = "expression"
        text = choice["expression"]
        supported = set(choice) == {"expression"}

    else:
        field = "license.id"
        license_record = Record(choice["license"])
        text = license_record["id"]
        supported = set(choice) == {"license"} and set(license_record) == {"id"}

    evaluation: dict[str, object]

    if not supported:
        evaluation = {"status": "unknown", "reason": "unsupported-license-choice", "atoms": []}

    elif field == "license.id":
        try:
            LicenseIdentifier(str(text))

        except UnsupportedLicenseExpression:
            evaluation = {"status": "unknown", "reason": "unsupported-license-identifier",
                          "atoms": []}

        else:
            evaluation = EvaluateLicenseExpression(text, policy)

    else:
        evaluation = EvaluateLicenseExpression(text, policy)

    return {"source_field": field, "source_text": text, "source_role": "not-classified",
            "evaluation": evaluation}


def EvaluateVerifiedCycloneDxLicenses(
    state: ModelState, record: EvidenceRecord, provenance: ModelProvenance,
    image_identity: ImageIdentity, workspace_root: Path, policy: LicensePolicy,
) -> dict[str, object]:
    """Verify a complete original CycloneDX 1.6 inventory and project its independent assertions.

    Args:
        state: Existing owning immutable model snapshot; no returned candidate is persisted.
        record: Exact original sbom acquisition manifest retained in the owning evidence store.
        provenance: Existing source/scope/time/version attribution matching the original manifest.
        image_identity: Explicit config or manifest identity bound to the source container root.
        workspace_root: Existing owning workspace, including a relocated evidence/model store.
        policy: Explicit exact LicensePolicy; its normalized rules and digest accompany the result.

    Returns:
        Bounded detached source/component/occurrence coordinates and separate policy results.
        Missing/empty license lists and unsupported accepted choices remain explicit unknowns.
        Sibling entries are never combined and no package/image compliance result is produced.

    Raises:
        ValueError: Typed inputs, existing inventory profile or 4096-row/one-MiB budget fails.
        EvidenceError: Original manifest, bytes or physical owning evidence integrity fails.

    This function reads local evidence, reuses the original inventory owner's full validation,
    and discards its in-memory candidate. It performs no network, collection or storage writes.
    The Internal result does not change saved schemas or the existing expression-policy profile.
    """

    if type(state) is not ModelState or type(record) is not EvidenceRecord or (
        type(provenance) is not ModelProvenance or type(image_identity) is not ImageIdentity
        or type(policy) is not LicensePolicy
    ):
        raise ValueError("invalid-cyclonedx-license-policy-input")

    raw = VerifyRecords(state, provenance, (record,), workspace_root)["sbom"]
    # Reuse complete original admission; normalized license assets are not assertion truth.
    ApplyVerifiedCycloneDx(state, record, provenance, image_identity, workspace_root)
    payload = ParseJson(raw, IMAGE_IMPORT_MAX_BYTES)
    components = Items(payload.get("components", []))
    rows = 0

    for value in components:
        rows += max(1, len(Items(Record(value).get("licenses", []))))

        if rows > MAX_CYCLONEDX_LICENSE_ROWS:
            raise ValueError("cyclonedx-license-policy-limit")

    projected = []

    for component_index, value in enumerate(components):
        component = Record(value)
        identity = PackageIdentity.FromPurl(component["purl"])
        choices = Items(component.get("licenses", []))
        assertions = []

        for license_index, choice in enumerate(choices):
            assertions.append({"license_index": license_index,
                               **LicenseChoice(Record(choice), policy)})

        if not choices:
            information_state = "empty" if "licenses" in component else "omitted"
            assertions.append({"license_index": None, "source_field": None, "source_text": None,
                "source_role": "not-classified", "information_state": information_state,
                "evaluation": {"status": "unknown", "reason": "source-" + information_state,
                               "atoms": []}})

        projected.append({"component_index": component_index,
                          "source_bom_ref": component["bom-ref"],
                          "package_reference": identity.Object(state.workspace_id).Reference(),
                          "assertions": assertions})

    result: dict[str, object] = {
        "profile": CYCLONEDX_LICENSE_POLICY_PROFILE, "policy": policy.Description(),
        "image_reference": image_identity.Object(state.workspace_id).Reference(),
        "image_digest": image_identity.digest, "image_digest_kind": image_identity.digest_kind,
        "evidence_id": record.evidence_id, "source_sha256": record.reference.sha256,
        "provenance": json.loads(CanonicalModelJson(provenance)), "components": projected,
    }

    if len(CanonicalModelJson(result)) > MAX_CYCLONEDX_LICENSE_POLICY_BYTES:
        raise ValueError("cyclonedx-license-policy-limit")

    return result
