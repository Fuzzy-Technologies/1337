# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal read-only image inventory and explicitly configured Docker use projection."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TextIO, cast

from fuzzy1337.evidence import EvidenceError
from fuzzy1337.images import ImageIdentity, VerifyRecords
from fuzzy1337.license_policy import EvaluateLicenseExpression, LicensePolicy
from fuzzy1337.model import CanonicalModelJson, LocalModelStore, ModelState, RelationKind
from fuzzy1337.report_commands import OpenReportInput, ReportFailure
from fuzzy1337.sbom_commands import (
    CheckKnownSbomSources,
    SbomEvidenceStore,
    SbomFailure,
    SbomParser,
    SbomPath,
    SourceFact,
)
from fuzzy1337.sbom_graph import GraphCandidates
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceState

MAX_IMAGE_SBOM_VIEW_BYTES = 1024 * 1024
MAX_IMAGE_LICENSE_SOURCES = 64
MAX_IMAGE_LICENSE_ASSERTIONS = 4096


def ImageSbomView(model: ModelState, image: ImageIdentity) -> dict[str, object]:
    """Select saved containment and Docker associations for exactly one immutable image.

    Args:
        model: Owner-read, evidence-verified canonical snapshot.
        image: Explicit config or manifest identity; equal bytes never merge their meanings.

    Returns:
        Sorted original references, without creating transitive edges or runtime assessments.

    Raises:
        SbomFailure: The selected identity is absent or contradicts its image fields.
    """

    reference = image.Object(model.workspace_id).Reference()
    objects = {item.Reference(): item for item in model.objects}
    selected = objects.get(reference)

    if selected is None:
        raise SbomFailure("image-not-found")

    if any(selected.attributes.get(name) != value for name, value in (
        ("asset_type", "image"), ("digest", image.digest), ("digest_kind", image.digest_kind),
    )):
        raise SbomFailure("image-identity")

    children: dict[str, list[tuple[str, str]]] = {}

    for relation in model.relations:
        if relation.kind is RelationKind.CONTAINS:
            children.setdefault(relation.source_reference, []).append(
                (relation.target_reference, relation.Reference()))

    visited = {reference}
    frontier = [reference]
    containment = set()

    while frontier:
        source = frontier.pop()

        for target, relationReference in children.get(source, ()):
            # Another image's inventory cannot be borrowed through an arbitrary contains edge.
            if objects[target].attributes.get("asset_type") != "package":
                continue

            containment.add(relationReference)

            if target not in visited:
                visited.add(target)
                frontier.append(target)

    uses = []

    for relation in model.relations:
        container = objects[relation.target_reference]

        if image.digest_kind == "config" and relation.kind is RelationKind.RELATED_TO and (
            relation.source_reference == reference
            and relation.attributes.get("association") == "configured-image-use"
            and relation.attributes.get("basis") == "supplied-inspect"
            and container.attributes.get("asset_type") == "container"
            and container.attributes.get("provider") == "inventory.docker-inspect"
            and container.attributes.get("image_reference") == reference
        ):
            uses.append({"container_reference": container.Reference(),
                "relation_reference": relation.Reference(), "runtime_reachability": "unknown",
                "runtime_reason": "not-evaluated"})

    packages = sorted(visited - {reference})

    return {"image_reference": reference, "image_digest": image.digest,
        "image_digest_kind": image.digest_kind, "package_references": packages,
        "containment_relation_references": sorted(containment),
        "inventory_status": "observed" if packages else "unknown", "docker_uses": uses}


def ImageLicensePolicyView(model: ModelState, image: ImageIdentity, packages: Sequence[str],
                           workspace: WorkspaceState, root: Path,
                           policy: LicensePolicy) -> dict[str, object]:
    """Reparse exact original owned SPDX graph assertions before matching their license roles.

    Args:
        model: Evidence-verified saved model selected by the read-only image command.
        image: Exact selected config/manifest identity, never an equal-byte digest alias.
        packages: Original containment-selected package references from that same image view.
        workspace: Exact saved owner retaining the original acquisition manifest IDs.
        root: Existing physical owning workspace path selected by the command.
        policy: Explicit caller-authored bounded policy; unconfigured atoms remain unknown.

    Returns:
        Separate declared/concluded assertion decisions with original observation/source references
        and a reproducible policy digest. No package, image or compliance verdict is aggregated.

    Raises:
        SbomFailure: Original custody, exact interpretation equality or projection quotas fail.
        ValueError: Original source context or profile cannot be revalidated.
    """

    imageReference = image.Object(model.workspace_id).Reference()
    selected = set(packages)
    assertions = [item for item in model.observations if item.kind == "spdx-package-license"
        and item.subject_reference in selected
        and item.attributes.get("image_reference") == imageReference]

    if len(packages) > MAX_IMAGE_LICENSE_ASSERTIONS or len(assertions) > (
        MAX_IMAGE_LICENSE_ASSERTIONS
    ):
        raise SbomFailure("limit")

    store = SbomEvidenceStore(root / "evidence")
    originals: dict[tuple[str, bytes], set[str]] = {}
    retainedObservations = {item.Reference() for item in model.observations}
    results: dict[str, list[dict[str, object]]] = {reference: [] for reference in sorted(selected)}

    for assertion in sorted(assertions, key=lambda item: item.Reference()):
        evidenceId = assertion.attributes.get("evidence_id")

        if evidenceId is None:
            results[assertion.subject_reference].append({
                "observation_reference": assertion.Reference(), "status": "unknown",
                "reason": "unsupported-source-profile"})

            continue

        if type(evidenceId) is not str or evidenceId not in workspace.evidence_record_references:
            raise SbomFailure("license-source")

        key = (evidenceId, CanonicalModelJson(assertion.provenance))

        if key not in originals:
            if len(originals) >= MAX_IMAGE_LICENSE_SOURCES:
                raise SbomFailure("limit")

            record = store.Get(evidenceId)
            SourceFact(model, record, assertion.provenance, image, None)
            raw = VerifyRecords(model, assertion.provenance, (record,), root)["sbom"]
            _, _, facts = GraphCandidates(raw, model.workspace_id, record,
                                          assertion.provenance, image)
            aliases = {item.Reference() for item in facts if item.kind == "spdx-source-alias"}

            if not aliases.issubset(retainedObservations):
                raise SbomFailure("license-source")

            originals[key] = {item.Reference() for item in facts
                              if item.kind == "spdx-package-license"}

        if assertion.Reference() not in originals[key]:
            raise SbomFailure("license-source")

        roles = {}

        for role in ("declared", "concluded"):
            source = cast(Mapping[str, object], assertion.attributes[role])
            state = cast(str, source["state"])

            if state == "expression":
                decision = EvaluateLicenseExpression(source["expression"], policy)

            else:
                decision = {"status": "unknown", "reason": "source-" + state, "atoms": []}

            roles[role] = {"source": dict(source), "evaluation": decision}

        results[assertion.subject_reference].append({
            "observation_reference": assertion.Reference(),
            "evidence_id": evidenceId, "source_sha256": assertion.attributes["document_sha256"],
            "source_spdx_id": assertion.attributes["spdx_id"],
            "source_id": assertion.provenance.source_id, **roles})

    return {"policy": policy.Description(), "source_profile": "owned-spdx-graph-v1",
        "packages": [{"package_reference": reference, "assertions": values,
                      "status": "assertions-only" if values else "unknown",
                      "reason": "not-aggregated" if values else "no-selected-source-assertion"}
                     for reference, values in results.items()]}


def RunImageSbomView(arguments: Sequence[str], output: TextIO, *, json_output: bool) -> int:
    """Verify the saved owners and original evidence before exposing one bounded image view.

    Args:
        arguments: Explicit workspace, immutable digest and digest kind selections.
        output: Caller-owned terminal destination; no original bytes or paths are emitted.
        json_output: Emit the Internal schema-one result instead of a concise human view.

    Returns:
        Zero for a verified view, two for invalid configuration, four for refused saved state,
        or 130 for interruption. No persistence operation is performed.
    """

    outcome: dict[str, object] = {"schema_version": 1, "command": "sbom.image",
        "status": "failed", "failure": None}
    phase = "configuration"
    status = 4

    try:
        options = SbomParser().parse_args(arguments)
        policy = None

        if options.license_policy is not None:
            policy = LicensePolicy(options.license_policy, tuple(options.allow_license),
                                   tuple(options.deny_license))

        elif options.allow_license or options.deny_license:
            raise SbomFailure("configuration", 2)

        image = ImageIdentity(options.image_digest, options.image_digest_kind)
        root = SbomPath(options.workspace)
        phase = "integrity"
        workspace = LocalWorkspaceStore(root).Open()
        basis = LocalModelStore(root).Open()
        CheckKnownSbomSources(SbomEvidenceStore(root / "evidence"), None, workspace, basis)
        original = OpenReportInput(root)

        if original.workspace != workspace or original.report.state != basis:
            raise SbomFailure("basis-changed")

        view = ImageSbomView(basis, image)

        if policy is not None:
            view["license_policy"] = ImageLicensePolicyView(
                basis, image, cast(list[str], view["package_references"]), workspace, root, policy)

        if LocalWorkspaceStore(root).Open() != workspace or LocalModelStore(root).Open() != basis:
            raise SbomFailure("basis-changed")

        candidate = {**outcome, "status": "succeeded", "model_revision": basis.revision,
            "snapshot_sha256": original.report.SnapshotDigest(), **view}

        if len(CanonicalModelJson(candidate)) > MAX_IMAGE_SBOM_VIEW_BYTES:
            raise SbomFailure("limit")

        outcome = candidate
        status = 0

    except SbomFailure as error:
        outcome = {"schema_version": 1, "command": "sbom.image", "status": "failed",
                   "failure": error.category}
        status = error.status

    except ReportFailure as error:
        outcome["failure"] = error.kind

    except KeyboardInterrupt:
        outcome["failure"] = "interrupted"
        status = 130

    except (EvidenceError, OSError, ValueError, TypeError, OverflowError, RecursionError):
        outcome["failure"] = phase
        status = 2 if phase == "configuration" else 4

    except Exception:
        outcome["failure"] = "internal"

    if json_output:
        output.write(CanonicalModelJson(outcome).decode("utf-8") + "\n")

    else:
        output.write(f"sbom.image: {outcome['status']}\n")

        if status == 0:
            output.write(f"image_reference: {outcome['image_reference']}\n")
            output.write(f"model_revision: {outcome['model_revision']}\n")
            output.write(CanonicalModelJson(view).decode("utf-8") + "\n")

        else:
            output.write(f"failure: {outcome['failure']}\n")

    return status
