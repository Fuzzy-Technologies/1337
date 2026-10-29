# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal read-only image inventory and explicitly configured Docker use projection."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TextIO

from fuzzy1337.evidence import EvidenceError
from fuzzy1337.images import ImageIdentity
from fuzzy1337.model import CanonicalModelJson, LocalModelStore, ModelState, RelationKind
from fuzzy1337.report_commands import OpenReportInput, ReportFailure
from fuzzy1337.sbom_commands import (
    CheckKnownSbomSources,
    SbomEvidenceStore,
    SbomFailure,
    SbomParser,
    SbomPath,
)
from fuzzy1337.workspace import LocalWorkspaceStore

MAX_IMAGE_SBOM_VIEW_BYTES = 1024 * 1024


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

        for target, relation_reference in children.get(source, ()):
            # Another image's inventory cannot be borrowed through an arbitrary contains edge.
            if objects[target].attributes.get("asset_type") != "package":
                continue

            containment.add(relation_reference)

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
