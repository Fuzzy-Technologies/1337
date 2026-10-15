# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal explicit read-only selected-graph path analysis through existing evidence owners."""

from __future__ import annotations

import argparse
import os
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any, TextIO, cast

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.artifact_inputs import MatchesArtifactReadIdentity, PhysicalIdentity
from fuzzy1337.evidence import (
    EVIDENCE_MANIFEST_MAX_BYTES,
    CheckStorageEntry,
    EvidenceError,
    EvidenceProvenance,
    EvidenceRecord,
    LocalEvidenceStore,
    ParseEvidenceManifest,
    RequireEvidenceDigest,
)
from fuzzy1337.model import (
    CanonicalModelJson,
    LocalModelStore,
    ModelState,
    ObjectKind,
    Observation,
    RelationKind,
)
from fuzzy1337.path_analysis import (
    AnalyzeReachabilityPaths,
    PathAnalysis,
    PathAnalysisLimits,
)
from fuzzy1337.reachability import (
    AssessmentJson,
    ClaimFields,
    Declaration,
    Fields,
    Integer,
    Items,
    ProjectReachability,
    ReachabilityLimits,
    ReachabilityModelVersion,
    ReadReachabilityClaims,
    Reference,
    Text,
    Time,
    Version,
)
from fuzzy1337.runtime_commands import RuntimeArgumentParser, RuntimeFailure, RuntimePath
from fuzzy1337.workspace import LocalWorkspaceStore

__all__ = ("PathParser", "RunPathCommands")

MAX_PATH_OUTPUT_BYTES = 1024 * 1024
ASSESSMENT_BYTES = 256 * 1024
SUPPORT_BYTES = 64 * 1024


def PathParser() -> argparse.ArgumentParser:
    """Declare one explicit source/target analysis without discovery, grouping or output files.

    Returns:
        Parser requiring complete model pins, original selections, replay clock and all budgets.
    """

    parser = RuntimeArgumentParser(prog="1337 paths", add_help=False)
    parser.add_argument("action", choices=("analyze",))
    parser.add_argument("workspace", type=Path)
    parser.add_argument("--expected-revision", required=True, type=int)
    parser.add_argument("--expected-snapshot-sha256", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--transition", required=True, action="append")
    assessments = parser.add_mutually_exclusive_group(required=True)
    assessments.add_argument("--assessment", action="append")
    assessments.add_argument("--no-assessments", action="store_true")

    for name in ("context", "scope-reference", "as-of"):
        parser.add_argument("--" + name, required=True)

    for name in ("max-age-seconds", "max-depth", "max-paths", "max-work", "max-frontier",
                 "max-cut-work"):
        parser.add_argument("--" + name, required=True, type=int)

    return parser


class PathEvidenceStore(LocalEvidenceStore):
    """Preflight selected immutable manifests and physical blobs without unrelated alias reads."""

    def __init__(self, root: Path, workspace_id: str, scope: str) -> None:
        """Retain exact offline ownership context without touching any stored artifact.

        Args:
            root: Explicit existing local evidence directory.
            workspace_id: Exact current owning workspace identity.
            scope: Explicit offline attribution shared by assessments and support.
        """

        super().__init__(root)
        self.workspace_id = workspace_id
        self.scope = scope

    def ReadStoredBytes(self, parts: tuple[str, ...], max_bytes: int) -> bytes:
        """Read bounded selected metadata/assessment bytes with stable single-link observations.

        Args:
            parts: Fixed content-addressed relative path through the existing storage owner.
            max_bytes: Original manifest/schema byte ceiling, never a declared allocation hint.

        Returns:
            Unchanged bounded bytes after same-view and path/handle identity checks.
        """

        selected = self.StoragePath(parts)
        before = CheckStorageEntry(selected, directory=False)

        if before.st_nlink != 1 or not 0 <= before.st_size <= max_bytes:
            raise RuntimeFailure("integrity")

        with selected.open("rb") as stream:
            opened = os.fstat(stream.fileno())

            if opened.st_nlink != 1 or not MatchesArtifactReadIdentity(before, opened):
                raise RuntimeFailure("integrity")

            raw = stream.read(max_bytes + 1)
            finished = os.fstat(stream.fileno())

        after = CheckStorageEntry(selected, directory=False)

        if finished.st_nlink != 1 or after.st_nlink != 1 or (
            PhysicalIdentity(before) != PhysicalIdentity(after)
            or PhysicalIdentity(opened) != PhysicalIdentity(finished)
            or not MatchesArtifactReadIdentity(after, finished)
            or len(raw) != before.st_size
        ):
            raise RuntimeFailure("integrity")

        return raw

    def Manifest(self, identity: str, *, assessment: bool) -> EvidenceRecord:
        """Validate original typed identity/context/profile/size before any referenced raw read.

        Args:
            identity: Explicit original assessment or source-declared support manifest ID.
            assessment: Require the closed assessment profile; support roles remain SDK-owned.

        Returns:
            Exact canonical immutable record after non-following physical blob size preflight.
        """

        Reference(identity, "sha256")
        record = ParseEvidenceManifest(self.ReadStoredBytes(
            ("records", identity[7:] + ".json"), EVIDENCE_MANIFEST_MAX_BYTES))

        if type(record) is not EvidenceRecord:
            raise RuntimeFailure("integrity")

        if type(record.reference) is not EvidenceReference or (
            type(record.provenance) is not EvidenceProvenance
            or record.evidence_id != identity
            or record.provenance.workspace_id != self.workspace_id
            or record.provenance.scope_reference != self.scope
        ):
            raise RuntimeFailure("integrity")

        maximum = ASSESSMENT_BYTES if assessment else SUPPORT_BYTES
        Integer(record.reference.size_bytes, 0, maximum)

        if assessment and (record.reference.role != "reachability-claims" or (
            record.reference.media_type != "application/json"
            or record.provenance.source_version != "1"
            or record.provenance.execution is not None
            or record.provenance.invocation_sha256 is not None
        )):
            raise RuntimeFailure("integrity")

        blob = self.StoragePath(("blobs", "sha256", record.reference.sha256))
        physical = CheckStorageEntry(blob, directory=False)

        if physical.st_nlink != 1 or physical.st_size != record.reference.size_bytes or (
            physical.st_size > maximum
        ):
            raise RuntimeFailure("integrity")

        return record


def PreflightProof(entry: dict[str, object], subject: str,
                   records: tuple[EvidenceRecord, ...], observations: dict[str, Observation],
                   scope: str) -> None:
    """Reject substituted retained support joins before any selected support blob is read.

    Args:
        entry: Original SDK-parsed declaration basis or blocking-control proof entry.
        subject: Original selected relation or explicitly named control reference.
        records: Metadata-only preflighted original supporting manifests.
        observations: Exact current owning model observations indexed by reference.
        scope: Explicit offline attribution, granting no execution authority.

    Returns:
        Nothing; missing basis/evidence remains for the actual SDK's attributed UNKNOWN outcome.
    """

    observation = observations.get(cast(str, entry["observation_reference"]))

    if observation is None:
        return

    provenance = observation.provenance

    if observation.kind != "reachability-support" or observation.subject_reference != subject or (
        provenance.scope_reference != scope
    ):
        raise RuntimeFailure("integrity")

    references = [CanonicalModelJson(record.reference) for record in records]

    if records and (len(set(references)) != len(references) or set(references) != {
        CanonicalModelJson(reference) for reference in provenance.evidence_references
    }):
        raise RuntimeFailure("integrity")

    for record in records:
        actual = record.provenance

        if (actual.source_id, actual.tool_version, actual.scope_reference,
            actual.finished_at, actual.execution) != (
            provenance.source_id, provenance.provider_version, provenance.scope_reference,
            provenance.observed_at, provenance.execution,
        ):
            raise RuntimeFailure("integrity")


def PreflightAssessments(store: PathEvidenceStore, identities: tuple[str, ...],
                         model: ModelState, context: str) -> tuple[EvidenceRecord, ...]:
    """Preflight every selected assessment and all declared support before SDK support reads.

    Args:
        store: Exact local read owner with current workspace and offline scope attribution.
        identities: Zero or up to 32 distinct independently selected original assessment pins.
        model: Exact owner-read current model; stale assessment pins remain the SDK's UNKNOWN input.
        context: Explicit attestation context, never authentication or execution grant.

    Returns:
        Original selected typed assessment records, never manufactured sealed claim objects.
    """

    if type(identities) is not tuple or len(identities) > 32 or (
        len(set(identities)) != len(identities)
    ):
        raise RuntimeFailure("configuration", 2)

    records = tuple(store.Manifest(identity, assessment=True) for identity in identities)
    support: dict[str, EvidenceRecord] = {}
    observations = {item.Reference(): item for item in model.observations}
    declarations = 0

    for record in records:
        envelope = Fields(AssessmentJson(store.Read(record.reference)), {
            "profile_version", "assessment_kind", "model_version", "context_reference",
            "scope_reference", "claims"})
        Integer(envelope["profile_version"], 1, 1)
        version = Version(envelope["model_version"])

        if envelope["assessment_kind"] != "supplied-transition-attestation" or (
            version.workspace_id != model.workspace_id
            or Text(envelope["context_reference"]) != context
            or Text(envelope["scope_reference"]) != store.scope
        ):
            raise RuntimeFailure("integrity")

        claims = Items(envelope["claims"], 2048)
        declarations += len(claims)

        if declarations > 2048:
            raise RuntimeFailure("integrity")

        for candidate in claims:
            declaration = Declaration(candidate)

            for proof in [*cast(list[dict[str, Any]], declaration["basis"]),
                          *cast(list[dict[str, Any]], declaration["blocking_controls"])]:
                selected = []

                for identity in cast(list[str], proof["evidence_manifest_ids"]):
                    if identity not in support:
                        if len(support) >= 256:
                            raise RuntimeFailure("integrity")

                        support[identity] = store.Manifest(identity, assessment=False)

                    selected.append(support[identity])

                subject = cast(str, proof.get("control_reference",
                                              declaration["relation_reference"]))
                PreflightProof(proof, subject, tuple(selected), observations, store.scope)

    return records


class OutputBudget:
    """Bound incremental DTO record construction before building a large repeated explanation."""

    def __init__(self) -> None:
        """Reserve a small fixed envelope budget and own one per-render accounting counter."""

        self.charged = 4096

    def Records(self, values: Iterable[dict[str, object]]) -> list[dict[str, object]]:
        """Charge each compact record before retaining it in a detached output collection.

        Args:
            values: Lazy safe dictionaries without raw attributes or private SDK fields.

        Returns:
            Bounded detached list; excessive output fails instead of truncating explanation facts.
        """

        result = []

        for value in values:
            self.charged += len(CanonicalModelJson(value)) + 1

            if self.charged > MAX_PATH_OUTPUT_BYTES:
                raise RuntimeFailure("output-limit")

            result.append(value)

        return result


def PathDocument(result: PathAnalysis) -> dict[str, object]:
    """Project original SDK explanations into a bounded safe DTO without seals or source bodies.

    Args:
        result: Exact actual pure consumer output over its owning-read sealed projection.

    Returns:
        Explicit profile-one path/coverage/cut facts with preserved reasons and original references.
    """

    if type(result) is not PathAnalysis:
        raise RuntimeFailure("integrity")

    search = result.search
    projection = search.projection
    budget = OutputBudget()
    transitions = []

    for transition in projection.transitions:
        claims = []

        for claim in transition.claims:
            fields = ClaimFields(claim)
            version = claim.model_version
            fields["model_version"] = {"schema_version": version.schema_version,
                "workspace_id": version.workspace_id, "revision": version.revision,
                "snapshot_sha256": version.snapshot_sha256}
            claims.extend(budget.Records((fields,)))

        header: dict[str, object] = {"relation_reference": transition.relation_reference,
            "source_reference": transition.source_reference, "target_reference":
            transition.target_reference, "state": transition.state.value,
            "reasons": list(transition.reasons), "claims": []}
        rendered = budget.Records((header,))[0]
        rendered["claims"] = claims
        transitions.append(rendered)

    paths = budget.Records({"path_reference": path.path_reference, "nodes": list(path.nodes),
        "hops": [hop.relation_reference for hop in path.hops], "state": path.state.value,
        "confidence_estimates": [{"claim_reference": estimate.claim_reference,
            "relation_reference": estimate.relation_reference,
            "declared_state": estimate.declared_state.value,
            "declared_confidence": estimate.declared_confidence,
            "effective_confidence": estimate.effective_confidence}
            for estimate in path.confidence_estimates],
        "decisive_blocking_claims": [claim.claim_reference
                                     for claim in path.decisive_blocking_claims],
        "semantics": path.semantics} for path in search.paths)
    participation = budget.Records({"kind": item.kind, "reference": item.reference,
        "path_references": list(item.path_references), "state_counts": dict(item.state_counts)}
        for item in result.participation)
    leverage = budget.Records({"kind": item.kind, "reference": item.reference,
        "removed_path_references": list(item.removed_path_references),
        "remaining_candidate_count": item.remaining_candidate_count}
        for item in result.removal_leverage)
    cuts = result.choke_points

    def Elements(values: object) -> list[dict[str, object]]:
        """Render original cut members with the same incremental byte accounting."""

        return budget.Records({"kind": item.kind, "reference": item.reference}
                              for item in cast(Any, values))

    return {"analysis_reference": result.analysis_reference, "semantics": result.semantics,
        "projection_reference": projection.projection_reference,
        "transitions": transitions, "coverage": {"admitted_claims": projection.admitted_claims,
            "unusable_claims": projection.unusable_claims,
            "unassessed_transitions": projection.unassessed_transitions,
            "conflicting_transitions": projection.conflicting_transitions,
            "unknown_transitions": projection.unknown_transitions},
        "search": {"query_reference": search.query_reference, "source_reference":
            search.source_reference, "target_reference": search.target_reference,
            "limits": {"max_depth": search.limits.max_depth, "max_paths": search.limits.max_paths,
                "max_work": search.limits.max_work, "max_frontier": search.limits.max_frontier},
            "paths": paths, "complete": search.complete,
            "no_candidate_path": search.no_candidate_path,
            "reasons": list(search.reasons), "examined_successors": search.examined_successors,
            "pending_prefixes": search.pending_prefixes, "unexamined_successors":
            search.unexamined_successors, "depth_cut_prefixes": search.depth_cut_prefixes,
            "claim_scope": search.claim_scope},
        "participation": participation, "removal_leverage": leverage,
        "nonblocked_returned_candidates": result.nonblocked_returned_candidates,
        "leverage_scope": result.leverage_scope,
        "cuts": {"max_cut_work": result.cut_limits.max_cut_work,
            "candidate_route_exists": cuts.candidate_route_exists,
            "witness": None if cuts.witness is None else {"nodes": list(cuts.witness.nodes),
                "relation_references": list(cuts.witness.relation_references)},
            "verified": Elements(cuts.verified),
            "alternatives_exist": Elements(cuts.alternatives_exist),
            "unverified": Elements(cuts.unverified), "complete": cuts.complete,
            "examined_successors": cuts.examined_successors, "reasons": list(cuts.reasons),
            "claim_scope": cuts.claim_scope}}


def RunPathCommands(arguments: Sequence[str], output: TextIO, *, json_output: bool = False) -> int:
    """Analyze only an explicitly pinned saved selected graph without any durable writes.

    Args:
        arguments: Analyze action, existing workspace, selections, clock and finite budgets.
        output: Caller-owned stream receiving safe bounded JSON or a concise human explanation.
        json_output: Emit a schema-one DTO without raw evidence, observations or private seals.

    Returns:
        Zero for completed bounded analysis, two for invalid configuration, four for input/proof/
        output failure, and 130 for interruption. Truncated analysis is honest completed output;
        no-path/cuts/completeness concern only the explicit selected graph and declared limits.
    """

    parser = PathParser()

    if "--help" in arguments or "-h" in arguments:
        parser.print_help(file=output)

        return 0

    outcome: dict[str, object] = {"schema_version": 1, "command": "paths.analyze",
        "status": "failed",
        "failure": None, "model_version": None, "analysis": None,
        "core_mutation": "none", "evidence_mutation": "none", "authority": "none"}
    status = 4
    phase = "configuration"

    try:
        options = parser.parse_args(arguments)
        if type(options.expected_revision) is not int or options.expected_revision < 0:
            raise RuntimeFailure("configuration", 2)

        RequireEvidenceDigest(options.expected_snapshot_sha256)
        source, target = Reference(options.source, "object"), Reference(options.target, "object")
        transitions = tuple(Reference(value, "relation") for value in options.transition)
        assessments = tuple(Reference(value, "sha256") for value in (options.assessment or ()))

        if source == target or not 1 <= len(transitions) <= 2048 or (
            len(set(transitions)) != len(transitions) or len(assessments) > 32
            or len(set(assessments)) != len(assessments)
        ):
            raise RuntimeFailure("configuration", 2)

        context, scope = Text(options.context), Text(options.scope_reference)
        at = Time(options.as_of)
        age = Integer(options.max_age_seconds, 0, 604800)
        search_limits = ReachabilityLimits(options.max_depth, options.max_paths, options.max_work,
                                          options.max_frontier)
        cut_limits = PathAnalysisLimits(options.max_cut_work)
        root = RuntimePath(options.workspace)
        phase = "basis"
        workspace = LocalWorkspaceStore(root).Open()
        model = LocalModelStore(root).Open()
        version = ReachabilityModelVersion(1, workspace.workspace_id, options.expected_revision,
                                           options.expected_snapshot_sha256)

        if ReachabilityModelVersion.FromModel(model) != version:
            raise RuntimeFailure("basis")

        eligible = {ObjectKind.DOMAIN, ObjectKind.HOST, ObjectKind.ASSET, ObjectKind.PORT,
                    ObjectKind.SERVICE, ObjectKind.ENDPOINT, ObjectKind.TECHNOLOGY}
        objects = {item.Reference() for item in model.objects if item.identity.kind in eligible}
        relations = {item.Reference(): item for item in model.relations}

        if len(objects) > 512 or source not in objects or target not in objects or any(
            reference not in relations
            or relations[reference].kind is not RelationKind.RELATED_TO
            or relations[reference].source_reference not in objects
            or relations[reference].target_reference not in objects for reference in transitions
        ):
            raise RuntimeFailure("selection", 2)

        store = PathEvidenceStore(root / "evidence", workspace.workspace_id, scope)
        phase = "proof"
        records = PreflightAssessments(store, assessments, model, context)
        claims = ReadReachabilityClaims(model, records, workspace_root=root,
            expected_model_version=version, context_reference=context, scope_reference=scope,
            at=at, max_age_seconds=age)
        projection = ProjectReachability(model, transitions, claims, expected_model_version=version)
        result = AnalyzeReachabilityPaths(projection, model, source, target,
                                         search_limits=search_limits, cut_limits=cut_limits)
        phase = "output"
        document = PathDocument(result)

        if LocalWorkspaceStore(root).Open() != workspace or LocalModelStore(root).Open() != model:
            raise RuntimeFailure("basis-changed")

        outcome.update({"status": "completed", "model_version": {"schema_version":
            version.schema_version, "workspace_id": version.workspace_id,
            "revision": version.revision,
            "snapshot_sha256": version.snapshot_sha256}, "context_reference": context,
            "scope_reference": scope, "as_of": at, "max_age_seconds": age,
            "assessment_manifest_ids": sorted(assessments), "analysis": document})

        outcome["exit_code"] = 0

        if len(CanonicalModelJson(outcome)) + 1 > MAX_PATH_OUTPUT_BYTES:
            raise RuntimeFailure("output-limit")

        status = 0

    except RuntimeFailure as error:
        outcome["failure"] = error.category
        status = error.status

    except KeyboardInterrupt:
        outcome["failure"] = "interrupted"
        status = 130

    except (OSError, EvidenceError, ValueError, TypeError, AttributeError,
            OverflowError, RecursionError):
        outcome["failure"] = phase
        status = 2 if phase == "configuration" else 4

    if status != 0:
        outcome.update({"status": "failed", "analysis": None})

    outcome["exit_code"] = status

    if json_output:
        output.write(CanonicalModelJson(outcome).decode("utf-8") + "\n")

    else:
        output.write("Selected-graph path analysis " + str(outcome["status"]) +
                     " (exit " + str(status) + ").\n")

        if status == 0:
            output.write("Returned candidate paths: " + str(len(result.search.paths)) +
                "; enumeration complete: " + str(result.search.complete).lower() +
                "; verified cuts: " + str(len(result.choke_points.verified)) +
                "; cut checks complete: " + str(result.choke_points.complete).lower() + ".\n")
            output.write("Original hop attestations and structural cuts only; "
                         "physical access, global completeness and mitigation efficacy "
                         "are unassessed.\n")

    output.flush()

    return status
