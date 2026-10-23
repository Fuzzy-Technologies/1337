# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal original JSON OpenAPI product import without transport or execution authority."""

from __future__ import annotations

import argparse
import hashlib
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import TextIO

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.adapters.contracts import RequireIdentifier
from fuzzy1337.api_commands import (
    ApiEvidenceStore,
    PreflightApiReferences,
    PreflightKnownApiReferences,
    ReadOwnedApiFile,
    RequireApiRecord,
)
from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.evidence import (
    EVIDENCE_MANIFEST_MAX_BYTES,
    EvidenceError,
    EvidenceProvenance,
    EvidenceRecord,
    ParseEvidenceManifest,
    RequireEvidenceDigest,
)
from fuzzy1337.model import (
    CanonicalModelJson,
    LocalModelStore,
    ModelProvenance,
    ModelState,
    ObjectKind,
    Observation,
    Relation,
    SecurityObject,
)
from fuzzy1337.openapi import (
    MAX_OPENAPI_BYTES,
    MAX_OPENAPI_OPERATIONS,
    ApiImportBaseUrl,
    ApiOperation,
    CheckOpenApiTarget,
    ImportOpenApi,
    OpenApiImport,
    ProjectOpenApi,
)
from fuzzy1337.policy import UtcNow
from fuzzy1337.report_commands import MAX_EXPORT_ACQUISITIONS, OpenReportInput
from fuzzy1337.requests import Endpoint, RequestDigest, RequestsFromObject
from fuzzy1337.runtime_commands import (
    CheckBases,
    ReferenceProposal,
    RuntimeArgumentParser,
    RuntimeFailure,
    RuntimePath,
)
from fuzzy1337.scope import LocalScopeStore, ScopeSnapshot, Target, TargetKind
from fuzzy1337.workspace import (
    LocalWorkspaceStore,
    RequireWorkspaceInteger,
    RequireWorkspaceText,
    WorkspaceBusyError,
    WorkspaceConflictError,
    WorkspaceState,
)

OPENAPI_PRODUCT_PROFILE = "openapi-json"
_SOURCE_ID = "openapi-import"
_SOURCE_VERSION = "1"
_FACT_KIND = "openapi-import-source"
_FACT_FIELDS = frozenset({
    "profile", "evidence_id", "source_sha256", "source_version", "base_url",
    "endpoint_count", "operation_count", "operation_references",
    "read_actor_reference", "read_consent_reference",
})


def OpenApiBase(value: object) -> str | None:
    """Require exact canonical raw base spelling, preserving explicit-versus-absent custody.

    Args:
        value: Explicit canonical resolution URL or None; no URL is contacted.

    Returns:
        Original spelling unchanged or None.
    """

    if value is None:
        return None

    if type(value) is not str or Target(TargetKind.URL, value).value != value:
        raise RuntimeFailure("configuration", 2)

    ApiImportBaseUrl(value)

    return value


def OpenApiEndpoint(value: SecurityObject) -> Endpoint:
    """Recover one concrete structural endpoint without interpreting arbitrary object keys.

    Args:
        value: Existing typed endpoint whose complete request collection is independently read.

    Returns:
        The single existing endpoint shared by every retained request template.
    """

    templates = RequestsFromObject(value)

    if not templates or value.identity.kind is not ObjectKind.ENDPOINT:
        raise RuntimeFailure("source-context")

    endpoint = templates[0].endpoint

    if endpoint.PathVariables() or endpoint.Identity() != value.identity:
        raise RuntimeFailure("source-context")

    return endpoint


def OpenApiAttribution(record: EvidenceRecord, endpoint: Endpoint,
                       run: str) -> ModelProvenance:
    """Bind original source acquisition to one exact derived endpoint and caller run.

    Args:
        record: Closed original OpenAPI manifest already checked for ownership/profile.
        endpoint: Concrete structural endpoint; membership is checked separately.
        run: Explicit bounded caller run reference, identical on replay.

    Returns:
        Existing model provenance without a job, invocation or execution grant.
    """

    return ModelProvenance(_SOURCE_ID, run, record.provenance.finished_at,
        record.provenance.scope_reference,
        Target(TargetKind.URL, endpoint.origin + endpoint.path_template).Reference(),
        None, (record.reference,))


def KnownOpenApiFacts(state: ModelState, record: EvidenceRecord) -> tuple[Observation, ...]:
    """Verify complete known original custody before any retained raw source read.

    Args:
        state: Current owner-read model basis containing original per-endpoint custody.
        record: Preflighted immutable original manifest, independent of its blob digest.

    Returns:
        Nonempty canonical facts with coherent base/run/consent and complete operation counts.
    """

    facts = tuple(item for item in state.observations if item.kind == _FACT_KIND
        and item.attributes.get("evidence_id") == record.evidence_id)

    if not facts or len(facts) > MAX_OPENAPI_OPERATIONS:
        raise RuntimeFailure("source-context")

    subjects = {item.Reference(): item for item in state.objects}
    identities: set[str] = set()
    references: set[str] = set()
    context = None

    for fact in facts:
        attributes = fact.attributes

        if set(attributes) != _FACT_FIELDS or (
            attributes["profile"] != OPENAPI_PRODUCT_PROFILE
            or attributes["source_sha256"] != record.reference.sha256
            or attributes["source_version"] != _SOURCE_VERSION
        ):
            raise RuntimeFailure("source-context")

        try:
            base = OpenApiBase(attributes["base_url"])

        except (ValueError, RuntimeFailure):
            raise RuntimeFailure("source-context") from None
        actor, consent = attributes["read_actor_reference"], attributes["read_consent_reference"]

        if type(actor) is not str or type(consent) is not str:
            raise RuntimeFailure("source-context")

        ArtifactReadConsent(actor, consent)
        endpoint_count = RequireWorkspaceInteger(attributes["endpoint_count"], "endpoint_count")
        operation_count = RequireWorkspaceInteger(attributes["operation_count"], "operation_count")
        current = (base, fact.provenance.run_reference, actor, consent,
                   endpoint_count, operation_count)

        if endpoint_count != len(facts) or not 1 <= operation_count <= MAX_OPENAPI_OPERATIONS or (
            context is not None and context != current
        ) or fact.subject_reference in identities:
            raise RuntimeFailure("source-context")

        context = current
        identities.add(fact.subject_reference)
        subject = subjects.get(fact.subject_reference)

        if subject is None:
            raise RuntimeFailure("source-context")

        endpoint = OpenApiEndpoint(subject)

        if fact.provenance != OpenApiAttribution(record, endpoint,
                                                fact.provenance.run_reference):
            raise RuntimeFailure("source-context")

        selected = attributes["operation_references"]
        operations = subject.attributes.get("openapi_operations")

        if type(selected) is not tuple or not selected or (
            len(selected) > MAX_OPENAPI_OPERATIONS or type(operations) is not tuple
        ):
            raise RuntimeFailure("source-context")

        available = set()
        request_references = {item.Reference() for item in RequestsFromObject(subject)}

        for operation in operations:
            if not isinstance(operation, Mapping):
                raise RuntimeFailure("source-context")

            if operation.get("source_digest") != "sha256:" + record.reference.sha256:
                continue

            identity = RequestDigest("api-operation", {name: operation.get(name) for name in (
                "source_digest", "source_pointer", "request_reference", "media_type",
            )})

            if identity != operation.get("operation_reference") or (
                operation.get("request_reference") not in request_references
            ):
                raise RuntimeFailure("source-context")

            available.add(identity)

        if any(type(item) is not str for item in selected) or (
            tuple(sorted(set(selected))) != selected or set(selected) != available
            or references.intersection(selected)
        ):
            raise RuntimeFailure("source-context")

        references.update(selected)

    assert context is not None, "Nonempty original facts must contain one custody context."

    if len(references) != context[-1]:
        raise RuntimeFailure("source-context")

    return tuple(sorted(facts, key=lambda item: item.subject_reference))


def PreflightKnownOpenApiReferences(state: ModelState, workspace: WorkspaceState,
                                   root: Path) -> None:
    """Check known OpenAPI manifests, complete custody and aliases before generic raw readers.

    Args:
        state: Owner-read model basis; GraphQL retains its separate unchanged fact validator.
        workspace: Independently selected workspace retaining original acquisition references.
        root: Existing evidence partition, not another authoritative store.
    """

    evidence = ApiEvidenceStore(root, workspace.workspace_id, "scope:preflight",
                                profile=OPENAPI_PRODUCT_PROFILE)
    ids = set(workspace.evidence_record_references)

    for fact in state.observations:
        if fact.kind == _FACT_KIND:
            selected = fact.attributes.get("evidence_id")

            if type(selected) is not str:
                raise RuntimeFailure("integrity")

            ids.add(selected)

    if len(ids) > MAX_EXPORT_ACQUISITIONS:
        raise RuntimeFailure("limit")

    known_references = set()

    for identity in sorted(ids):
        if not identity.startswith("sha256:"):
            raise RuntimeFailure("integrity")

        RequireEvidenceDigest(identity[7:])
        record = ParseEvidenceManifest(evidence.ReadStoredBytes(
            ("records", identity[7:] + ".json"), EVIDENCE_MANIFEST_MAX_BYTES))

        if record.evidence_id != identity:
            raise RuntimeFailure("integrity")

        if record.reference.role == OPENAPI_PRODUCT_PROFILE:
            original = ApiEvidenceStore(root, workspace.workspace_id,
                record.provenance.scope_reference, profile=OPENAPI_PRODUCT_PROFILE)
            RequireApiRecord(record, workspace.workspace_id, record.provenance.scope_reference,
                             profile=OPENAPI_PRODUCT_PROFILE)
            KnownOpenApiFacts(state, record)
            PreflightApiReferences(state, workspace, record, original)
            known_references.add(record.reference)

        elif any(item.kind == _FACT_KIND and item.attributes.get("evidence_id") == identity
                 for item in state.observations):
            raise RuntimeFailure("integrity")

    entities: tuple[SecurityObject | Relation, ...] = (*state.objects, *state.relations)
    contexts = [item for entity in entities for item in entity.provenance]
    contexts.extend(item.provenance for item in state.observations)
    references = [*workspace.evidence_references,
        *(reference for item in contexts for reference in item.evidence_references)]

    for reference in references:
        if reference.role != OPENAPI_PRODUCT_PROFILE:
            continue

        if reference not in known_references:
            raise RuntimeFailure("source-context")

        evidence.CheckReference(reference)

        if any((other.sha256 == reference.sha256 or other.locator == reference.locator)
               and other != reference for other in references):
            raise RuntimeFailure("integrity")


def OpenApiProjection(imported: OpenApiImport, state: ModelState, record: EvidenceRecord,
                      run: str, base: str | None, consent: ArtifactReadConsent | None,
                      ) -> tuple[tuple[SecurityObject, ...], tuple[Observation, ...]]:
    """Produce every concrete endpoint patch and exact original source-custody collection.

    Args:
        imported: Whole original SDK import; no operation selection or filtering is admitted.
        state: Current model basis used for occupied collection and original custody checks.
        record: Actual closed original source acquisition.
        run: Caller run reference.
        base: Exact optional original resolution context.
        consent: Explicit file read consent, or None for known original replay.

    Returns:
        Complete compatible endpoint patches and their original per-endpoint source facts.
    """

    groups: dict[str, list[ApiOperation]] = {}

    for operation in imported.operations:
        endpoint = operation.template.endpoint

        if endpoint.PathVariables():
            raise RuntimeFailure("unsupported-path")

        groups.setdefault(endpoint.Identity().Reference(), []).append(operation)

    if not groups:
        raise RuntimeFailure("normalization")

    known = tuple(item for item in state.observations if item.kind == _FACT_KIND
        and item.attributes.get("evidence_id") == record.evidence_id)

    if known:
        known = KnownOpenApiFacts(state, record)
        first = known[0].attributes
        original = ArtifactReadConsent(str(first["read_actor_reference"]),
                                       str(first["read_consent_reference"]))

        if consent is not None and consent != original:
            raise RuntimeFailure("source-context")

        consent = original

    if consent is None:
        raise RuntimeFailure("source-context")

    patches, facts = [], []
    existing = {item.Reference(): item for item in state.objects}

    for reference in sorted(groups):
        operations = groups[reference]
        endpoint = operations[0].template.endpoint
        provenance = OpenApiAttribution(record, endpoint, run)
        grouped = OpenApiImport(imported.workspace_id, imported.specification_version,
                                imported.source_digest, tuple(operations))
        patch, = ProjectOpenApi(grouped, provenance=(provenance,))
        occupied = existing.get(reference)
        fields = {"request_templates", "openapi_operations"}

        if occupied is not None and fields.intersection(occupied.attributes):
            if not fields.issubset(occupied.attributes) or any(
                CanonicalModelJson(occupied.attributes[name]) !=
                CanonicalModelJson(patch.attributes[name]) for name in fields
            ):
                raise RuntimeFailure("occupied-endpoint")

        patches.append(patch)
        facts.append(Observation(_FACT_KIND, reference, {
            "profile": OPENAPI_PRODUCT_PROFILE, "evidence_id": record.evidence_id,
            "source_sha256": record.reference.sha256, "source_version": _SOURCE_VERSION,
            "base_url": base, "endpoint_count": len(groups),
            "operation_count": len(imported.operations),
            "operation_references": sorted(item.Reference() for item in operations),
            "read_actor_reference": consent.actor_ref,
            "read_consent_reference": consent.record_ref,
        }, provenance))

    proposed = tuple(facts)

    if known and proposed != known:
        raise RuntimeFailure("source-context")

    return tuple(patches), proposed


def OpenApiParser() -> argparse.ArgumentParser:
    """Declare the closed owned-file or known-original JSON import product grammar.

    Returns:
        Internal parser without fetching, YAML detection, transport or authentication options.
    """

    parser = RuntimeArgumentParser(prog="1337 api import openapi-json", add_help=False)
    parser.add_argument("action", choices=("import",))
    parser.add_argument("profile", choices=(OPENAPI_PRODUCT_PROFILE,))
    parser.add_argument("workspace", type=Path)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--file", type=Path)
    selection.add_argument("--evidence")

    for name in ("scope", "run"):
        parser.add_argument("--" + name, required=True)

    parser.add_argument("--expected-revision", type=int, required=True)
    parser.add_argument("--expected-workspace-revision", type=int, required=True)
    parser.add_argument("--base-url")
    parser.add_argument("--owner")
    parser.add_argument("--read-consent-reference")

    return parser


def CheckOpenApiScope(imported: OpenApiImport, scope: ScopeSnapshot,
                      clock: Callable[[], datetime]) -> None:
    """Check every concrete operation at current time without registering or contacting targets.

    Args:
        imported: Whole imported operation collection.
        scope: Matching owner-read current scope; revisions are checked separately.
        clock: Actual aware membership decision clock, invoked at each persistence boundary.
    """

    at = clock()

    for operation in imported.operations:
        endpoint = operation.template.endpoint

        if endpoint.PathVariables():
            raise RuntimeFailure("unsupported-path")

        CheckOpenApiTarget(operation,
            Target(TargetKind.URL, endpoint.origin + endpoint.path_template), scope, at=at)


def RunOpenApiCommands(arguments: Sequence[str], output: TextIO, *, json_output: bool = False,
                       clock: Callable[[], datetime] = UtcNow) -> int:
    """Import original JSON through independent evidence/model/workspace commit boundaries.

    Args:
        arguments: Explicit closed profile, source selection, read consent and current bases.
        output: Caller-owned non-secret summary stream; source text and paths are excluded.
        json_output: Emit one Internal schema-v1 terminal acknowledgement document.
        clock: Actual aware acquisition and scope-decision clock.

    Returns:
        Zero on success, two for invalid setup, four for other refusals, or 130 on interruption.
        Unknown acknowledgements can already have committed; no rollback is claimed.
    """

    parser = OpenApiParser()

    if "--help" in arguments or "-h" in arguments:
        parser.print_help(file=output)

        return 0

    outcome: dict[str, object] = {
        "schema_version": 1, "command": "api.import.openapi-json", "status": "failed",
        "source_selection": None, "evidence_id": None, "source_sha256": None,
        "received_bytes": None, "started_at": None, "finished_at": None,
        "acquisition_commit": "not-attempted", "model_commit": "not-attempted",
        "workspace_commit": "not-attempted", "model_revision": None,
        "workspace_revision": None, "created": None, "updated": None, "failure": None,
    }
    status, phase = 4, "configuration"

    try:
        options = parser.parse_args(arguments)
        RequireWorkspaceInteger(options.expected_revision, "expected_revision")
        RequireWorkspaceInteger(options.expected_workspace_revision, "expected_workspace_revision")
        RequireWorkspaceText(options.run, "run_reference")
        RequireIdentifier(options.scope, "scope_id")
        base = OpenApiBase(options.base_url)
        consent = None

        if options.file is not None:
            consent = ArtifactReadConsent(options.owner, options.read_consent_reference)

        elif options.owner is not None or options.read_consent_reference is not None:
            raise RuntimeFailure("configuration", 2)

        root = RuntimePath(options.workspace)
        phase = "integrity"
        workspace = LocalWorkspaceStore(root).Open()
        basis = LocalModelStore(root).Open()

        if basis.workspace_id != workspace.workspace_id or not set(workspace.object_references) <= {
            item.Reference() for item in basis.objects
        }:
            raise RuntimeFailure("integrity")

        if basis.revision != options.expected_revision:
            raise RuntimeFailure("revision-conflict")

        if workspace.revision != options.expected_workspace_revision:
            raise RuntimeFailure("workspace-conflict")

        scope = LocalScopeStore(root).Open(options.scope)

        if type(scope) is not ScopeSnapshot or scope.workspace_id != workspace.workspace_id or (
            ScopeSnapshot.FromDict(scope.ToDict()) != scope
        ):
            raise RuntimeFailure("scope")

        CheckBases(root, workspace, basis, scope)
        evidence = ApiEvidenceStore(root / "evidence", workspace.workspace_id, scope.Reference(),
                                    profile=OPENAPI_PRODUCT_PROFILE)
        outcome["source_selection"] = "file" if options.file is not None else "retained"
        record = None

        if options.file is None:
            phase = "manifest"
            record = evidence.Manifest(options.evidence)
            known = KnownOpenApiFacts(basis, record)

            if any(item.attributes["base_url"] != base or (
                item.provenance.run_reference != options.run
            ) for item in known):
                raise RuntimeFailure("source-context")

            PreflightApiReferences(basis, workspace, record, evidence)

        phase = "integrity"
        PreflightKnownApiReferences(basis, workspace,
            ApiEvidenceStore(root / "evidence", workspace.workspace_id, scope.Reference()))
        original = OpenReportInput(root)

        if original.workspace != workspace or original.report.state != basis:
            raise RuntimeFailure("revision-conflict")

        CheckBases(root, workspace, basis, scope)

        if options.file is not None:
            phase = "acquisition"

            if consent is None:
                raise RuntimeFailure("configuration", 2)

            raw, started, finished = ReadOwnedApiFile(options.file, consent, clock,
                                                     maximum=MAX_OPENAPI_BYTES)
            source = EvidenceProvenance(workspace.workspace_id, scope.Reference(), _SOURCE_ID,
                                        _SOURCE_VERSION, None, started, finished)
            digest = hashlib.sha256(raw).hexdigest()
            expected = EvidenceRecord(EvidenceReference(OPENAPI_PRODUCT_PROFILE,
                "blobs/sha256/" + digest, digest, "application/json", len(raw)), source)
            outcome.update({"evidence_id": expected.evidence_id, "acquisition_commit": "unknown"})
            record = evidence.Put(raw, OPENAPI_PRODUCT_PROFILE, "application/json", source)

            if record != expected:
                raise RuntimeFailure("integrity")

            outcome["acquisition_commit"] = "confirmed"

        if record is None or evidence.Manifest(record.evidence_id) != record:
            raise RuntimeFailure("integrity")

        PreflightApiReferences(basis, workspace, record, evidence)
        raw = evidence.Read(record.reference)
        source = record.provenance
        outcome.update({"acquisition_commit": "confirmed", "evidence_id": record.evidence_id,
            "source_sha256": record.reference.sha256, "received_bytes": record.reference.size_bytes,
            "started_at": source.started_at, "finished_at": source.finished_at})
        phase = "normalization"
        imported = ImportOpenApi(raw.decode("utf-8"), workspace_id=workspace.workspace_id,
                                 base_url=base)

        if imported.source_digest != "sha256:" + record.reference.sha256:
            raise RuntimeFailure("integrity")

        phase = "scope"
        CheckOpenApiScope(imported, scope, clock)
        phase = "projection"
        patches, facts = OpenApiProjection(imported, basis, record, options.run, base, consent)
        proposed, delta = basis.Apply(objects=patches, observations=facts)
        phase = "model-verification"
        CheckOpenApiScope(imported, scope, clock)
        CheckBases(root, workspace, basis, scope)
        phase = "model-save"
        outcome["model_commit"] = "unknown"
        saved = LocalModelStore(root).Save(proposed, expected_revision=basis.revision)
        outcome.update({"model_commit": "confirmed", "model_revision": saved.revision,
            "created": len(delta.created), "updated": len(delta.updated)})
        phase = "workspace-verification"
        CheckOpenApiScope(imported, scope, clock)
        CheckBases(root, workspace, saved, scope)
        retained = ReferenceProposal(workspace, saved, record, scope)
        phase = "workspace-save"
        outcome["workspace_commit"] = "unknown"

        if retained != workspace:
            retained = LocalWorkspaceStore(root).Save(retained)

        outcome.update({"workspace_commit": "confirmed", "workspace_revision": retained.revision})
        phase = "final-verification"
        CheckOpenApiScope(imported, scope, clock)
        CheckBases(root, retained, saved, scope)
        outcome["status"], status = "succeeded", 0

    except RuntimeFailure as error:
        outcome["failure"], status = error.category, error.status

    except (WorkspaceBusyError, WorkspaceConflictError) as error:
        owner = "workspace" if phase == "workspace-save" else "model"
        outcome[owner + "_commit"] = "not-committed"
        outcome["failure"] = owner + (
            "-busy" if isinstance(error, WorkspaceBusyError) else "-conflict")

    except KeyboardInterrupt:
        outcome["failure"], status = "interrupted", 130

    except (EvidenceError, OSError, ValueError, TypeError, PermissionError,
            OverflowError, RecursionError):
        outcome["failure"] = phase
        status = 2 if phase == "configuration" else 4

    except Exception:
        outcome["failure"] = "internal"

    if json_output:
        output.write(CanonicalModelJson(outcome).decode("utf-8") + "\n")

    else:
        output.write(f"{outcome['command']}: {outcome['status']}\n")

        for name in ("evidence_id", "model_revision", "workspace_revision", "acquisition_commit",
                     "model_commit", "workspace_commit", "failure"):
            if outcome[name] is not None:
                output.write(f"{name}: {outcome[name]}\n")

    return status
