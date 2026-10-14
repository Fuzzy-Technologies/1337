# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal bounded original GraphQL import with independent storage acknowledgements."""

from __future__ import annotations

import argparse
import hashlib
import os
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import TextIO
from urllib.parse import urlsplit

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.adapters.contracts import RequireIdentifier
from fuzzy1337.artifact_inputs import (
    ArtifactReadConsent,
    MatchesArtifactReadIdentity,
    PhysicalIdentity,
)
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
from fuzzy1337.graphql_import import (
    MAX_GRAPHQL_BYTES,
    CheckGraphQlTarget,
    ImportGraphQl,
    ProjectGraphQl,
)
from fuzzy1337.model import (
    CanonicalModelJson,
    LocalModelStore,
    ModelProvenance,
    ModelState,
    Observation,
    Relation,
    SecurityObject,
)
from fuzzy1337.policy import UtcNow
from fuzzy1337.report_commands import MAX_EXPORT_ACQUISITIONS, OpenReportInput
from fuzzy1337.requests import Endpoint
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

_PROFILE = "graphql-introspection"
_SOURCE_ID = "graphql-import"
_SOURCE_VERSION = "1"


def RequireApiRecord(record: EvidenceRecord, workspace_id: str, scope_reference: str) -> None:
    """Check exact nominal original records and full closed collection context before raw access.

    Args:
        record: Owning manifest selection, never an imported symbolic description.
        workspace_id: Current independently opened model/workspace identity.
        scope_reference: Exact existing selected scope, not an execution authorization.
    """

    if (
        type(record) is not EvidenceRecord
        or type(record.reference) is not EvidenceReference
        or (type(record.provenance) is not EvidenceProvenance)
    ):
        raise RuntimeFailure("integrity")

    reference, source = record.reference, record.provenance

    if (
        reference.role != _PROFILE
        or reference.media_type != "application/json"
        or (
            type(reference.size_bytes) is not int
            or not 1 <= reference.size_bytes <= MAX_GRAPHQL_BYTES
            or source.workspace_id != workspace_id
            or source.scope_reference != scope_reference
            or source.source_id != _SOURCE_ID
            or source.source_version != _SOURCE_VERSION
            or source.tool_version is not None
            or source.invocation_sha256 is not None
            or source.execution is not None
            or ParseEvidenceManifest(record.Serialize()) != record
        )
    ):
        raise RuntimeFailure("integrity")


class ApiEvidenceStore(LocalEvidenceStore):
    """Preflight original manifests before the existing evidence owner's eager raw verification."""

    def __init__(self, root: Path, workspace_id: str, scope_reference: str) -> None:
        """Retain exact local context without opening any manifest or blob."""

        super().__init__(root)
        self.workspace_id = workspace_id
        self.scope_reference = scope_reference

    def Manifest(self, evidence_id: str) -> EvidenceRecord:
        """Verify the original manifest identity, profile, bounds and context without raw access.

        Args:
            evidence_id: Exact owning acquisition identity, independent from the source digest.

        Returns:
            Canonical closed-profile original record; no blob has been read.
        """

        if type(evidence_id) is not str or not evidence_id.startswith("sha256:"):
            raise RuntimeFailure("integrity")

        digest = evidence_id[7:]
        RequireEvidenceDigest(digest)
        data = self.ReadStoredBytes(("records", digest + ".json"), EVIDENCE_MANIFEST_MAX_BYTES)
        record = ParseEvidenceManifest(data)
        RequireApiRecord(record, self.workspace_id, self.scope_reference)

        if record.evidence_id != evidence_id:
            raise RuntimeFailure("integrity")

        return record

    def Get(self, evidence_id: str) -> EvidenceRecord:
        """Check the original profile/context before the owner's eager raw verification.

        Args:
            evidence_id: Original acquisition identity selected by the controller.

        Returns:
            Preflighted original record after raw integrity verification.
        """

        record = self.Manifest(evidence_id)
        self.Read(record.reference)

        return record

    def CheckReference(self, reference: EvidenceReference) -> None:
        """Preflight a fixed-profile raw reference and its physical size without reading bytes.

        Args:
            reference: Original profile reference from a manifest or existing model provenance.
        """

        if (
            type(reference) is not EvidenceReference
            or reference.role != _PROFILE
            or (
                reference.media_type != "application/json"
                or type(reference.size_bytes) is not int
                or not 1 <= reference.size_bytes <= MAX_GRAPHQL_BYTES
            )
        ):
            raise RuntimeFailure("integrity")

        if reference.locator != "blobs/sha256/" + reference.sha256:
            raise RuntimeFailure("integrity")

        RequireEvidenceDigest(reference.sha256)
        metadata = CheckStorageEntry(
            self.StoragePath(("blobs", "sha256", reference.sha256)), directory=False,
        )

        if metadata.st_nlink != 1 or metadata.st_size != reference.size_bytes:
            raise RuntimeFailure("integrity")

    def Read(self, reference: EvidenceReference) -> bytes:
        """Bound the original JSON role before the owner verifies raw bytes.

        Args:
            reference: Original reference from a preflighted owning manifest.

        Returns:
            Unmodified bytes after existing owner digest and length verification.
        """

        self.CheckReference(reference)

        return super().Read(reference)


def ReadOwnedGraphQl(
    path: Path, consent: ArtifactReadConsent, clock: Callable[[], datetime]
) -> tuple[bytes, str, str]:
    """Acquire one original physical JSON file within the SDK's 512 KiB ceiling.

    Args:
        path: Explicit owned source; links and observed replacement are refused.
        consent: Explicit artifact-read actor and record, separate from endpoint scope.
        clock: Actual UTC observations immediately around the bounded original read.

    Returns:
        Complete unmodified bytes and actual acquisition timestamps.
    """

    if type(consent) is not ArtifactReadConsent:
        raise RuntimeFailure("configuration", 2)

    ArtifactReadConsent(consent.actor_ref, consent.record_ref)
    selected = RuntimePath(path)
    before = CheckStorageEntry(selected, directory=False)

    if before.st_nlink != 1:
        raise RuntimeFailure("configuration", 2)

    if not 1 <= before.st_size <= MAX_GRAPHQL_BYTES:
        raise RuntimeFailure("limit")

    started = clock().isoformat()

    with selected.open("rb") as stream:
        opened = os.fstat(stream.fileno())

        if opened.st_nlink != 1 or not MatchesArtifactReadIdentity(before, opened):
            raise RuntimeFailure("source-changed")

        raw = stream.read(MAX_GRAPHQL_BYTES + 1)
        finished = clock().isoformat()
        closed = os.fstat(stream.fileno())

    after = CheckStorageEntry(selected, directory=False)

    if (
        closed.st_nlink != 1
        or after.st_nlink != 1
        or (
            PhysicalIdentity(before) != PhysicalIdentity(after)
            or PhysicalIdentity(opened) != PhysicalIdentity(closed)
            or not MatchesArtifactReadIdentity(after, closed)
            or len(raw) != before.st_size
        )
    ):
        raise RuntimeFailure("source-changed")

    return raw, started, finished


def ApiParser() -> argparse.ArgumentParser:
    """Declare only explicit original file acquisition or known original GraphQL custody replay.

    Returns:
        Internal parser with no transport, preview, authentication or discovery options.
    """

    parser = RuntimeArgumentParser(
        prog="1337 api",
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Explicit import selections:
  import graphql-introspection WORKSPACE
    (--file FILE --owner ACTOR --read-consent-reference REF | --evidence sha256:MANIFEST)
    --endpoint URL --scope SCOPE --run RUN_REF
    --expected-revision MODEL_REV --expected-workspace-revision WS_REV
Retained evidence requires known original custody with unchanged endpoint/run/scope.
Occupied incompatible API collections are refused.
Refresh and source composition are not supplied.""",
    )
    actions = parser.add_subparsers(
        dest="action", required=True, parser_class=RuntimeArgumentParser
    )
    importer = actions.add_parser("import", add_help=False)
    importer.add_argument("profile", choices=(_PROFILE,))
    importer.add_argument("workspace", type=Path)
    selection = importer.add_mutually_exclusive_group(required=True)
    selection.add_argument("--file", type=Path)
    selection.add_argument("--evidence")

    for name in ("endpoint", "scope", "run"):
        importer.add_argument("--" + name, required=True)

    importer.add_argument("--expected-revision", type=int, required=True)
    importer.add_argument("--expected-workspace-revision", type=int, required=True)
    importer.add_argument("--owner")
    importer.add_argument("--read-consent-reference")

    return parser


def ApiSourceFact(
    state: ModelState,
    record: EvidenceRecord,
    provenance: ModelProvenance,
    endpoint: Endpoint,
    consent: ArtifactReadConsent | None,
) -> Observation:
    """Bind original acquisition identity and context using an existing inert observation.

    Args:
        state: Exact model basis containing any prior original product custody.
        record: Preflighted original manifest, independent from its raw-byte digest.
        provenance: Exact endpoint/run/scope/time/source attribution, never an execution grant.
        endpoint: Explicit SDK-compatible POST Endpoint description, not target registration.
        consent: Current file consent; None permits only already known original custody.

    Returns:
        Exact original custody on replay or one first file-acquisition custody fact.
    """

    attributes = {
        "profile": _PROFILE,
        "evidence_id": record.evidence_id,
        "source_sha256": record.reference.sha256,
        "source_version": _SOURCE_VERSION,
        "read_actor_reference": consent.actor_ref if consent is not None else None,
        "read_consent_reference": consent.record_ref if consent is not None else None,
    }
    facts = [
        item
        for item in state.observations
        if item.kind == "api-import-source"
        and item.attributes.get("evidence_id") == record.evidence_id
    ]

    if facts:
        fact = facts[0]

        if (
            len(facts) != 1
            or fact.subject_reference != endpoint.Identity().Reference()
            or (fact.provenance != provenance or set(fact.attributes) != set(attributes))
        ):
            raise RuntimeFailure("source-context")

        actor = fact.attributes["read_actor_reference"]
        read_reference = fact.attributes["read_consent_reference"]

        if type(actor) is not str or type(read_reference) is not str:
            raise RuntimeFailure("source-context")

        original = ArtifactReadConsent(actor, read_reference)
        attributes.update(
            {
                "read_actor_reference": original.actor_ref,
                "read_consent_reference": original.record_ref,
            }
        )

        if dict(fact.attributes) != attributes or consent is not None and consent != original:
            raise RuntimeFailure("source-context")

        return fact

    if consent is None:
        raise RuntimeFailure("source-context")

    return Observation("api-import-source", endpoint.Identity().Reference(), attributes, provenance)


def AdmitApiProjection(state: ModelState, projection: SecurityObject) -> None:
    """Refuse replacing any occupied incompatible complete API collection.

    Args:
        state: Exact independently selected model basis.
        projection: Existing SDK Endpoint patch from freshly verified original bytes.
    """

    current = next(
        (item for item in state.objects if item.Reference() == projection.Reference()), None
    )
    fields = {"request_templates", "graphql_import"}

    if current is not None and fields & set(current.attributes):
        if not fields <= set(current.attributes) or any(
            CanonicalModelJson(current.attributes[name])
            != CanonicalModelJson(projection.attributes[name])
            for name in fields
        ):
            raise RuntimeFailure("occupied-endpoint")


def PreflightApiReferences(state: ModelState, workspace: WorkspaceState,
                          record: EvidenceRecord, evidence: ApiEvidenceStore) -> None:
    """Bound the selected original blob before any generic workspace/report evidence reader.

    Args:
        state: Exact owning model basis, including retained provenance references.
        workspace: Independently selected workspace and its retained raw references.
        record: Original manifest already checked for profile and known custody.
        evidence: Actual original evidence owner; unrelated blobs retain their own bounds.
    """

    RequireApiRecord(record, workspace.workspace_id, evidence.scope_reference)
    reference = record.reference
    evidence.CheckReference(reference)

    entities: tuple[SecurityObject | Relation, ...] = (*state.objects, *state.relations)
    contexts = [provenance for item in entities
                for provenance in item.provenance]
    contexts.extend(item.provenance for item in state.observations)
    references = [*workspace.evidence_references,
                  *(item for context in contexts for item in context.evidence_references)]

    if any((item.sha256 == reference.sha256 or item.locator == reference.locator) and (
        type(item) is not EvidenceReference or item != reference
    ) for item in references):
        raise RuntimeFailure("integrity")


def PreflightKnownApiReferences(state: ModelState, workspace: WorkspaceState,
                               evidence: ApiEvidenceStore) -> None:
    """Bound known GraphQL manifests, raw references and aliases in either selection mode.

    Args:
        state: Existing raw provenance and custody, before generic retained raw verification.
        workspace: Exact independently selected owning workspace.
        evidence: Current evidence partition; each original keeps its own recorded scope.
    """

    record_ids = set(workspace.evidence_record_references)

    for fact in state.observations:
        if fact.kind != "api-import-source" or fact.attributes.get("profile") != _PROFILE:
            continue

        evidence_id = fact.attributes.get("evidence_id")

        if type(evidence_id) is not str:
            raise RuntimeFailure("integrity")

        record_ids.add(evidence_id)

    if len(record_ids) > MAX_EXPORT_ACQUISITIONS:
        raise RuntimeFailure("limit")

    for evidence_id in sorted(record_ids):
        if not evidence_id.startswith("sha256:"):
            raise RuntimeFailure("integrity")

        digest = evidence_id[7:]
        RequireEvidenceDigest(digest)
        record = ParseEvidenceManifest(evidence.ReadStoredBytes(
            ("records", digest + ".json"), EVIDENCE_MANIFEST_MAX_BYTES,
        ))

        if record.evidence_id != evidence_id:
            raise RuntimeFailure("integrity")

        if record.reference.role == _PROFILE:
            original = ApiEvidenceStore(evidence.root, workspace.workspace_id,
                                        record.provenance.scope_reference)
            PreflightApiReferences(state, workspace, record, original)

    entities: tuple[SecurityObject | Relation, ...] = (*state.objects, *state.relations)
    contexts = [provenance for item in entities for provenance in item.provenance]
    contexts.extend(item.provenance for item in state.observations)
    references = [*workspace.evidence_references,
                  *(item for context in contexts for item in context.evidence_references)]

    for reference in references:
        if reference.role != _PROFILE:
            continue

        evidence.CheckReference(reference)

        if any((item.sha256 == reference.sha256 or item.locator == reference.locator)
               and item != reference for item in references):
            raise RuntimeFailure("integrity")


def RunApiCommands(
    arguments: Sequence[str],
    output: TextIO,
    *,
    json_output: bool = False,
    clock: Callable[[], datetime] = UtcNow,
) -> int:
    """Import original structural metadata with truthful acquisition/model/workspace outcomes.

    Args:
        arguments: Explicit closed profile, current owner bases, endpoint and original selection.
        output: Caller-owned summary stream; source values and filenames are never rendered.
        json_output: Emit one bounded Internal schema-v1 outcome.
        clock: Current aware scope-decision and actual original file observation clock.

    Returns:
        Zero on success, two for configuration refusal, four for other failures, or 130 on
        interruption. Unknown acknowledgements may have committed; no rollback is claimed.
    """

    parser = ApiParser()

    if "--help" in arguments or "-h" in arguments:
        parser.print_help(file=output)

        return 0

    outcome: dict[str, object] = {
        "schema_version": 1,
        "command": "api.import.graphql-introspection",
        "status": "failed",
        "source_selection": None,
        "evidence_id": None,
        "source_sha256": None,
        "received_bytes": None,
        "started_at": None,
        "finished_at": None,
        "acquisition_commit": "not-attempted",
        "model_commit": "not-attempted",
        "workspace_commit": "not-attempted",
        "model_revision": None,
        "workspace_revision": None,
        "created": None,
        "updated": None,
        "failure": None,
    }
    status, phase = 4, "configuration"

    try:
        options = parser.parse_args(arguments)
        RequireWorkspaceInteger(options.expected_revision, "expected_revision")
        RequireWorkspaceInteger(options.expected_workspace_revision, "expected_workspace_revision")
        RequireWorkspaceText(options.run, "run_reference")
        RequireIdentifier(options.scope, "scope_id")
        target = Target(TargetKind.URL, options.endpoint)
        parsed = urlsplit(target.value)
        consent = None

        if "?" in options.endpoint or "{" in options.endpoint or "}" in options.endpoint:
            raise RuntimeFailure("configuration", 2)

        if options.file is not None:
            consent = ArtifactReadConsent(options.owner, options.read_consent_reference)

        elif options.owner is not None or options.read_consent_reference is not None:
            raise RuntimeFailure("configuration", 2)

        root = RuntimePath(options.workspace)
        phase = "integrity"
        workspace = LocalWorkspaceStore(root).Open()
        basis = LocalModelStore(root).Open()
        endpoint = Endpoint(
            workspace.workspace_id, f"{parsed.scheme}://{parsed.netloc}", parsed.path, "POST"
        )

        if endpoint.PathVariables():
            raise RuntimeFailure("configuration", 2)

        if basis.workspace_id != workspace.workspace_id or not set(workspace.object_references) <= {
            item.Reference() for item in basis.objects
        }:
            raise RuntimeFailure("integrity")

        if basis.revision != options.expected_revision:
            raise RuntimeFailure("revision-conflict")

        if workspace.revision != options.expected_workspace_revision:
            raise RuntimeFailure("workspace-conflict")

        scope = LocalScopeStore(root).Open(options.scope)

        if (
            type(scope) is not ScopeSnapshot
            or scope.workspace_id != workspace.workspace_id
            or (ScopeSnapshot.FromDict(scope.ToDict()) != scope)
        ):
            raise RuntimeFailure("scope")

        phase = "scope"
        at = clock()

        if not scope.Check(target, at=at).Allowed():
            raise RuntimeFailure("scope")

        CheckBases(root, workspace, basis, scope)
        evidence = ApiEvidenceStore(root / "evidence", workspace.workspace_id, scope.Reference())
        outcome["source_selection"] = "file" if options.file is not None else "retained"
        record = None

        if options.file is None:
            phase = "manifest"
            record = evidence.Manifest(options.evidence)
            RequireApiRecord(record, workspace.workspace_id, scope.Reference())

            if record.evidence_id != options.evidence:
                raise RuntimeFailure("integrity")

            provenance = ModelProvenance(
                _SOURCE_ID,
                options.run,
                record.provenance.finished_at,
                scope.Reference(),
                target.Reference(),
                None,
                (record.reference,),
            )
            ApiSourceFact(basis, record, provenance, endpoint, None)
            PreflightApiReferences(basis, workspace, record, evidence)

        phase = "integrity"
        PreflightKnownApiReferences(basis, workspace, evidence)
        original = OpenReportInput(root)

        if original.workspace != workspace or original.report.state != basis:
            raise RuntimeFailure("revision-conflict")

        CheckBases(root, workspace, basis, scope)

        if options.file is not None:
            phase = "acquisition"

            if consent is None:
                raise RuntimeFailure("configuration", 2)

            raw, started, finished = ReadOwnedGraphQl(options.file, consent, clock)
            source = EvidenceProvenance(
                workspace.workspace_id,
                scope.Reference(),
                _SOURCE_ID,
                _SOURCE_VERSION,
                None,
                started,
                finished,
            )
            digest = hashlib.sha256(raw).hexdigest()
            expected = EvidenceRecord(
                EvidenceReference(
                    _PROFILE, "blobs/sha256/" + digest, digest, "application/json", len(raw)
                ),
                source,
            )
            outcome.update({"evidence_id": expected.evidence_id, "acquisition_commit": "unknown"})
            record = evidence.Put(raw, _PROFILE, "application/json", source)
            RequireApiRecord(record, workspace.workspace_id, scope.Reference())

            if record != expected:
                raise RuntimeFailure("integrity")

            outcome["acquisition_commit"] = "confirmed"

        if record is None or evidence.Manifest(record.evidence_id) != record:
            raise RuntimeFailure("integrity")

        RequireApiRecord(record, workspace.workspace_id, scope.Reference())
        source = record.provenance
        provenance = ModelProvenance(
            _SOURCE_ID,
            options.run,
            source.finished_at,
            scope.Reference(),
            target.Reference(),
            None,
            (record.reference,),
        )
        fact = ApiSourceFact(basis, record, provenance, endpoint, consent)
        raw = evidence.Read(record.reference)
        outcome.update(
            {
                "acquisition_commit": "confirmed",
                "evidence_id": record.evidence_id,
                "source_sha256": record.reference.sha256,
                "received_bytes": record.reference.size_bytes,
                "started_at": source.started_at,
                "finished_at": source.finished_at,
            }
        )
        phase = "normalization"
        imported = ImportGraphQl(
            raw, workspace_id=workspace.workspace_id, endpoint_url=target.value
        )

        if imported.source_digest != "sha256:" + record.reference.sha256:
            raise RuntimeFailure("integrity")

        current_at = clock()

        for operation in imported.operations:
            CheckGraphQlTarget(operation, target, scope, at=current_at)

        projection = ProjectGraphQl(imported, provenance=(provenance,))
        AdmitApiProjection(basis, projection)
        proposed, delta = basis.Apply(objects=(projection,), observations=(fact,))
        phase = "model-verification"
        CheckBases(root, workspace, basis, scope)
        phase = "model-save"
        outcome["model_commit"] = "unknown"
        saved = LocalModelStore(root).Save(proposed, expected_revision=basis.revision)
        outcome.update(
            {
                "model_commit": "confirmed",
                "model_revision": saved.revision,
                "created": len(delta.created),
                "updated": len(delta.updated),
            }
        )
        phase = "workspace-verification"
        CheckBases(root, workspace, saved, scope)
        retained = ReferenceProposal(workspace, saved, record, scope)
        phase = "workspace-save"
        outcome["workspace_commit"] = "unknown"

        if retained != workspace:
            retained = LocalWorkspaceStore(root).Save(retained)

        outcome.update({"workspace_commit": "confirmed", "workspace_revision": retained.revision})
        phase = "final-verification"
        CheckBases(root, retained, saved, scope)
        outcome["status"], status = "succeeded", 0

    except RuntimeFailure as error:
        outcome["failure"], status = error.category, error.status

    except (WorkspaceBusyError, WorkspaceConflictError) as error:
        owner = "workspace" if phase == "workspace-save" else "model"
        outcome[owner + "_commit"] = "not-committed"
        outcome["failure"] = owner + (
            "-busy" if isinstance(error, WorkspaceBusyError) else "-conflict"
        )

    except KeyboardInterrupt:
        outcome["failure"], status = "interrupted", 130

    except (
        EvidenceError,
        OSError,
        ValueError,
        TypeError,
        PermissionError,
        OverflowError,
        RecursionError,
    ):
        outcome["failure"] = phase
        status = 2 if phase == "configuration" else 4

    except Exception:
        outcome["failure"] = "internal"

    if json_output:
        output.write(CanonicalModelJson(outcome).decode("utf-8") + "\n")

    else:
        output.write(f"{outcome['command']}: {outcome['status']}\n")

        for name in (
            "evidence_id",
            "model_revision",
            "workspace_revision",
            "acquisition_commit",
            "model_commit",
            "workspace_commit",
            "failure",
        ):
            if outcome[name] is not None:
                output.write(f"{name}: {outcome[name]}\n")

    return status
