# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal original SPDX graph import and read-only verified image inventory commands."""

from __future__ import annotations

import argparse
import hashlib
import os
from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Never, TextIO

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
from fuzzy1337.images import IMAGE_IMPORT_MAX_BYTES, ImageIdentity
from fuzzy1337.model import (
    CanonicalModelJson,
    LocalModelStore,
    ModelDelta,
    ModelProvenance,
    ModelState,
    Observation,
    Relation,
    SecurityObject,
)
from fuzzy1337.policy import UtcNow
from fuzzy1337.report_commands import MAX_EXPORT_ACQUISITIONS, MAX_EXPORT_SCOPES, OpenReportInput
from fuzzy1337.reporting import ReportSnapshot
from fuzzy1337.sbom_graph import ApplyVerifiedSpdxGraph
from fuzzy1337.scope import LocalScopeStore, ScopeSnapshot
from fuzzy1337.workspace import (
    LocalWorkspaceStore,
    RequireWorkspaceInteger,
    RequireWorkspaceText,
    StoragePathInfo,
    WorkspaceBusyError,
    WorkspaceConflictError,
    WorkspaceState,
)

__all__ = ["SbomParser", "RunSbomCommands"]


class SbomFailure(RuntimeError):
    """Carry a fixed failure category without reflecting rejected source, path or consent values."""

    def __init__(self, category: str, status: int = 4) -> None:
        """Retain only an implementation-owned category and terminal process status."""

        super().__init__(category)
        self.category = category
        self.status = status


class SbomArgumentParser(argparse.ArgumentParser):
    """Keep argparse grammar while excluding untrusted values from diagnostics."""

    def Error(self, message: str) -> Never:
        """Fail with a fixed category instead of the unretained framework diagnostic.

        Args:
            message: Framework diagnostic which may contain rejected input values.

        Returns:
            Never returns; invalid explicit arguments become configuration refusal.
        """

        raise SbomFailure("configuration", 2)

    error = Error


class SbomEvidenceStore(LocalEvidenceStore):
    """Check selected original manifest metadata and its four-MiB ceiling before eager reads."""

    def CheckReference(self, reference: EvidenceReference) -> None:
        """Require the exact original offline JSON SBOM role and bounded byte count.

        Args:
            reference: Original manifest reference, never a content digest used as custody.
        """

        if type(reference) is not EvidenceReference or reference.role != "sbom" or (
            reference.media_type != "application/json" or type(reference.size_bytes) is not int
            or not 1 <= reference.size_bytes <= IMAGE_IMPORT_MAX_BYTES
        ):
            raise SbomFailure("selected-source")

    def Read(self, reference: EvidenceReference) -> bytes:
        """Apply the selected source ceiling before the unchanged evidence owner's raw read.

        Args:
            reference: Exact original selected offline SBOM reference.

        Returns:
            Original verified raw bytes without normalization or remote retrieval.
        """

        self.CheckReference(reference)

        return super().Read(reference)

    def Manifest(self, evidence_id: str, *, selected: bool = True) -> EvidenceRecord:
        """Parse original manifest identity without reading any referenced raw blob.

        Args:
            evidence_id: Explicit original canonical manifest identity.
            selected: Enforce SBOM source constraints; false inspects unrelated alias metadata only.

        Returns:
            Exact original typed record, with no current execution or custody authority inferred.
        """

        if type(evidence_id) is not str or not evidence_id.startswith("sha256:"):
            raise SbomFailure("integrity")

        RequireEvidenceDigest(evidence_id[7:])
        data = self.ReadStoredBytes(("records", evidence_id[7:] + ".json"),
                                    EVIDENCE_MANIFEST_MAX_BYTES)
        record = ParseEvidenceManifest(data)

        if record.evidence_id != evidence_id:
            raise SbomFailure("integrity")

        if selected:
            self.CheckReference(record.reference)
            source = record.provenance

            if source.execution is not None or source.invocation_sha256 is not None:
                raise SbomFailure("source-context")

        return record

    def Get(self, evidence_id: str) -> EvidenceRecord:
        """Preflight the selected actual manifest before the owner's eager raw verification.

        Args:
            evidence_id: Explicit original selected SBOM manifest identity.

        Returns:
            Original record after exact original metadata and raw-byte verification.
        """

        self.Manifest(evidence_id)

        return super().Get(evidence_id)


def SbomPath(path: Path) -> Path:
    """Require a bounded explicit lexical path and reject linked parent directories.

    Args:
        path: Explicit owning workspace or original caller-selected non-secret source file.

    Returns:
        Absolute lexical path without following source links or resolving discovery targets.
    """

    value = str(path)

    if ".." in path.parts or len(value.encode("utf-8")) > 4096 or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise SbomFailure("configuration", 2)

    selected = path.absolute()

    for parent in reversed(selected.parents):
        CheckStorageEntry(parent, directory=True)

    return selected


def ReadOwnedSbom(path: Path, consent: ArtifactReadConsent,
                  clock: Callable[[], datetime]) -> tuple[bytes, str, str]:
    """Read one explicit consented regular file under the unchanged four-MiB SDK ceiling.

    Args:
        path: Original owned file selected explicitly, never an archive extraction or remote URL.
        consent: Exact descriptive actor/read-record references, not a scan or execution grant.
        clock: Owning observation clock immediately around the actual bounded read.

    Returns:
        Original unmodified bytes and actual local-read timestamps after stable identity checks.

    Raises:
        SbomFailure: Consent, type, single-link ownership, byte limit or identity is refused.
        OSError: The selected original file or descriptor cannot be read or inspected.
    """

    if type(consent) is not ArtifactReadConsent:
        raise SbomFailure("configuration", 2)

    ArtifactReadConsent(consent.actor_ref, consent.record_ref)
    selected = SbomPath(path)
    before = CheckStorageEntry(selected, directory=False)

    if before.st_nlink != 1:
        raise SbomFailure("selected-source")

    if not 1 <= before.st_size <= IMAGE_IMPORT_MAX_BYTES:
        raise SbomFailure("limit")

    started = clock().isoformat()
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(selected, flags)

    try:
        stream = os.fdopen(descriptor, "rb")

    except BaseException:
        os.close(descriptor)

        raise

    with stream:
        opened = os.fstat(stream.fileno())

        if opened.st_nlink != 1 or not MatchesArtifactReadIdentity(before, opened):
            raise SbomFailure("source-changed")

        raw = stream.read(IMAGE_IMPORT_MAX_BYTES + 1)
        finished = clock().isoformat()
        closed = os.fstat(stream.fileno())

    after = CheckStorageEntry(selected, directory=False)

    if closed.st_nlink != 1 or after.st_nlink != 1 or (
        PhysicalIdentity(before) != PhysicalIdentity(after)
        or PhysicalIdentity(opened) != PhysicalIdentity(closed)
        or not MatchesArtifactReadIdentity(after, closed) or len(raw) != before.st_size
    ):
        raise SbomFailure("source-changed")

    return raw, started, finished


def SbomParser() -> argparse.ArgumentParser:
    """Declare explicit original acquisition, known custody replay and saved image viewing.

    Returns:
        Internal parser requiring explicit image semantics and action-specific owner selections.
    """

    parser = SbomArgumentParser(prog="1337 sbom", add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Explicit offline selections:
  import spdx-graph WORKSPACE
    (--file FILE --owner ACTOR --read-consent-reference REFERENCE
      --source-id SOURCE --source-version VERSION [--provider-version DECLARED]
     | --evidence sha256:ORIGINAL_MANIFEST)
    --image-digest sha256:DIGEST --image-digest-kind {config,manifest}
    --scope SCOPE --run RUN --expected-revision MODEL --expected-workspace-revision WORKSPACE
  image WORKSPACE --image-digest sha256:DIGEST --image-digest-kind {config,manifest}
Retained replay requires known original product custody.
It accepts no context or read overrides.""")
    actions = parser.add_subparsers(dest="action", required=True, parser_class=SbomArgumentParser)
    importer = actions.add_parser("import", add_help=False)
    importer.add_argument("profile", choices=("spdx-graph",))
    importer.add_argument("workspace", type=Path)
    selection = importer.add_mutually_exclusive_group(required=True)
    selection.add_argument("--file", type=Path)
    selection.add_argument("--evidence")
    importer.add_argument("--image-digest", required=True)
    importer.add_argument("--image-digest-kind", choices=("config", "manifest"), required=True)

    for name in ("scope", "run"):
        importer.add_argument("--" + name, required=True)

    importer.add_argument("--expected-revision", type=int, required=True)
    importer.add_argument("--expected-workspace-revision", type=int, required=True)

    for name in ("owner", "read-consent-reference", "source-id", "source-version",
                 "provider-version"):
        importer.add_argument("--" + name)

    viewer = actions.add_parser("image", add_help=False)
    viewer.add_argument("workspace", type=Path)
    viewer.add_argument("--image-digest", required=True)
    viewer.add_argument("--image-digest-kind", choices=("config", "manifest"), required=True)

    return parser


def CheckBases(root: Path, workspace: WorkspaceState, model: ModelState,
               scope: ScopeSnapshot) -> None:
    """Refuse observed owner changes without claiming atomic isolation across separate stores.

    Args:
        root: Existing physical owning workspace.
        workspace: Explicit selected or confirmed saved workspace snapshot.
        model: Explicit selected or confirmed saved model snapshot.
        scope: Existing workspace-local attribution snapshot, never an execution grant.
    """

    if LocalWorkspaceStore(root).Open() != workspace:
        raise SbomFailure("workspace-conflict")

    if LocalModelStore(root).Open() != model:
        raise SbomFailure("revision-conflict")

    if LocalScopeStore(root).Open(scope.scope_id) != scope:
        raise SbomFailure("scope-conflict")


def CheckKnownSbomSources(store: SbomEvidenceStore, reference: EvidenceReference | None,
                         workspace: WorkspaceState, model: ModelState) -> None:
    """Guard every known original SBOM blob and all aliases before generic raw verification.

    Args:
        store: Existing owning evidence metadata reader, not a retrieval mechanism.
        reference: Exact incoming original SBOM reference, or None for a saved-state view.
        workspace: Current selected workspace metadata before any generic owning raw read.
        model: Complete current model including old originals in their own attribution contexts.

    Raises:
        SbomFailure: An original SBOM exceeds its ceiling or any same-blob alias changes metadata.
        EvidenceError: Original manifest metadata or physical owning paths cannot verify.
    """

    if reference is not None:
        store.CheckReference(reference)

    record_ids = set(workspace.evidence_record_references)
    custody = [item for item in model.observations if item.kind == "sbom-import-source"]

    for fact in custody:
        evidence_id = fact.attributes.get("evidence_id")

        if type(evidence_id) is not str:
            raise SbomFailure("source-context")

        record_ids.add(evidence_id)

    if len(record_ids) > MAX_EXPORT_ACQUISITIONS:
        raise SbomFailure("limit")

    references = [*workspace.evidence_references, *ReportSnapshot(model).EvidenceReferences()]
    scopes = set(workspace.scope_references)
    entities: tuple[SecurityObject | Relation, ...] = (*model.objects, *model.relations)

    for entity in entities:
        scopes.update(item.scope_reference for item in entity.provenance)

    scopes.update(item.provenance.scope_reference for item in model.observations)

    originals = {}

    for record_id in sorted(record_ids):
        original = store.Manifest(record_id, selected=False)
        originals[record_id] = original
        references.append(original.reference)
        scopes.add(original.provenance.scope_reference)

        if original.provenance.workspace_id != workspace.workspace_id:
            raise SbomFailure("integrity")

    for fact in custody:
        original = originals[str(fact.attributes["evidence_id"])]
        source = original.provenance
        digest = fact.attributes.get("image_digest")
        digest_kind = fact.attributes.get("image_digest_kind")

        if type(digest) is not str or type(digest_kind) is not str or (
            source.invocation_sha256 is not None or source.execution is not None
        ):
            raise SbomFailure("source-context")

        store.CheckReference(original.reference)
        image = ImageIdentity(digest, digest_kind)
        image_reference = image.Object(model.workspace_id).Reference()
        attribution = ModelProvenance(source.source_id, fact.provenance.run_reference,
            source.finished_at, source.scope_reference, image_reference,
            source.tool_version, (original.reference,))
        SourceFact(model, original, attribution, image, None)

    if len(scopes) > MAX_EXPORT_SCOPES:
        raise SbomFailure("limit")

    for scope in sorted(scopes):
        if not scope.startswith("scope:"):
            raise SbomFailure("source-context")

        LocalScopeStore(store.root.parent).Open(scope[6:])

    protected = {} if reference is None else {reference.sha256: reference}
    known = set()

    for original_reference in references:
        if original_reference.role != "sbom":
            continue

        if original_reference.locator != "blobs/sha256/" + original_reference.sha256 or (
            type(original_reference.size_bytes) is not int
            or not 1 <= original_reference.size_bytes <= IMAGE_IMPORT_MAX_BYTES
        ):
            raise SbomFailure("selected-source")

        if original_reference.sha256 in protected and (
            protected[original_reference.sha256] != original_reference
        ):
            raise SbomFailure("selected-source-alias")

        protected[original_reference.sha256] = original_reference
        known.add(original_reference.sha256)

    by_locator = {item.locator: item for item in protected.values()}

    for alias in references:
        protected_reference = protected.get(alias.sha256) or by_locator.get(alias.locator)

        if protected_reference is not None and alias != protected_reference:
            raise SbomFailure("selected-source-alias")

    for original_reference in protected.values():
        parent = store.root
        present = True

        for component in ("blobs", "sha256"):
            parent = parent / component

            if StoragePathInfo(parent) is None:
                present = False

                break

            CheckStorageEntry(parent, directory=True)

        path = parent / original_reference.sha256
        metadata = StoragePathInfo(path) if present else None

        if metadata is None:
            if original_reference.sha256 in known:
                raise SbomFailure("selected-source")

            continue

        metadata = CheckStorageEntry(path, directory=False)

        if metadata.st_nlink != 1 or not 1 <= metadata.st_size <= IMAGE_IMPORT_MAX_BYTES or (
            metadata.st_size != original_reference.size_bytes
        ):
            raise SbomFailure("selected-source")


def SourceFact(state: ModelState, record: EvidenceRecord, provenance: ModelProvenance,
               image: ImageIdentity, consent: ArtifactReadConsent | None) -> Observation:
    """Bind known product custody to the independently selected original acquisition manifest.

    Args:
        state: Exact owning model before import or retained replay.
        record: Original offline manifest; raw-content SHA alone never identifies custody.
        provenance: Exact original source/time/scope plus explicit image/run interpretation.
        image: Explicit config/manifest semantics retained separately from checksum equality.
        consent: Explicit file acquisition description, or None for known original replay.

    Returns:
        Original unchanged custody fact, or first file-mode custody observation.

    Raises:
        SbomFailure: Unknown retained custody, original context or read description changes.
    """

    fields = {"profile": "spdx-graph", "evidence_id": record.evidence_id,
        "source_sha256": record.reference.sha256, "source_id": record.provenance.source_id,
        "source_version": record.provenance.source_version, "image_digest": image.digest,
        "image_digest_kind": image.digest_kind}
    facts = [item for item in state.observations if item.kind == "sbom-import-source"
             and item.attributes.get("evidence_id") == record.evidence_id]

    if facts:
        fact = facts[0]

        if len(facts) != 1 or fact.subject_reference != provenance.target_reference or (
            fact.provenance != provenance or set(fact.attributes) != {
                *fields, "read_actor_reference", "read_consent_reference"}
            or any(fact.attributes[name] != value for name, value in fields.items())
        ):
            raise SbomFailure("source-context")

        actor = fact.attributes["read_actor_reference"]
        read_reference = fact.attributes["read_consent_reference"]

        if type(actor) is not str or type(read_reference) is not str:
            raise SbomFailure("source-context")

        original = ArtifactReadConsent(actor, read_reference)

        if consent is not None and consent != original:
            raise SbomFailure("source-context")

        return fact

    if consent is None:
        raise SbomFailure("source-context")

    return Observation("sbom-import-source", provenance.target_reference, {
        **fields, "read_actor_reference": consent.actor_ref,
        "read_consent_reference": consent.record_ref}, provenance)


def ApplySourceFact(state: ModelState, delta: ModelDelta, fact: Observation
                    ) -> tuple[ModelState, ModelDelta]:
    """Fold custody into the SDK's one in-memory revision while preserving exact no-op replay.

    Args:
        state: Unchanged SDK proposal with prior graph, finding and operator facts retained.
        delta: SDK aggregate transition from the original explicit model basis.
        fact: Exact immutable original-manifest custody observation.

    Returns:
        One combined proposal and delta, without storage or a second model revision.
    """

    proposed, extra = state.Apply(observations=(fact,))
    created = set(delta.created) | set(extra.created)
    updated = (set(delta.updated) | set(extra.updated)) - created
    revision = delta.previous_revision + bool(created or updated)

    return replace(proposed, revision=revision), ModelDelta(delta.previous_revision, revision,
        tuple(sorted(created)), tuple(sorted(updated)))


def ReferenceProposal(workspace: WorkspaceState, model: ModelState, record: EvidenceRecord,
                      scope: ScopeSnapshot) -> WorkspaceState:
    """Retain old references and the original imported source through the workspace CAS owner.

    Args:
        workspace: Original workspace basis at its independent expected revision.
        model: Exact successfully saved canonical model.
        record: Independently pinned immutable original SBOM acquisition.
        scope: Existing local attribution scope, never live execution permission.

    Returns:
        Workspace proposal retaining original evidence and all canonical object references.
    """

    references = {(item.locator, item.role): item for item in workspace.evidence_references}
    references[(record.reference.locator, record.reference.role)] = record.reference

    return replace(workspace,
        scope_references=tuple(sorted({*workspace.scope_references, scope.Reference()})),
        object_references=tuple(sorted(item.Reference() for item in model.objects)),
        evidence_references=tuple(references[key] for key in sorted(references)),
        evidence_record_references=tuple(sorted({*workspace.evidence_record_references,
                                                 record.evidence_id})))


def RunSbomCommands(arguments: Sequence[str], output: TextIO, *, json_output: bool = False,
                    clock: Callable[[], datetime] = UtcNow) -> int:
    """Dispatch saved image viewing or bounded original graph acquisition and independent CAS saves.

    Args:
        arguments: Explicit source, image semantics, offline scope/run and both revision bases.
        output: Caller-owned terminal stream excluding original bytes and selected paths.
        json_output: Emit one Internal schema-one outcome with independent acknowledgements.
        clock: Local-read observation clock; retained original replay never calls it.

    Returns:
        Zero after confirmed import, two for configuration refusal, four for integrity/storage
        failure or unknown acknowledgement, and 130 for interruption. No rollback or atomic
        cross-store transaction is claimed when one owner has already committed.
    """

    parser = SbomParser()

    if "--help" in arguments or "-h" in arguments:
        parser.print_help(file=output)

        return 0

    if arguments and arguments[0] == "image":
        from fuzzy1337.image_sbom_view import RunImageSbomView

        return RunImageSbomView(arguments, output, json_output=json_output)

    outcome: dict[str, object] = {"schema_version": 1, "command": "sbom.import.spdx-graph",
        "status": "failed", "source_selection": None, "evidence_id": None,
        "source_sha256": None, "received_bytes": None, "started_at": None, "finished_at": None,
        "acquisition_commit": "not-attempted", "model_commit": "not-attempted",
        "workspace_commit": "not-attempted", "model_revision": None,
        "workspace_revision": None, "created": None, "updated": None, "failure": None}
    status = 4
    phase = "configuration"

    try:
        options = parser.parse_args(arguments)
        RequireWorkspaceInteger(options.expected_revision, "expected_revision")
        RequireWorkspaceInteger(options.expected_workspace_revision, "expected_workspace_revision")
        RequireWorkspaceText(options.run, "run_reference")
        RequireIdentifier(options.scope, "scope_id")
        image = ImageIdentity(options.image_digest, options.image_digest_kind)
        consent = None

        if options.file is not None:
            consent = ArtifactReadConsent(options.owner, options.read_consent_reference)
            RequireIdentifier(options.source_id, "source_id")
            RequireWorkspaceText(options.source_version, "source_version")

            if options.provider_version is not None:
                RequireWorkspaceText(options.provider_version, "provider_version")

        elif any(value is not None for value in (options.owner, options.read_consent_reference,
            options.source_id, options.source_version, options.provider_version)):
            raise SbomFailure("configuration", 2)

        root = SbomPath(options.workspace)
        phase = "integrity"
        workspace = LocalWorkspaceStore(root).Open()
        basis = LocalModelStore(root).Open()
        scope = LocalScopeStore(root).Open(options.scope)

        if basis.revision != options.expected_revision:
            raise SbomFailure("revision-conflict")

        if workspace.revision != options.expected_workspace_revision:
            raise SbomFailure("workspace-conflict")

        if not set(workspace.object_references) <= {item.Reference() for item in basis.objects}:
            raise SbomFailure("integrity")

        evidence = SbomEvidenceStore(root / "evidence")
        target = image.Object(basis.workspace_id).Reference()
        outcome["source_selection"] = "file" if options.file is not None else "retained"

        if options.file is not None:
            phase = "acquisition"
            assert consent is not None, "File mode requires explicitly validated read consent"
            raw, started, finished = ReadOwnedSbom(options.file, consent, clock)
            source = EvidenceProvenance(workspace.workspace_id, scope.Reference(),
                options.source_id, options.source_version, options.provider_version,
                started, finished)
            digest = hashlib.sha256(raw).hexdigest()
            expected = EvidenceRecord(EvidenceReference("sbom", "blobs/sha256/" + digest,
                digest, "application/json", len(raw)), source)
            record = expected

        else:
            record = evidence.Manifest(options.evidence)
            source = record.provenance

        if source.workspace_id != basis.workspace_id or source.scope_reference != scope.Reference():
            raise SbomFailure("source-context")

        provenance = ModelProvenance(source.source_id, options.run, source.finished_at,
            scope.Reference(), target, source.tool_version, (record.reference,))
        fact = SourceFact(basis, record, provenance, image, consent)
        CheckBases(root, workspace, basis, scope)
        CheckKnownSbomSources(evidence, record.reference, workspace, basis)
        original = OpenReportInput(root)

        if original.workspace != workspace or original.report.state != basis:
            raise SbomFailure("basis-changed")

        if options.file is not None:
            outcome.update({"evidence_id": expected.evidence_id, "acquisition_commit": "unknown"})
            record = evidence.Put(raw, "sbom", "application/json", source)

            if record != expected:
                raise SbomFailure("integrity")

        if evidence.Get(record.evidence_id) != record:
            raise SbomFailure("integrity")

        outcome.update({"acquisition_commit": "confirmed", "evidence_id": record.evidence_id,
            "source_sha256": record.reference.sha256, "received_bytes": record.reference.size_bytes,
            "started_at": source.started_at, "finished_at": source.finished_at})
        phase = "normalization"
        proposed, delta = ApplyVerifiedSpdxGraph(basis, record, provenance, image, root)
        proposed, delta = ApplySourceFact(proposed, delta, fact)
        phase = "model-verification"
        CheckBases(root, workspace, basis, scope)
        phase = "model-save"
        outcome["model_commit"] = "unknown"
        saved = LocalModelStore(root).Save(proposed, expected_revision=basis.revision)
        outcome.update({"model_commit": "confirmed", "model_revision": saved.revision,
                        "created": len(delta.created), "updated": len(delta.updated)})
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
        outcome["status"] = "succeeded"
        status = 0

    except SbomFailure as error:
        outcome["failure"] = error.category
        status = error.status

    except (WorkspaceBusyError, WorkspaceConflictError) as error:
        owner = "workspace" if phase == "workspace-save" else "model"
        outcome[owner + "_commit"] = "not-committed"
        outcome["failure"] = owner + ("-busy" if isinstance(error, WorkspaceBusyError)
                                      else "-conflict")

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
        output.write(f"{outcome['command']}: {outcome['status']}\n")

        for name in ("evidence_id", "model_revision", "workspace_revision",
                     "acquisition_commit", "model_commit", "workspace_commit", "failure"):
            if outcome[name] is not None:
                output.write(f"{name}: {outcome[name]}\n")

    return status
