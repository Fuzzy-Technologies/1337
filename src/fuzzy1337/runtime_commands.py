# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal owned offline runtime import with independent truthful storage acknowledgements."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Never, TextIO

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.adapters.contracts import RequireIdentifier
from fuzzy1337.artifact_inputs import (
    ArtifactReadConsent,
    MatchesArtifactReadIdentity,
    PhysicalIdentity,
)
from fuzzy1337.docker_inventory import ApplyVerifiedDockerInspect, DockerInventoryLimits
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
from fuzzy1337.kubernetes_inventory import ApplyVerifiedKubernetesList, KubernetesInventoryLimits
from fuzzy1337.model import (
    CanonicalModelJson,
    LocalModelStore,
    ModelDelta,
    ModelProvenance,
    ModelState,
    ObjectKind,
    Observation,
    Relation,
    RequireModelReference,
    SecurityObject,
)
from fuzzy1337.policy import UtcNow
from fuzzy1337.report_commands import MAX_EXPORT_ACQUISITIONS, OpenReportInput
from fuzzy1337.scope import LocalScopeStore, ScopeSnapshot
from fuzzy1337.workspace import (
    LocalWorkspaceStore,
    RequireWorkspaceInteger,
    RequireWorkspaceText,
    WorkspaceBusyError,
    WorkspaceConflictError,
    WorkspaceState,
)

_SOURCE_ID = "inventory.docker-inspect"
_SOURCE_VERSION = "owned-docker-container-inspect-v1"
_MAX_BYTES = DockerInventoryLimits().max_bytes
_PROFILES = MappingProxyType({
    "docker-inspect": (_SOURCE_ID, _SOURCE_VERSION, _MAX_BYTES),
    "kubernetes-list": ("inventory.kubernetes-list", "owned-kubernetes-list-v1",
                        KubernetesInventoryLimits().max_bytes),
})


class RuntimeFailure(RuntimeError):
    """Carry only a fixed local failure category, never rejected source or path values."""

    def __init__(self, category: str, status: int = 4) -> None:
        """Keep a trusted category and process status for one terminal outcome."""

        super().__init__(category)
        self.category = category
        self.status = status


class RuntimeArgumentParser(argparse.ArgumentParser):
    """Replace framework diagnostics that can echo filenames, consent or rejected values."""

    def Error(self, message: str) -> Never:
        """Reject invalid grammar without rendering argparse's untrusted diagnostic.

        Args:
            message: Unretained framework text, which may include source values.

        Returns:
            Never returns; the handler receives a fixed configuration failure.
        """

        raise RuntimeFailure("configuration", 2)

    error = Error


class RuntimeEvidenceStore(LocalEvidenceStore):
    """Bind the actual original reference to one selected profile before eager blob reads."""

    def __init__(self, root: Path, *, profile: str = "docker-inspect") -> None:
        """Retain one exact closed profile and its fixed original byte ceiling.

        Args:
            root: Existing owning workspace evidence directory.
            profile: Explicit profile; the legacy Internal constructor retains Docker semantics.
        """

        _, _, self.maximum = RuntimeProfile(profile)
        self.profile = profile
        super().__init__(root)

    def Read(self, reference: EvidenceReference) -> bytes:
        """Admit only the fixed profile role/media and its original one-MiB byte ceiling.

        Args:
            reference: Explicit or actually parsed original manifest content reference.

        Returns:
            Original verified selected-profile bytes without interpretation or retrieval.
        """

        self.CheckReference(reference)

        return super().Read(reference)

    def CheckReference(self, reference: EvidenceReference) -> None:
        """Check fixed role/media/size and actual physical ownership before any raw byte read.

        Args:
            reference: Exact original reference from a manifest or retained model provenance.
        """

        if type(reference) is not EvidenceReference or reference.role != self.profile or (
            reference.media_type != "application/json"
            or type(reference.size_bytes) is not int
            or not 1 <= reference.size_bytes <= self.maximum
        ):
            raise RuntimeFailure("integrity")

        RequireEvidenceDigest(reference.sha256)

        if reference.locator != "blobs/sha256/" + reference.sha256:
            raise RuntimeFailure("integrity")

        metadata = CheckStorageEntry(
            self.StoragePath(("blobs", "sha256", reference.sha256)), directory=False,
        )

        if metadata.st_nlink != 1 or metadata.st_size != reference.size_bytes:
            raise RuntimeFailure("integrity")

    def Get(self, evidence_id: str) -> EvidenceRecord:
        """Check the exact selected original manifest profile before the owner's eager blob read.

        Args:
            evidence_id: Explicit original SHA-256 manifest selection.

        Returns:
            Original record after unchanged manifest identity and complete raw-byte verification.
        """

        self.Manifest(evidence_id)

        return super().Get(evidence_id)

    def Manifest(self, evidence_id: str) -> EvidenceRecord:
        """Preflight the original identity/profile without reading any referenced raw blob.

        Args:
            evidence_id: Explicit selected original manifest identity.

        Returns:
            Exact parsed original record for caller-owned context checks before raw reads.
        """

        if type(evidence_id) is not str or not evidence_id.startswith("sha256:"):
            raise RuntimeFailure("integrity")

        RequireEvidenceDigest(evidence_id[7:])
        data = self.ReadStoredBytes(("records", evidence_id[7:] + ".json"),
                                    EVIDENCE_MANIFEST_MAX_BYTES)
        record = ParseEvidenceManifest(data)
        source_id, source_version, _ = RuntimeProfile(self.profile)

        if record.evidence_id != evidence_id or record.provenance.source_id != source_id or (
            record.provenance.source_version != source_version
            or record.provenance.execution is not None
            or record.provenance.invocation_sha256 is not None
        ):
            raise RuntimeFailure("integrity")

        self.CheckReference(record.reference)

        return record


def RuntimeProfile(profile: str) -> tuple[str, str, int]:
    """Return only fixed source identity and limits for an exact selected offline profile.

    Args:
        profile: Literal Docker inspect or Kubernetes List profile, without default inference.

    Returns:
        Fixed source ID, version and original byte ceiling.
    """

    if type(profile) is not str or profile not in _PROFILES:
        raise RuntimeFailure("configuration", 2)

    return _PROFILES[profile]


def PreflightKnownRuntimeReferences(state: ModelState, workspace: WorkspaceState,
                                    evidence: LocalEvidenceStore) -> None:
    """Bound known closed-profile originals and aliases before any generic retained raw read.

    Args:
        state: Current owning model, including custody after a lost workspace acknowledgement.
        workspace: Independently selected owner and retained manifest/raw references.
        evidence: Original evidence partition; unrelated roles keep their existing owner bounds.
    """

    entities: tuple[SecurityObject | Relation, ...] = (*state.objects, *state.relations)
    contexts = [provenance for item in entities for provenance in item.provenance]
    contexts.extend(item.provenance for item in state.observations)
    references = {*workspace.evidence_references,
                  *(item for context in contexts for item in context.evidence_references)}
    record_ids = set(workspace.evidence_record_references)
    custody: dict[str, list[Observation]] = {}

    for fact in state.observations:
        if fact.kind != "runtime-import-source":
            continue

        profile = fact.attributes.get("profile")
        evidence_id = fact.attributes.get("evidence_id")

        if type(profile) is not str or profile not in _PROFILES or type(evidence_id) is not str:
            raise RuntimeFailure("source-context")

        custody.setdefault(evidence_id, []).append(fact)
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

        reference, source = record.reference, record.provenance
        original_facts = custody.get(evidence_id, [])

        if any(fact.attributes["profile"] != reference.role for fact in original_facts):
            raise RuntimeFailure("source-context" if reference.role in _PROFILES else "integrity")

        if reference.role not in _PROFILES:
            continue

        source_id, source_version, _ = RuntimeProfile(reference.role)

        if source.workspace_id != workspace.workspace_id or source.source_id != source_id or (
            source.source_version != source_version or source.execution is not None
            or source.invocation_sha256 is not None
        ):
            raise RuntimeFailure("integrity")

        for fact in original_facts:
            try:
                anchor = RequireRuntimeAnchor(state, reference.role, fact.subject_reference)
                provenance = ModelProvenance(source_id, fact.provenance.run_reference,
                    source.finished_at, source.scope_reference, anchor, source.tool_version,
                    (reference,))
                SourceFact(state, record, provenance, None, profile=reference.role)

            except (RuntimeFailure, ValueError, TypeError):
                raise RuntimeFailure("source-context") from None

        RuntimeEvidenceStore(evidence.root, profile=reference.role).CheckReference(reference)
        references.add(reference)

    for reference in references:
        if reference.role not in _PROFILES:
            continue

        RuntimeEvidenceStore(evidence.root, profile=reference.role).CheckReference(reference)

        if any((item.sha256 == reference.sha256 or item.locator == reference.locator)
               and item != reference for item in references):
            raise RuntimeFailure("integrity")


def RequireRuntimeAnchor(state: ModelState, profile: str, reference: str) -> str:
    """Require the selected existing HOST or exact declared cluster ASSET before source reads.

    Args:
        state: Current validated owning snapshot, before evidence verification reads.
        profile: Exact closed selected profile.
        reference: Explicit canonical object reference, never an inferred target.

    Returns:
        Unchanged validated reference; no object or authority is created.
    """

    RuntimeProfile(profile)
    selected = RequireModelReference(reference)
    entity = next((item for item in state.objects if item.Reference() == selected), None)

    if profile == "docker-inspect":
        if entity is None or entity.identity.kind is not ObjectKind.HOST:
            raise RuntimeFailure("host", 2)

    else:
        if entity is None or entity.identity.kind is not ObjectKind.ASSET:
            raise RuntimeFailure("cluster", 2)

        cluster_id = entity.attributes.get("cluster_id")

        if entity.attributes.get("asset_type") != "kubernetes-cluster" or (
            type(cluster_id) is not str
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}", cluster_id)
            or entity.identity.key != "kubernetes-cluster:" + cluster_id
        ):
            raise RuntimeFailure("cluster", 2)

    return selected


def RuntimePath(path: Path) -> Path:
    """Require one explicit bounded physical path without resolving observed links.

    Args:
        path: Caller-selected existing workspace or single original file.

    Returns:
        Absolute lexical path after non-following parent directory checks.
    """

    value = str(path)

    if ".." in path.parts or len(value.encode("utf-8")) > 4096 or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise RuntimeFailure("configuration", 2)

    selected = path.absolute()

    for parent in reversed(selected.parents):
        CheckStorageEntry(parent, directory=True)

    return selected


def ReadOwnedInspect(path: Path, consent: ArtifactReadConsent,
                     clock: Callable[[], datetime], *, maximum: int = _MAX_BYTES
                     ) -> tuple[bytes, str, str]:
    """Read exactly one consented original file while observing bounded size and stable metadata.

    Args:
        path: Explicit current caller-owned physical source, never a daemon socket or mount path.
        consent: Exact explicit actor/read-record references, not a signature or scan grant.
        clock: Owning UTC observation clock called immediately around the original file read.
        maximum: Positive original ceiling, never above the unchanged one-MiB file-read bound.

    Returns:
        Unmodified complete bounded bytes and actual local-read observation timestamps.

    Raises:
        RuntimeFailure: Consent, file type/link count, size or observed stability is refused.
        OSError: The selected physical file cannot be read or observed.
    """

    if type(consent) is not ArtifactReadConsent:
        raise RuntimeFailure("configuration", 2)

    consent = ArtifactReadConsent(consent.actor_ref, consent.record_ref)

    if type(maximum) is not int or not 1 <= maximum <= _MAX_BYTES:
        raise RuntimeFailure("configuration", 2)

    selected = RuntimePath(path)
    before = CheckStorageEntry(selected, directory=False)

    if before.st_nlink != 1:
        raise RuntimeFailure("configuration", 2)

    if not 1 <= before.st_size <= maximum:
        raise RuntimeFailure("limit")

    started_at = clock().isoformat()

    with selected.open("rb") as stream:
        opened = os.fstat(stream.fileno())

        if opened.st_nlink != 1 or not MatchesArtifactReadIdentity(before, opened):
            raise RuntimeFailure("source-changed")

        raw = stream.read(maximum + 1)
        finished_at = clock().isoformat()
        finished = os.fstat(stream.fileno())

    after = CheckStorageEntry(selected, directory=False)
    if finished.st_nlink != 1 or after.st_nlink != 1 or (
        PhysicalIdentity(before) != PhysicalIdentity(after)
        or PhysicalIdentity(opened) != PhysicalIdentity(finished)
        or not MatchesArtifactReadIdentity(after, finished)
        or len(raw) != before.st_size
    ):
        raise RuntimeFailure("source-changed")

    return raw, started_at, finished_at


def RuntimeParser() -> argparse.ArgumentParser:
    """Declare only explicit owned file acquisition or original retained-evidence import.

    Returns:
        Internal namespace parser without daemon, scanner, discovery or policy-grant options.
    """

    parser = RuntimeArgumentParser(prog="1337 runtime", add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Explicit import selections:
  import docker-inspect WORKSPACE
    (--file FILE --owner ACTOR --read-consent-reference REFERENCE | --evidence sha256:MANIFEST)
    --host OBJECT_REFERENCE --scope SCOPE_ID --run RUN_REFERENCE
    --expected-revision MODEL_REVISION --expected-workspace-revision WORKSPACE_REVISION
    [--provider-version DECLARED_VERSION]
  import kubernetes-list WORKSPACE
    (--file FILE --owner ACTOR --read-consent-reference REFERENCE | --evidence sha256:MANIFEST)
    --cluster OBJECT_REFERENCE --scope SCOPE_ID --run RUN_REFERENCE
    --expected-revision MODEL_REVISION --expected-workspace-revision WORKSPACE_REVISION
    [--provider-version DECLARED_VERSION]
Retained evidence preserves original context and accepts no file-read or provider overrides.""")
    actions = parser.add_subparsers(dest="action", required=True,
                                   parser_class=RuntimeArgumentParser)
    importer = actions.add_parser("import", add_help=False)
    importer.add_argument("profile", choices=tuple(_PROFILES))
    importer.add_argument("workspace", type=Path)
    selection = importer.add_mutually_exclusive_group(required=True)
    selection.add_argument("--file", type=Path)
    selection.add_argument("--evidence")

    anchor = importer.add_mutually_exclusive_group(required=True)
    anchor.add_argument("--host")
    anchor.add_argument("--cluster")

    for name in ("scope", "run"):
        importer.add_argument("--" + name, required=True)

    importer.add_argument("--expected-revision", type=int, required=True)
    importer.add_argument("--expected-workspace-revision", type=int, required=True)
    importer.add_argument("--owner")
    importer.add_argument("--read-consent-reference")
    importer.add_argument("--provider-version")

    return parser


def CheckBases(root: Path, workspace: WorkspaceState, model: ModelState,
               scope: ScopeSnapshot) -> None:
    """Refuse observed cooperating-writer changes without claiming cross-store atomic isolation.

    Args:
        root: Exact existing owning workspace.
        workspace: Last explicitly selected or successfully saved workspace snapshot.
        model: Exact explicitly selected or successfully saved canonical model snapshot.
        scope: Existing local scope retained for attribution, never an execution grant.

    Raises:
        RuntimeFailure: A selected authoritative snapshot differs when reopened.
    """

    if LocalWorkspaceStore(root).Open() != workspace:
        raise RuntimeFailure("workspace-conflict")

    if LocalModelStore(root).Open() != model:
        raise RuntimeFailure("revision-conflict")

    if LocalScopeStore(root).Open(scope.scope_id) != scope:
        raise RuntimeFailure("scope-conflict")


def SourceFact(state: ModelState, record: EvidenceRecord, provenance: ModelProvenance,
               consent: ArtifactReadConsent | None, *, profile: str = "docker-inspect"
               ) -> Observation:
    """Bind original manifest identity and retain original profile/anchor/run/read descriptions.

    Args:
        state: Exact owning basis containing any original import source fact.
        record: Original manifest already verified through its owning store.
        provenance: Exact original source/scope/version/time/raw-reference offline attribution.
        consent: Explicit current file-read references, or None for retained original selection.
        profile: Exact selected profile; legacy Internal callers retain Docker semantics.

    Returns:
        Original immutable source fact on replay, or one inert first product custody observation.

    Raises:
        RuntimeFailure: Existing original manifest or compatible SDK attribution changes context.
    """

    source_id, source_version, _ = RuntimeProfile(profile)
    facts = [item for item in state.observations if item.kind == "runtime-import-source"
             and item.attributes.get("evidence_id") == record.evidence_id]

    if facts:
        if len(facts) != 1 or facts[0].subject_reference != provenance.target_reference or (
            facts[0].provenance != provenance
            or set(facts[0].attributes) != {
                "profile", "evidence_id", "source_sha256", "source_version",
                "read_actor_reference", "read_consent_reference",
            }
            or facts[0].attributes.get("profile") != profile
            or facts[0].attributes.get("source_sha256") != record.reference.sha256
            or facts[0].attributes.get("source_version") != source_version
        ):
            raise RuntimeFailure("source-context")

        actor = facts[0].attributes["read_actor_reference"]
        read_reference = facts[0].attributes["read_consent_reference"]

        if actor is not None or read_reference is not None:
            if not isinstance(actor, str) or not isinstance(read_reference, str):
                raise RuntimeFailure("source-context")

            try:
                original_consent = ArtifactReadConsent(actor, read_reference)

            except ValueError:
                raise RuntimeFailure("source-context") from None

            if consent is not None and original_consent != consent:
                raise RuntimeFailure("source-context")

        elif consent is not None:
            raise RuntimeFailure("source-context")

        return facts[0]

    contexts = [item.provenance for item in state.observations
                if item.provenance.source_id == source_id
                and item.provenance.observed_at == record.provenance.finished_at
                and record.reference in item.provenance.evidence_references]

    if any(context != provenance for context in contexts):
        raise RuntimeFailure("source-context")

    return Observation("runtime-import-source", provenance.target_reference, {
        "profile": profile, "evidence_id": record.evidence_id,
        "source_sha256": record.reference.sha256, "source_version": source_version,
        "read_actor_reference": consent.actor_ref if consent is not None else None,
        "read_consent_reference": consent.record_ref if consent is not None else None,
    }, provenance)


def ApplySourceFact(state: ModelState, delta: ModelDelta, fact: Observation
                    ) -> tuple[ModelState, ModelDelta]:
    """Fold the explicit custody fact into the SDK's one atomic in-memory transition.

    Args:
        state: Validated SDK proposal with existing finding triage retained.
        delta: SDK aggregate delta from the original owning basis.
        fact: Original manifest-bound inert custody observation.

    Returns:
        One combined canonical revision and delta, including a no-op exact replay.
    """

    proposed, extra = state.Apply(observations=(fact,))
    created = set(delta.created) | set(extra.created)
    updated = (set(delta.updated) | set(extra.updated)) - created
    revision = delta.previous_revision + bool(created or updated)
    proposed = replace(proposed, revision=revision)

    return proposed, ModelDelta(delta.previous_revision, revision,
                                tuple(sorted(created)), tuple(sorted(updated)))


def ReferenceProposal(workspace: WorkspaceState, model: ModelState, record: EvidenceRecord,
                      scope: ScopeSnapshot) -> WorkspaceState:
    """Retain original acquisition and canonical object/scope references without creating a job.

    Args:
        workspace: Exact original workspace basis for its independent CAS owner.
        model: Exact successfully saved model snapshot.
        record: Immutable owning original selected-profile acquisition manifest.
        scope: Existing local source attribution scope.

    Returns:
        Validated proposal at the selected workspace revision; replay may equal the basis.
    """

    references = {(item.locator, item.role): item for item in workspace.evidence_references}
    references[(record.reference.locator, record.reference.role)] = record.reference

    return replace(workspace,
        scope_references=tuple(sorted({*workspace.scope_references, scope.Reference()})),
        object_references=tuple(sorted(item.Reference() for item in model.objects)),
        evidence_references=tuple(references[key] for key in sorted(references)),
        evidence_record_references=tuple(sorted({*workspace.evidence_record_references,
                                                 record.evidence_id})))


def RunRuntimeCommands(arguments: Sequence[str], output: TextIO, *, json_output: bool = False,
                       clock: Callable[[], datetime] = UtcNow) -> int:
    """Compose original acquisition, unchanged SDK and independently acknowledged CAS saves.

    Args:
        arguments: Explicit import profile, owning bases, source selection and current read consent.
        output: Caller-owned bounded summary stream; original source never enters presentation.
        json_output: Emit one Internal schema-v1 terminal acknowledgement record.
        clock: Actual local-read observation clock; retained replay never calls it.

    Returns:
        Zero on success, two for configuration refusal, four for source/normalization/storage
        failure, or 130 for interruption. A failed save can already have committed; unknown
        acknowledgement and separately confirmed owners are preserved without rollback.
    """

    parser = RuntimeParser()

    if "--help" in arguments or "-h" in arguments:
        parser.print_help(file=output)

        return 0

    outcome: dict[str, object] = {
        "schema_version": 1, "command": "runtime.import.docker-inspect", "status": "failed",
        "source_selection": None, "evidence_id": None, "source_sha256": None,
        "received_bytes": None, "started_at": None, "finished_at": None,
        "acquisition_commit": "not-attempted", "model_commit": "not-attempted",
        "workspace_commit": "not-attempted", "model_revision": None,
        "workspace_revision": None, "created": None, "updated": None, "failure": None,
    }

    if list(arguments[:2]) == ["import", "kubernetes-list"]:
        outcome["command"] = "runtime.import.kubernetes-list"

    status = 4
    phase = "configuration"

    try:
        options = parser.parse_args(arguments)
        source_id, source_version, maximum = RuntimeProfile(options.profile)
        outcome["command"] = "runtime.import." + options.profile

        if (options.profile == "docker-inspect" and options.host is None) or (
            options.profile == "kubernetes-list" and options.cluster is None
        ):
            raise RuntimeFailure("configuration", 2)

        RequireWorkspaceInteger(options.expected_revision, "expected_revision")
        RequireWorkspaceInteger(options.expected_workspace_revision, "expected_workspace_revision")
        RequireWorkspaceText(options.run, "run_reference")
        RequireIdentifier(options.scope, "scope_id")
        anchor = RequireModelReference(
            options.host if options.host is not None else options.cluster)
        consent = None

        if options.provider_version is not None:
            RequireWorkspaceText(options.provider_version, "provider_version")

        if options.file is not None:
            consent = ArtifactReadConsent(options.owner, options.read_consent_reference)

        elif any(value is not None for value in (
            options.owner, options.read_consent_reference, options.provider_version,
        )):
            raise RuntimeFailure("configuration", 2)

        root = RuntimePath(options.workspace)
        phase = "integrity"
        workspace = LocalWorkspaceStore(root).Open()
        basis = LocalModelStore(root).Open()
        scope = LocalScopeStore(root).Open(options.scope)

        if basis.revision != options.expected_revision:
            raise RuntimeFailure("revision-conflict")

        if workspace.revision != options.expected_workspace_revision:
            raise RuntimeFailure("workspace-conflict")

        if not set(workspace.object_references) <= {item.Reference() for item in basis.objects}:
            raise RuntimeFailure("integrity")

        anchor = RequireRuntimeAnchor(basis, options.profile, anchor)
        evidence = RuntimeEvidenceStore(root / "evidence", profile=options.profile)

        if options.evidence is not None:
            selected_record = evidence.Manifest(options.evidence)

            if selected_record.provenance.workspace_id != workspace.workspace_id or (
                selected_record.provenance.scope_reference != scope.Reference()
            ):
                raise RuntimeFailure("integrity")

        PreflightKnownRuntimeReferences(basis, workspace, evidence)
        original = OpenReportInput(root)

        if original.workspace != workspace:
            raise RuntimeFailure("workspace-conflict")

        if original.report.state != basis:
            raise RuntimeFailure("revision-conflict")

        outcome["source_selection"] = "file" if options.file is not None else "retained"

        if options.file is not None:
            phase = "acquisition"

            if consent is None:
                raise RuntimeFailure("configuration", 2)

            raw, started, finished = ReadOwnedInspect(options.file, consent, clock, maximum=maximum)
            source = EvidenceProvenance(workspace.workspace_id, scope.Reference(), source_id,
                                       source_version, options.provider_version, started, finished)
            digest = hashlib.sha256(raw).hexdigest()
            expected = EvidenceRecord(EvidenceReference(options.profile,
                "blobs/sha256/" + digest, digest,
                "application/json", len(raw)), source)
            outcome.update({"evidence_id": expected.evidence_id,
                            "acquisition_commit": "unknown"})
            record = evidence.Put(raw, options.profile, "application/json", source)

            if record != expected:
                raise RuntimeFailure("integrity")

        else:
            record = evidence.Get(options.evidence)

        source = record.provenance

        if source.workspace_id != basis.workspace_id or source.source_id != source_id or (
            source.source_version != source_version or source.scope_reference != scope.Reference()
            or source.invocation_sha256 is not None or source.execution is not None
            or evidence.Get(record.evidence_id) != record
        ):
            raise RuntimeFailure("integrity")

        outcome.update({"acquisition_commit": "confirmed", "evidence_id": record.evidence_id,
                        "source_sha256": record.reference.sha256,
                        "received_bytes": record.reference.size_bytes,
                        "started_at": source.started_at, "finished_at": source.finished_at})
        provenance = ModelProvenance(source_id, options.run, source.finished_at,
            source.scope_reference, anchor, source.tool_version, (record.reference,))
        fact = SourceFact(basis, record, provenance, consent, profile=options.profile)
        phase = "normalization"

        if options.profile == "docker-inspect":
            proposed, delta = ApplyVerifiedDockerInspect(basis, record, provenance,
                host_reference=anchor, workspace_root=root)

        else:
            proposed, delta = ApplyVerifiedKubernetesList(basis, record, provenance,
                cluster_reference=anchor, workspace_root=root)

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

    except RuntimeFailure as error:
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
