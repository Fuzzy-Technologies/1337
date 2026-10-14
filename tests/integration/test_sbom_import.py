# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Original custody, saved graph history, alias preflights and truthful storage outcomes."""

from __future__ import annotations

from dataclasses import replace

import pytest

import fuzzy1337.sbom_commands as commands
from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.findings import ApplyFindings, Finding, Findings, FindingStatus, TransitionFinding
from fuzzy1337.images import IMAGE_IMPORT_MAX_BYTES
from fuzzy1337.model import LocalModelStore, Observation
from fuzzy1337.policy import UtcNow
from fuzzy1337.reachability import (
    ProjectReachability,
    ReachabilityModelVersion,
    ReachabilityState,
    ReadReachabilityClaims,
)
from fuzzy1337.scope import LocalScopeStore, ScopeSnapshot
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceBusyError, WorkspaceConflictError
from tests.sbom_helpers import Arguments, Context, OwnedSbom, Run, Value


def Imported(parent):
    """Acquire through the actual product handler before constructing hostile replay inputs."""

    owned = Context(parent)
    status, outcome = Run(Arguments(owned))
    assert status == 0, "Actual original product acquisition must complete before replay testing"

    return owned, outcome


def test_OriginalRelocatedReplayIsByteExactNoopAndUsesNoFileClock(tmp_path):
    """Original manifest, model, custody and workspace survive relocation and exact replay."""

    owned, original = Imported(tmp_path)
    model_path = owned.root / "state/model/model.json"
    model_bytes = model_path.read_bytes()
    record = LocalEvidenceStore(owned.root / "evidence").Get(original["evidence_id"])
    manifest_bytes = record.Serialize()
    moved = tmp_path / "relocated workspace"
    owned.root.rename(moved)
    owned = OwnedSbom(moved, owned.source)

    def Forbidden():
        """Trip any new file-acquisition clock call during original retained replay."""

        raise AssertionError("Retained replay cannot claim a new file read")

    status, outcome = Run(Arguments(owned, evidence_id=record.evidence_id), clock=Forbidden)
    assert status == 0 and outcome["created"] == outcome["updated"] == 0 and (
        outcome["model_revision"] == original["model_revision"]
        and outcome["workspace_revision"] == original["workspace_revision"]
    ), "Exact original portable replay must remain a no-op for both independent saved owners"
    assert (moved / "state/model/model.json").read_bytes() == model_bytes and (
        LocalEvidenceStore(moved / "evidence").Get(record.evidence_id).Serialize() == manifest_bytes
    ), "Relocation/replay must preserve actual saved model and original manifest bytes"


def test_SeparateOriginalAcquisitionsKeepConfigAndManifestImagesDistinct(tmp_path):
    """Equal checksum bytes do not collapse the explicitly declared image digest-kind namespace."""

    owned, first = Imported(tmp_path)
    status, second = Run(Arguments(owned, digest_kind="manifest"))
    state = LocalModelStore(owned.root).Open()
    images = [item for item in state.objects if item.attributes.get("asset_type") == "image"]
    kinds = {item.attributes["digest_kind"] for item in images}
    assert status == 0 and len(images) == 2 and kinds == {"config", "manifest"}, (
        "Separate explicit original acquisitions must retain distinct image hash-kind identities"
    )
    assert first["source_sha256"] == second["source_sha256"] and (
        first["evidence_id"] != second["evidence_id"]
    ), "Raw equality cannot substitute one independently observed acquisition manifest for another"


def test_ActualDependencyProjectionRemainsUnknownWithoutSeparateAssessment(tmp_path):
    """Original package dependency claims do not become verified runtime reachability."""

    owned, _ = Imported(tmp_path)
    state = LocalModelStore(owned.root).Open()
    version = ReachabilityModelVersion.FromModel(state)
    claims = ReadReachabilityClaims(state, (), workspace_root=owned.root,
        expected_model_version=version, context_reference="context:owned-spdx",
        scope_reference="scope:owned", at=UtcNow().isoformat())
    selected = tuple(item.Reference() for item in state.relations
                     if item.attributes.get("association") == "spdx-dependency-claim")
    projection = ProjectReachability(state, selected, claims, expected_model_version=version)
    assert len(selected) == projection.unknown_transitions == (
        projection.unassessed_transitions
    ) == 3, (
        "All three dependency relations stay unassessed UNKNOWN in the actual graph consumer"
    )
    assert all(item.state is ReachabilityState.UNKNOWN for item in projection.transitions), (
        "No dependency claim may grant a confirmed transition or invented reverse reachability"
    )


def test_ImportPreservesExistingFindingTriageAndUnrelatedHistory(tmp_path):
    """Graph import links existing packages while retaining operator disposition and prior facts."""

    owned, _ = Imported(tmp_path)
    store = LocalModelStore(owned.root)
    state = store.Open()
    package = next(item for item in state.objects if item.attributes.get("asset_type") == "package")
    context = replace(package.provenance[0], source_id="owned.detector",
                      run_reference="run:detector")
    finding = Finding(package.Reference(), "owned.synthetic", "package:owned", "Owned test finding",
                      (context,))
    detected, _ = ApplyFindings(state, (finding,))
    state = store.Save(detected, expected_revision=state.revision)
    operator = replace(context, source_id="operator", run_reference="decision:owned")
    decided, _ = TransitionFinding(state, finding.ToObject(state.workspace_id).Reference(),
        FindingStatus.DISMISSED, operator, "Owned operator dismissal")
    state = store.Save(decided, expected_revision=state.revision)
    before = Findings(state)
    status, outcome = Run(Arguments(owned))
    assert status == 0 and Findings(store.Open()) == before and (
        Findings(store.Open())[0].status is FindingStatus.DISMISSED
    ), "Actual new original graph acquisition cannot rewrite detector facts or explicit triage"
    assert outcome["model_revision"] == state.revision + 1, (
        "Graph facts and product custody must remain one in-memory model transition"
    )


@pytest.mark.parametrize("mode", ["run", "image-kind", "scope", "same-raw-new-manifest",
                                  "raw-digest", "custody-field"])
def test_KnownOriginalCustodyRefusesContextOrManifestSubstitutionBeforeRawReads(
    tmp_path, monkeypatch, mode
):
    """Independently pinned original manifest/context is verified before every selected raw read."""

    owned, imported = Imported(tmp_path)
    evidence = LocalEvidenceStore(owned.root / "evidence")
    record = evidence.Get(imported["evidence_id"])
    arguments = Arguments(owned, evidence_id=record.evidence_id)

    if mode == "run":
        arguments = Value(arguments, "--run", "run:changed")

    elif mode == "image-kind":
        arguments = Value(arguments, "--image-digest-kind", "manifest")

    elif mode == "scope":
        LocalScopeStore(owned.root).Create(ScopeSnapshot("other", "owned-sbom"))
        arguments = Value(arguments, "--scope", "other")

    elif mode == "same-raw-new-manifest":
        foreign = evidence.Put(evidence.Read(record.reference), "sbom", "application/json",
            replace(record.provenance, source_version="another-declared-version"))
        assert foreign.reference == record.reference and (
            foreign.evidence_id != record.evidence_id
        ), (
            "The hostile specimen must actually share raw bytes while changing original custody"
        )
        arguments = Value(arguments, "--evidence", foreign.evidence_id)

    elif mode == "raw-digest":
        arguments = Value(arguments, "--evidence", "sha256:" + record.reference.sha256)

    else:
        store = LocalModelStore(owned.root)
        state = store.Open()
        fact = next(item for item in state.observations if item.kind == "sbom-import-source")
        altered = replace(fact, attributes=dict(fact.attributes, source_version="changed"))
        store.WriteState(store.ValidatePaths(), replace(state, observations=tuple(
            altered if item is fact else item for item in state.observations)))

    calls = []

    def Forbidden(*_args, **_kwargs):
        """Trip any selected/generic raw reader before original context refusal."""

        calls.append("raw")

        raise AssertionError("Substituted original context reached raw bytes")

    monkeypatch.setattr(LocalEvidenceStore, "Read", Forbidden)
    monkeypatch.setattr(commands, "OpenReportInput", Forbidden)
    status, outcome = Run(arguments)
    assert status == 4 and not calls and outcome["acquisition_commit"] == "not-attempted", (
        "Wrong context or original identity cannot borrow raw-content equality to reach readers"
    )


@pytest.mark.parametrize("flag,value", [("--owner", "owner:changed"),
    ("--read-consent-reference", "read:changed"), ("--source-id", "source.changed"),
    ("--source-version", "changed"), ("--provider-version", "changed")])
def test_RetainedModeRefusesEveryAcquisitionOverride(tmp_path, monkeypatch, flag, value):
    """Known retained acquisition fields cannot be re-declared by file-mode options."""

    owned, imported = Imported(tmp_path)
    arguments = [*Arguments(owned, evidence_id=imported["evidence_id"]), flag, value]

    def Forbidden(*_args, **_kwargs):
        """Trip any owning source lookup after invalid override grammar."""

        raise AssertionError("Retained source override reached a manifest or raw reader")

    monkeypatch.setattr(commands.SbomEvidenceStore, "Manifest", Forbidden)
    status, outcome = Run(arguments)
    assert status == 2 and outcome["model_commit"] == "not-attempted", (
        "Retained context is original manifest custody, never caller-supplied override fields"
    )


@pytest.mark.parametrize("placement", ["workspace", "model", "manifest", "physical-oversize"])
def test_SelectedBlobAndEveryAliasPreflightBeforeGenericOwningReader(
    tmp_path, monkeypatch, placement
):
    """Generic report verification cannot read selected content through another role/size alias."""

    owned, imported = Imported(tmp_path)
    evidence = LocalEvidenceStore(owned.root / "evidence")
    record = evidence.Get(imported["evidence_id"])
    alias = replace(record.reference, role="stdout", size_bytes=record.reference.size_bytes + 1)

    if placement == "workspace":
        store = LocalWorkspaceStore(owned.root)
        store.Save(replace(store.Open(), evidence_references=(record.reference, alias)))

    elif placement == "model":
        store = LocalModelStore(owned.root)
        state = store.Open()
        fact = next(item for item in state.observations if item.kind == "sbom-import-source")
        context = replace(fact.provenance, evidence_references=(alias,))
        proposed, _ = state.Apply(observations=(Observation("owned-alias", fact.subject_reference,
                                                           {}, context),))
        store.Save(proposed, expected_revision=state.revision)

    elif placement == "manifest":
        other = evidence.Put(evidence.Read(record.reference), "stdout", "application/json",
                             record.provenance)
        store = LocalWorkspaceStore(owned.root)
        state = store.Open()
        store.Save(replace(state, evidence_record_references=tuple(sorted({
            *state.evidence_record_references, other.evidence_id}))))

    else:
        blob = owned.root / "evidence" / record.reference.locator

        with blob.open("wb") as stream:
            stream.truncate(IMAGE_IMPORT_MAX_BYTES + 1)

    arguments = Arguments(owned, evidence_id=record.evidence_id)
    calls = []

    def Forbidden(*_args, **_kwargs):
        """Trip generic report or raw-owning verification if selected preflight was late."""

        calls.append("raw")

        raise AssertionError("Selected oversized or incompatible alias reached generic raw bytes")

    monkeypatch.setattr(commands, "OpenReportInput", Forbidden)
    monkeypatch.setattr(LocalEvidenceStore, "Read", Forbidden)
    status, outcome = Run(arguments)
    assert status == 4 and outcome["failure"] in {"selected-source", "selected-source-alias"} and (
        not calls
    ), "Actual selected bytes and every retained alias must preflight before generic raw readers"


@pytest.mark.parametrize("mode", ["malformed", "checksum", "dependency-only"])
def test_ActualSourceRejectionPreservesOriginalAcquisitionWithoutModelCommit(tmp_path, mode):
    """Unsupported original graph bytes stay retained while neither saved state is fabricated."""

    import json

    owned = Context(tmp_path)
    payload = json.loads(owned.source.read_bytes())

    if mode == "malformed":
        owned.source.write_bytes(b"{malformed owned source")

    elif mode == "checksum":
        root = next(item for item in payload["packages"] if item["SPDXID"] == "SPDXRef-Image")
        root["checksums"][0]["checksumValue"] = "b" * 64
        owned.source.write_text(json.dumps(payload))

    else:
        payload["relationships"] = [item for item in payload["relationships"]
            if item["relationshipType"] not in {"CONTAINS", "CONTAINED_BY"}]
        owned.source.write_text(json.dumps(payload))

    status, outcome = Run(Arguments(owned))
    assert status == 4 and outcome["failure"] == "normalization" and (
        outcome["acquisition_commit"] == "confirmed"
        and outcome["model_commit"] == outcome["workspace_commit"] == "not-attempted"
    ), "Original source rejection retains acquisition truth without inventing saved-state success"
    record = LocalEvidenceStore(owned.root / "evidence").Get(outcome["evidence_id"])
    assert LocalEvidenceStore(owned.root / "evidence").Read(record.reference) == (
        owned.source.read_bytes()
    ) and LocalModelStore(owned.root).Open().revision == 0 and (
        LocalWorkspaceStore(owned.root).Open().revision == 0
    ), "Actually published orphan acquisition remains original; saved owners do not claim rollback"


@pytest.mark.parametrize("owner", ["model", "workspace", "scope"])
def test_ObservedWriterChangeAfterFileReadRefusesBeforeGenericReadsOrAcquisition(
    tmp_path, monkeypatch, owner
):
    """Independent current snapshots are checked again before generic raw reads and any write."""

    owned = Context(tmp_path)
    arguments = Arguments(owned)
    original = commands.ReadOwnedSbom

    def Read(*args, **kwargs):
        """Read actual consented bytes before applying one cooperating owner metadata change."""

        value = original(*args, **kwargs)

        if owner == "model":
            store = LocalModelStore(owned.root)
            state = store.Open()
            store.Save(replace(state, revision=state.revision + 1),
                       expected_revision=state.revision)

        elif owner == "workspace":
            store = LocalWorkspaceStore(owned.root)
            store.Save(replace(store.Open(), job_references=("job:other",)))

        else:
            store = LocalScopeStore(owned.root)
            store.Save(store.Open("owned"))

        return value

    calls = []

    def Forbidden(*_args, **_kwargs):
        """Trip any later generic raw verification or acquisition publication after basis drift."""

        calls.append("generic-or-write")

        raise AssertionError("Changed owning basis reached later raw reading or persistence")

    monkeypatch.setattr(commands, "ReadOwnedSbom", Read)
    monkeypatch.setattr(commands, "OpenReportInput", Forbidden)
    monkeypatch.setattr(commands.SbomEvidenceStore, "Put", Forbidden)
    status, outcome = Run(arguments)
    category = {"model": "revision-conflict", "workspace": "workspace-conflict",
                "scope": "scope-conflict"}[owner]
    assert status == 4 and outcome["failure"] == category and not calls and (
        outcome["acquisition_commit"] == "not-attempted"
    ), (
        "Observed cooperating writer changes must refuse before generic reading or custody writes"
    )


@pytest.mark.parametrize("source_mode", ["file", "retained"])
@pytest.mark.parametrize("kind", ["old-sbom-size", "old-physical-size", "old-alias",
                                  "same-locator"])
def test_EveryKnownOriginalSbomAndAliasPreflightsBeforeGenericReadInBothModes(
    tmp_path, monkeypatch, source_mode, kind
):
    """An older original cannot bypass its SBOM ceiling through a different current selection."""

    owned, imported = Imported(tmp_path)
    evidence = LocalEvidenceStore(owned.root / "evidence")
    LocalScopeStore(owned.root).Create(ScopeSnapshot("other", "owned-sbom"))
    raw = b"x" * (IMAGE_IMPORT_MAX_BYTES + 1) if kind == "old-sbom-size" else b"old owned SBOM"
    old = evidence.Put(raw, "sbom", "application/json", EvidenceProvenance(
        "owned-sbom", "scope:other", "old.sbom", "older-version", None,
        "2026-10-14T00:00:00Z", "2026-10-14T00:00:01Z"))
    aliases = []

    if kind == "old-alias":
        aliases.append(replace(old.reference, role="stdout", size_bytes=IMAGE_IMPORT_MAX_BYTES + 1))

    elif kind == "same-locator":
        aliases.append(replace(old.reference, role="stdout", sha256="b" * 64))

    elif kind == "old-physical-size":
        with (owned.root / "evidence" / old.reference.locator).open("wb") as stream:
            stream.truncate(IMAGE_IMPORT_MAX_BYTES + 1)

    store = LocalWorkspaceStore(owned.root)
    state = store.Open()
    record_ids = tuple(sorted({*state.evidence_record_references, old.evidence_id}))
    store.Save(replace(state,
        evidence_references=(*state.evidence_references, old.reference, *aliases),
        evidence_record_references=record_ids))
    selected = imported["evidence_id"] if source_mode == "retained" else None
    arguments = Arguments(owned, evidence_id=selected)
    calls = []

    def Forbidden(*_args, **_kwargs):
        """Trip every generic or raw-owning reader for an older invalid original source."""

        calls.append("raw")

        raise AssertionError("Older invalid SBOM reached generic original bytes")

    monkeypatch.setattr(commands, "OpenReportInput", Forbidden)
    monkeypatch.setattr(LocalEvidenceStore, "Read", Forbidden)
    status, outcome = Run(arguments)
    assert status == 4 and outcome["failure"] in {"selected-source", "selected-source-alias"} and (
        not calls
    ), "Both modes must refuse every older SBOM original and incompatible alias before raw reading"


@pytest.mark.parametrize("source_mode", ["file", "retained"])
def test_OlderOriginalKeepsItsOwnScopeMediaAndSourceContext(tmp_path, source_mode):
    """New selected context does not rebind a valid older independently owned SBOM acquisition."""

    owned, imported = Imported(tmp_path)
    LocalScopeStore(owned.root).Create(ScopeSnapshot("other", "owned-sbom"))
    evidence = LocalEvidenceStore(owned.root / "evidence")
    old = evidence.Put(b"old original owned SPDX bytes", "sbom", "application/vnd.spdx+json",
        EvidenceProvenance("owned-sbom", "scope:other", "old.sbom", "older-version", "older-tool",
                           "2026-10-14T00:00:00Z", "2026-10-14T00:00:01Z"))
    original_manifest = old.Serialize()
    store = LocalWorkspaceStore(owned.root)
    state = store.Open()
    record_ids = tuple(sorted({*state.evidence_record_references, old.evidence_id}))
    store.Save(replace(state, evidence_references=(*state.evidence_references, old.reference),
        evidence_record_references=record_ids))
    selected = imported["evidence_id"] if source_mode == "retained" else None
    status, _ = Run(Arguments(owned, evidence_id=selected))
    assert status == 0 and evidence.Get(old.evidence_id).Serialize() == original_manifest and (
        old.evidence_id in store.Open().evidence_record_references
    ), "Older own-scope source/media/version metadata remains original under both current modes"


def test_ModelOnlyKnownCustodyManifestIsCheckedBeforeAnyGenericRawReader(tmp_path, monkeypatch):
    """A model-confirmed/workspace-unrecorded original remains independently manifest-bound."""

    owned, imported = Imported(tmp_path)
    store = LocalWorkspaceStore(owned.root)
    state = store.Open()
    store.Save(replace(state, evidence_references=(), evidence_record_references=()))
    manifest = owned.root / "evidence/records" / (imported["evidence_id"][7:] + ".json")
    manifest.write_bytes(b"{}")
    arguments = Arguments(owned)
    calls = []

    def Forbidden(*_args, **_kwargs):
        """Trip generic raw reading while a known model-only original manifest is unverified."""

        calls.append("raw")

        raise AssertionError("Model-only original manifest corruption reached raw bytes")

    monkeypatch.setattr(commands, "OpenReportInput", Forbidden)
    monkeypatch.setattr(LocalEvidenceStore, "Read", Forbidden)
    status, outcome = Run(arguments)
    assert status == 4 and not calls and outcome["acquisition_commit"] == "not-attempted", (
        "Known product custody IDs are verified even without a confirmed workspace reference save"
    )


def test_UnrelatedLargerRetainedBlobKeepsItsExistingOwningBudget(tmp_path):
    """The selected four-MiB profile cap does not become a limit on unrelated older evidence."""

    owned = Context(tmp_path)
    evidence = LocalEvidenceStore(owned.root / "evidence")
    unrelated = evidence.Put(b"x" * (IMAGE_IMPORT_MAX_BYTES + 1), "owned-old", "text/plain",
        EvidenceProvenance("owned-sbom", "scope:owned", "old.source", "1", None,
                           "2026-10-14T00:00:00Z", "2026-10-14T00:00:01Z"))
    store = LocalWorkspaceStore(owned.root)
    store.Save(replace(store.Open(), evidence_references=(unrelated.reference,),
                       evidence_record_references=(unrelated.evidence_id,)))
    status, _ = Run(Arguments(owned))
    retained = store.Open()
    assert status == 0 and unrelated.reference in retained.evidence_references and (
        unrelated.evidence_id in retained.evidence_record_references
    ), "Unrelated larger original evidence remains valid under its unchanged generic owner budget"


@pytest.mark.parametrize("owner", ["acquisition", "model", "workspace"])
@pytest.mark.parametrize("after", [False, True], ids=["before-save", "lost-ack"])
@pytest.mark.parametrize("interrupted", [False, True], ids=["storage-error", "interrupt"])
def test_EachActualOwnerPreservesIndependentUnknownAcknowledgement(
    tmp_path, monkeypatch, owner, after, interrupted
):
    """Before/after actual persistence failures cannot invent commit confirmation or rollback."""

    owned = Context(tmp_path)
    arguments = Arguments(owned)
    selected = {"acquisition": (commands.SbomEvidenceStore, "Put"),
                "model": (LocalModelStore, "Save"), "workspace": (LocalWorkspaceStore, "Save")}
    store_type, method = selected[owner]
    original = getattr(store_type, method)

    def Save(self, *args, **kwargs):
        """Fail before the owning call or lose acknowledgement after its real durable operation."""

        if after:
            original(self, *args, **kwargs)

        if interrupted:
            raise KeyboardInterrupt()

        raise OSError("Owned storage acknowledgement failure")

    monkeypatch.setattr(store_type, method, Save)
    status, outcome = Run(arguments)
    assert status == (130 if interrupted else 4) and outcome[owner + "_commit"] == "unknown", (
        "An unreturned owning acknowledgement must remain unknown even if actual bytes committed"
    )
    expected_model = int(owner == "workspace" or owner == "model" and after)
    expected_workspace = int(owner == "workspace" and after)
    assert LocalModelStore(owned.root).Open().revision == expected_model and (
        LocalWorkspaceStore(owned.root).Open().revision == expected_workspace
    ), "Independent read-back retains actual durable owners without fabricating rollback"
    assert outcome["model_commit"] == ("confirmed" if owner == "workspace" else (
        "unknown" if owner == "model" else "not-attempted")), (
        "A later failure cannot erase prior confirmation or imply an unattempted owner committed"
    )


@pytest.mark.parametrize("owner", ["model", "workspace"])
@pytest.mark.parametrize("error", [WorkspaceBusyError, WorkspaceConflictError])
def test_ExplicitOwningCasRefusalRemainsNotCommitted(tmp_path, monkeypatch, owner, error):
    """Known cooperating-writer refusal is distinct from a lost persistence acknowledgement."""

    owned = Context(tmp_path)
    selected = LocalModelStore if owner == "model" else LocalWorkspaceStore

    def Refuse(*_args, **_kwargs):
        """Return the actual owning refusal category before any write is attempted."""

        raise error("Owned explicit CAS refusal")

    monkeypatch.setattr(selected, "Save", Refuse)
    status, outcome = Run(Arguments(owned))
    assert status == 4 and outcome[owner + "_commit"] == "not-committed", (
        "Explicit owning busy/conflict refusal cannot be confused with unknown acknowledgement"
    )
