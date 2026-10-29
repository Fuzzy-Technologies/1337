# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Offline runtime refusals, exact source context and independent storage acknowledgements."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from fuzzy1337 import artifact_inputs
from fuzzy1337 import runtime_commands as commands
from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.model import (
    LocalModelStore,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    Observation,
    SecurityObject,
)
from fuzzy1337.scope import LocalScopeStore
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.docker_helpers import Acquire
from tests.runtime_helpers import Arguments, Context, KubernetesContext, Run

TIME = datetime(2026, 10, 14, 10, 0, tzinfo=timezone.utc)


def Value(arguments, name, value):
    """Replace one explicitly selected parser value without changing independent arguments."""

    modified = list(arguments)
    modified[modified.index(name) + 1] = str(value)

    return modified


def Imported(tmp_path):
    """Acquire and commit through the actual product handler using a deterministic owned clock."""

    context = Context(tmp_path)
    status, outcome = Run(Arguments(context), clock=lambda: TIME)
    assert status == 0, "Original product setup did not acquire/save owned input"

    return context, outcome


@pytest.mark.parametrize("arguments", [[], ["remote", "SYNTHETIC_PRIVATE_MARKER"],
    ["import", "daemon", "SYNTHETIC_PRIVATE_MARKER"], ["import", "docker-inspect"],
    ["import", "docker-inspect", "SYNTHETIC_PRIVATE_MARKER", "--execute"],
])
def test_GrammarHasOnlyOfflineProfileAndNeverEchoesRejectedValues(arguments):
    """Invalid namespaces, missing selections and execution options yield one safe summary."""

    status, outcome = Run(arguments)
    assert status == 2 and outcome["failure"] == "configuration", "Invalid grammar was accepted"
    assert "SYNTHETIC_PRIVATE_MARKER" not in json.dumps(outcome), "Argument value escaped output"
    assert all(outcome[name] == "not-attempted" for name in (
        "acquisition_commit", "model_commit", "workspace_commit",
    )), "Invalid grammar attempted a storage owner operation"


def test_StaticHelpAndHumanOutcomeUseOnlyCallerOwnedPresentation(tmp_path):
    """Help needs no workspace and human output contains only safe acknowledgements."""

    status, help_text = Run(["--help"], json_output=False)
    assert status == 0 and "import" in help_text, "Static runtime namespace help failed"
    context = Context(tmp_path)
    status, output = Run(Arguments(context), json_output=False, clock=lambda: TIME)
    assert status == 0 and "model_commit: confirmed" in output, "Human output omitted actual commit"
    assert str(context[4]) not in output and "SYNTHETIC_PRIVATE_MARKER" not in output, (
        "Human presentation exposed selected file or original raw source"
    )


@pytest.mark.parametrize("flag", ["--owner", "--read-consent-reference"])
def test_FileModeRequiresExplicitActorAndReadConsentBeforeSourceAccess(tmp_path, flag):
    """No owner or read authority is inferred from the workspace, HOST or run reference."""

    context = Context(tmp_path)
    arguments = Arguments(context)
    index = arguments.index(flag)
    del arguments[index:index + 2]
    before = LocalModelStore(context[0]).Open()
    status, outcome = Run(arguments)
    assert status == 2 and outcome["acquisition_commit"] == "not-attempted", (
        "Missing explicit current file read consent was inferred"
    )
    assert LocalModelStore(context[0]).Open() == before, "Denied read changed model state"


@pytest.mark.parametrize("flag,value", [
    ("--expected-revision", -1), ("--expected-workspace-revision", -1),
    ("--run", "SYNTHETIC_PRIVATE_MARKER\n"), ("--scope", "../private"),
    ("--host", "host:SYNTHETIC_PRIVATE_MARKER"),
])
def test_InvalidExplicitBasesAndContextFailBeforeAcquisition(tmp_path, flag, value):
    """Unbounded/malformed context never reaches source read or a storage save."""

    context = Context(tmp_path)
    status, outcome = Run(Value(Arguments(context), flag, value))
    assert status == 2 and outcome["acquisition_commit"] == "not-attempted", "Invalid context read"
    assert "SYNTHETIC_PRIVATE_MARKER" not in json.dumps(outcome), "Invalid context leaked"


@pytest.mark.parametrize("flag", ["--expected-revision", "--expected-workspace-revision"])
def test_StaleExplicitRevisionRefusesBeforeOriginalFileAcquisition(tmp_path, flag):
    """A caller's stale model or workspace pin cannot be silently replaced with current state."""

    context = Context(tmp_path)
    status, outcome = Run(Value(Arguments(context), flag, 99))
    expected = "revision-conflict" if flag == "--expected-revision" else "workspace-conflict"
    assert status == 4 and outcome["failure"] == expected, "Stale owner basis was ignored"
    assert outcome["acquisition_commit"] == "not-attempted", "Stale selection read original file"


@pytest.mark.parametrize("mode", ["missing", "directory", "empty", "oversized", "malformed"])
def test_OriginalFileRefusalsAndInvalidJsonRetainHonestAcquisitionState(tmp_path, mode):
    """File/profile refusal differs from successfully acquired original invalid JSON."""

    context = Context(tmp_path)
    source = context[4]

    if mode == "missing":
        source.unlink()

    elif mode == "directory":
        source.unlink()
        source.mkdir()

    elif mode in {"empty", "oversized"}:
        source.write_bytes(b"" if mode == "empty" else b"x" * (1024 * 1024 + 1))

    else:
        source.write_bytes(b'{"original-private":"SYNTHETIC_PRIVATE_MARKER"}')

    status, outcome = Run(Arguments(context), clock=lambda: TIME)
    assert status == 4 and outcome["model_commit"] == "not-attempted", "Bad source applied a model"
    expected = "confirmed" if mode == "malformed" else "not-attempted"
    assert outcome["acquisition_commit"] == expected, "Failed original source custody was guessed"
    assert LocalModelStore(context[0]).Open() == context[1], "Invalid source mutated saved model"
    assert LocalWorkspaceStore(context[0]).Open().revision == 0, "Invalid source saved workspace"
    assert "SYNTHETIC_PRIVATE_MARKER" not in json.dumps(outcome), "Invalid source escaped output"


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_SelectedPhysicalLinksAreRefusedWithoutFollowingTheirSource(tmp_path, kind):
    """Explicit input selection does not authorize symlink traversal or shared hard-link bytes."""

    context = Context(tmp_path)
    selected = tmp_path / "linked.json"

    try:
        if kind == "symlink":
            selected.symlink_to(context[4])

        else:
            os.link(context[4], selected)

    except (OSError, NotImplementedError):
        pytest.skip("Physical link creation is unavailable on this test host")

    status, outcome = Run(Value(Arguments(context), "--file", selected))
    assert status in {2, 4} and outcome["acquisition_commit"] == "not-attempted", (
        "Selected link was followed or acquired before its physical refusal"
    )


def test_ActualObservationTimesSurroundReadAndDetectSourceChanges(tmp_path):
    """A selected file change after reading fails before retaining changed source."""

    context = Context(tmp_path)
    calls = 0

    def Clock():
        """Change the owned source only at the second observation after its read completes."""

        nonlocal calls
        calls += 1

        if calls == 2:
            context[4].write_bytes(b"owned replacement")

        return TIME

    status, outcome = Run(Arguments(context), clock=Clock)
    assert calls == 2 and status == 4 and outcome["failure"] == "source-changed", (
        "Observed source replacement was silently normalized as original bytes"
    )
    assert outcome["acquisition_commit"] == "not-attempted", "Changed source was retained"


def test_ObservedReplacementBeforeOpeningRefusesBeforeOriginalByteRead(tmp_path, monkeypatch):
    """A cooperating-writer replacement after selected metadata cannot substitute opened bytes."""

    context = Context(tmp_path)
    source = context[4]
    original = Path.open

    def Open(self, *args, **kwargs):
        """Replace only the explicitly selected owned test file immediately before opening it."""

        if self == source:
            replacement = source.with_name("replacement.json")
            replacement.write_bytes(b"owned changed bytes")
            replacement.replace(source)

        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", Open)
    status, outcome = Run(Arguments(context), clock=lambda: TIME)
    assert status == 4 and outcome["failure"] == "source-changed", "Opened replacement was admitted"
    assert outcome["acquisition_commit"] == "not-attempted", "Replaced physical source was retained"


def Metadata(info, **changes):
    """Describe exact unchanged inode/size/restored-mtime with one independent metadata drift."""

    fields = {name: getattr(info, name) for name in (
        "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink",
    )}

    return SimpleNamespace(**{**fields, **changes})


@pytest.mark.parametrize("view", ["path", "handle"])
@pytest.mark.parametrize("windows_views", [False, True])
def test_SameViewChangedCtimeRefusesRestoredMtimeBeforeEvidencePublication(
    tmp_path, monkeypatch, view, windows_views,
):
    """Same inode, byte count and restored mtime cannot conceal changed same-view ctime."""

    context = Context(tmp_path)
    source = context[4].absolute()
    path_info = commands.CheckStorageEntry
    handle_info = commands.os.fstat
    calls = 0

    def PathInfo(path, *, directory):
        """Change only the final original path's ctime after its complete read."""

        nonlocal calls
        info = path_info(path, directory=directory)

        if path == source and view == "path":
            calls += 1

            if calls == 2:
                return Metadata(info, st_ctime_ns=info.st_ctime_ns + 1)

        return info

    def HandleInfo(descriptor):
        """Change only the final owned handle's ctime while preserving other identity fields."""

        nonlocal calls
        info = handle_info(descriptor)

        if view == "handle":
            calls += 1

            if calls == 2:
                return Metadata(info, st_ctime_ns=info.st_ctime_ns + 1)

        return info

    monkeypatch.setattr(artifact_inputs, "_WINDOWS_STAT_VIEWS", windows_views)
    monkeypatch.setattr(commands, "CheckStorageEntry", PathInfo)
    monkeypatch.setattr(commands.os, "fstat", HandleInfo)
    status, outcome = Run(Arguments(context), clock=lambda: TIME)
    assert status == 4 and outcome["failure"] == "source-changed", "Same-view ctime drift passed"
    assert outcome["acquisition_commit"] == "not-attempted" and (
        not tuple((context[0] / "evidence" / "records").glob("*.json"))
    ), "Changed original source was published before its identity refusal"


def test_WindowsCrossViewCtimeDifferenceAllowsStableSameViewOriginalBytes(tmp_path, monkeypatch):
    """Windows API ctime differences are allowed only across stable path and handle views."""

    context = Context(tmp_path)
    original = context[4].read_bytes()
    handle_info = commands.os.fstat

    def HandleInfo(descriptor):
        """Keep the handle's full identity stable and distinct from path-view ctime."""

        info = handle_info(descriptor)

        return Metadata(info, st_ctime_ns=info.st_ctime_ns + 1)

    monkeypatch.setattr(artifact_inputs, "_WINDOWS_STAT_VIEWS", True)
    monkeypatch.setattr(commands.os, "fstat", HandleInfo)
    status, outcome = Run(Arguments(context), clock=lambda: TIME)
    assert status == 0, "Stable Windows path/handle API differences were rejected"
    record = context[3].Get(outcome["evidence_id"])
    assert context[3].Read(record.reference) == original and (
        record.reference.sha256 == hashlib.sha256(original).hexdigest()
    ), "Allowed cross-view acquisition lost the original complete content hash"


@pytest.mark.parametrize("view", ["opened", "finished", "after"])
def test_EveryOriginalReadViewRequiresOnePhysicalLink(tmp_path, monkeypatch, view):
    """A second observed physical link refuses original acquisition in each later view."""

    context = Context(tmp_path)
    path_info = commands.CheckStorageEntry
    handle_info = commands.os.fstat
    handle_calls = 0
    path_calls = 0

    def PathInfo(path, *, directory):
        """Expose an independent shared-link observation only for the final selected path."""

        nonlocal path_calls
        info = path_info(path, directory=directory)

        if path == context[4].absolute():
            path_calls += 1

            if view == "after" and path_calls == 2:
                return Metadata(info, st_nlink=2)

        return info

    def HandleInfo(descriptor):
        """Expose one later owned-handle link count without modifying source bytes."""

        nonlocal handle_calls
        info = handle_info(descriptor)
        handle_calls += 1

        if (view == "opened" and handle_calls == 1) or (
            view == "finished" and handle_calls == 2
        ):
            return Metadata(info, st_nlink=2)

        return info

    monkeypatch.setattr(commands, "CheckStorageEntry", PathInfo)
    monkeypatch.setattr(commands.os, "fstat", HandleInfo)
    status, outcome = Run(Arguments(context), clock=lambda: TIME)
    assert status == 4 and outcome["failure"] == "source-changed", "Shared source view passed"
    assert outcome["acquisition_commit"] == "not-attempted", "Shared physical source was retained"


@pytest.mark.parametrize("field,value", [
    ("source_id", "inventory.other"), ("source_version", "foreign"),
    ("workspace_id", "foreign-workspace"), ("scope_reference", "scope:other"),
    ("invocation_sha256", "a" * 64),
])
def test_RetainedSourceProfileCannotSubstituteOriginalAttribution(tmp_path, field, value):
    """Retained bytes cannot forge original offline source, workspace, scope or execution."""

    context = Context(tmp_path)
    root, _, _, evidence, source = context
    provenance = EvidenceProvenance("runtime-test", "scope:owned", "inventory.docker-inspect",
        "owned-docker-container-inspect-v1", None, TIME.isoformat(), TIME.isoformat())
    record = evidence.Put(source.read_bytes(), "docker-inspect", "application/json",
                          replace(provenance, **{field: value}))
    status, outcome = Run(Arguments(context, evidence_id=record.evidence_id))
    assert status == 4 and outcome["model_commit"] == "not-attempted", "Forged source was applied"
    assert LocalModelStore(root).Open() == context[1], "Retained source refusal saved partial state"


@pytest.mark.parametrize("flag,value", [
    ("--owner", "owner:other"), ("--read-consent-reference", "consent:other"),
    ("--provider-version", "invented"),
])
def test_RetainedReplayCannotOverrideOriginalReadOrVersionDescriptions(tmp_path, flag, value):
    """No new file read consent or declared version can be silently mixed with original custody."""

    context, original = Imported(tmp_path)
    arguments = Arguments(context, evidence_id=original["evidence_id"]) + [flag, value]
    status, outcome = Run(arguments)
    assert status == 2 and outcome["acquisition_commit"] == "not-attempted", (
        "Retained replay override was allowed"
    )


@pytest.mark.parametrize("field", ["run", "host"])
def test_OriginalRetainedManifestRejectsChangedHostOrRunContext(tmp_path, field):
    """Exact source identity retains its original model attribution on replay."""

    context, original = Imported(tmp_path)
    root = context[0]
    replacement = "run:other"

    if field == "host":
        model = LocalModelStore(root)
        state = model.Open()
        host = SecurityObject(ObjectIdentity(state.workspace_id, ObjectKind.HOST, "192.0.2.2"),
            {}, (ModelProvenance("owned.host", "run:host", TIME.isoformat(),
                                "scope:owned", "host:owned"),))
        proposal, _ = state.Apply(objects=(host,))
        model.Save(proposal, expected_revision=state.revision)
        replacement = host.Reference()

    arguments = Value(Arguments(context, evidence_id=original["evidence_id"]),
                      "--" + field, replacement)
    before = LocalModelStore(root).Open()
    status, outcome = Run(arguments)
    assert status == 4 and outcome["failure"] == "source-context", "Original source was rebound"
    assert LocalModelStore(root).Open() == before, "Rejected source context mutated model"


def test_NewReadWithSameManifestCannotReplaceItsOriginalConsentDescription(tmp_path):
    """The same content/acquisition identity retains its original explicit read references."""

    context, original = Imported(tmp_path)
    arguments = Value(Arguments(context), "--owner", "owner:other")
    status, outcome = Run(arguments, clock=lambda: TIME)
    assert status == 4 and outcome["failure"] == "source-context", "Original consent was rebound"
    assert outcome["evidence_id"] == original["evidence_id"], "Test did not reuse original identity"


@pytest.mark.parametrize("field,value", [
    ("profile", "daemon"), ("source_sha256", "b" * 64), ("source_version", "other"),
    ("read_actor_reference", None), ("read_consent_reference", "invalid\nreference"),
])
def test_OriginalCustodyFactMustRetainValidatedManifestAndReadFields(tmp_path, field, value):
    """A typed saved model cannot substitute unsupported original custody fields."""

    context, original = Imported(tmp_path)
    model = LocalModelStore(context[0])
    state = model.Open()
    observations = tuple(replace(item, attributes={**item.attributes, field: value})
                         if item.kind == "runtime-import-source" else item
                         for item in state.observations)
    replaced = replace(state, revision=state.revision + 1, observations=observations)
    model.Save(replaced, expected_revision=state.revision)
    status, outcome = Run(Arguments(context, evidence_id=original["evidence_id"]))
    assert status == 4 and outcome["failure"] == "source-context", "Custody substitution passed"
    assert model.Open() == replaced, "Rejected custody fact changed the existing model basis"


def test_DeclaredProviderVersionIsOriginalCallerAttributionRatherThanDetection(tmp_path):
    """Explicit metadata is retained exactly while default tool version remains absent elsewhere."""

    context = Context(tmp_path)
    status, outcome = Run(Arguments(context) + ["--provider-version", "owned-declared-version"],
                          clock=lambda: TIME)
    assert status == 0, "Explicit bounded provider attribution failed"
    record = context[3].Get(outcome["evidence_id"])
    assert record.provenance.tool_version == "owned-declared-version", "Declared version changed"


@pytest.mark.parametrize("changed", [False, True])
def test_ExistingSdkSourceUsesOriginalContextForItsFirstProductCustodyFact(tmp_path, changed):
    """Original SDK-only evidence gains one product fact without inventing host/run attribution."""

    context = Context(tmp_path)
    root, basis, host, _, _ = context
    record, provenance = Acquire(context[:4])
    proposed, _ = commands.ApplyVerifiedDockerInspect(basis, record, provenance,
        host_reference=host.Reference(), workspace_root=root)
    saved = LocalModelStore(root).Save(proposed, expected_revision=basis.revision)
    arguments = Arguments(context, evidence_id=record.evidence_id)

    if changed:
        arguments = Value(arguments, "--run", "run:other")

    status, outcome = Run(arguments)

    if changed:
        assert status == 4 and outcome["failure"] == "source-context", "SDK context was changed"
        assert LocalModelStore(root).Open() == saved, "Rejected SDK context changed model"

    else:
        assert status == 0 and outcome["model_revision"] == saved.revision + 1, (
            "Existing SDK source did not add exactly one original product custody fact"
        )


@pytest.mark.parametrize("kind", ["untyped", "subclass", "mutated"])
def test_FileReadRevalidatesExactConsentBeforePhysicalAccess(tmp_path, monkeypatch, kind):
    """Typed/frozen read declarations cannot be substituted or relaxed before physical reads."""

    context = Context(tmp_path)
    consent = ArtifactReadConsent("owner:owned", "consent:owned")

    if kind == "untyped":
        consent = object()

    elif kind == "subclass":
        derived = type("Derived", (ArtifactReadConsent,), {"__doc__": "Rejected read declaration."})
        consent = derived("owner:owned", "consent:owned")

    else:
        object.__setattr__(consent, "record_ref", None)

    def NoRead(*args, **kwargs):
        """Fail if invalid read declaration reaches physical path or source opening."""

        pytest.fail("Invalid typed read consent reached physical access")

    monkeypatch.setattr(commands, "RuntimePath", NoRead)

    with pytest.raises((commands.RuntimeFailure, ValueError)):
        commands.ReadOwnedInspect(context[4], consent, lambda: TIME)


@pytest.mark.parametrize("owner", ["model", "workspace"])
def test_ActualBusyOwnerNeverLosesItsWriterLock(tmp_path, owner):
    """A live writer lock refuses its save while preserving another owner's acknowledgement."""

    context = Context(tmp_path)
    root = context[0]
    lock = root / "state/model/.write-lock" if owner == "model" else root / ".write-lock"
    lock.mkdir()

    try:
        status, outcome = Run(Arguments(context), clock=lambda: TIME)
        assert status == 4 and outcome["failure"] == owner + "-busy", "Busy owner was ignored"
        assert lock.is_dir() and outcome[owner + "_commit"] == "not-committed", (
            "Busy writer lock was removed or its failed save was claimed committed"
        )
        assert outcome["model_commit"] == ("not-committed" if owner == "model" else "confirmed"), (
            "Independent model acknowledgement was conflated with workspace save refusal"
        )

    finally:
        lock.rmdir()


@pytest.mark.parametrize("owner", ["model", "workspace"])
@pytest.mark.parametrize("committed", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
@pytest.mark.parametrize("profile", ["docker-inspect", "kubernetes-list"])
def test_SaveAcknowledgementLossPreservesActualIndependentOwnerState(
    tmp_path, monkeypatch, capsys, owner, committed, error, profile,
):
    """Before/after real replacement failure stays unknown without rollback or invented success."""

    from fuzzy1337.cli import Main

    context = Context(tmp_path) if profile == "docker-inspect" else KubernetesContext(tmp_path)
    root = context[0]
    store_type = LocalModelStore if owner == "model" else LocalWorkspaceStore
    original = store_type.Save

    def Save(self, proposal, **options):
        """Optionally commit through the actual owner, then lose only its acknowledgement."""

        if committed:
            original(self, proposal, **options)

        raise error("SYNTHETIC_PRIVATE_MARKER")

    monkeypatch.setattr(store_type, "Save", Save)
    status = Main(["runtime", *Arguments(context, profile=profile), "--json"])
    outcome = json.loads(capsys.readouterr().out)
    assert status == (130 if error is KeyboardInterrupt else 4), "Lost acknowledgement hid failure"
    assert outcome[owner + "_commit"] == "unknown", "Lost acknowledgement guessed storage state"
    expected_model = context[1].revision + int(committed if owner == "model" else True)
    assert LocalModelStore(root).Open().revision == expected_model, "Failed save rolled back state"
    assert LocalWorkspaceStore(root).Open().revision == int(committed and owner == "workspace"), (
        "Independent workspace state was hidden or rolled back"
    )
    assert "SYNTHETIC_PRIVATE_MARKER" not in json.dumps(outcome), "Save error text leaked"


@pytest.mark.parametrize("committed", [False, True])
def test_AcquisitionAcknowledgementLossDoesNotGuessManifestPublication(
    tmp_path, monkeypatch, committed,
):
    """Original acquisition may have published even when its Put acknowledgement was lost."""

    context = Context(tmp_path)
    original = LocalEvidenceStore.Put

    def Put(self, *args, **kwargs):
        """Optionally publish the actual original manifest before losing its acknowledgement."""

        if committed:
            original(self, *args, **kwargs)

        raise OSError("SYNTHETIC_PRIVATE_MARKER")

    monkeypatch.setattr(LocalEvidenceStore, "Put", Put)
    status, outcome = Run(Arguments(context), clock=lambda: TIME)
    assert status == 4 and outcome["acquisition_commit"] == "unknown", "Acquisition state guessed"
    assert outcome["model_commit"] == "not-attempted", "Unacknowledged acquisition applied a model"
    path = context[0] / "evidence/records" / (outcome["evidence_id"][7:] + ".json")
    assert path.is_file() is committed, "Actual publication state disagreed with injected failure"


def test_ObservedWorkspaceAndScopeRacesPreserveAlreadyConfirmedModel(tmp_path, monkeypatch):
    """Changes between independent owner saves produce partial failure without rollback."""

    context = Context(tmp_path)
    original = LocalModelStore.Save

    def Save(self, proposal, **options):
        """Commit the actual model, then advance the other actual owner before retention."""

        saved = original(self, proposal, **options)
        workspace = LocalWorkspaceStore(self.root)
        workspace.Save(workspace.Open())

        return saved

    monkeypatch.setattr(LocalModelStore, "Save", Save)
    status, outcome = Run(Arguments(context), clock=lambda: TIME)
    assert status == 4 and outcome["failure"] == "workspace-conflict", "Observed owner race ignored"
    assert outcome["model_commit"] == "confirmed" and (
        outcome["workspace_commit"] == "not-attempted"
    ), (
        "A confirmed model was conflated with unattempted workspace retention"
    )
    assert LocalModelStore(context[0]).Open().revision == context[1].revision + 1, (
        "Observed race rolled back the canonical model commit"
    )


def test_ObservedScopeChangeBeforeModelSaveRefusesWithoutHistoricalGrant(tmp_path, monkeypatch):
    """A scope attribution race is detected without consulting or issuing execution approval."""

    context = Context(tmp_path)
    original = commands.ApplyVerifiedDockerInspect

    def Apply(*args, **kwargs):
        """Interpret original source, then advance its actual scope attribution owner."""

        proposed = original(*args, **kwargs)
        scope = LocalScopeStore(context[0])
        scope.Save(scope.Open("owned"))

        return proposed

    monkeypatch.setattr(commands, "ApplyVerifiedDockerInspect", Apply)
    status, outcome = Run(Arguments(context), clock=lambda: TIME)
    assert status == 4 and outcome["failure"] == "scope-conflict", "Scope race was ignored"
    assert outcome["model_commit"] == "not-attempted", "Raced attribution was saved as current"
    assert LocalModelStore(context[0]).Open() == context[1], "Scope race changed model"


@pytest.mark.parametrize("owner", ["model", "workspace"])
def test_ActualCompetingOwnerCommitWinsWithoutLostUpdates(tmp_path, monkeypatch, owner):
    """A competing actual CAS commit between verification and save refuses the stale proposal."""

    context = Context(tmp_path)
    store_type = LocalModelStore if owner == "model" else LocalWorkspaceStore
    original = store_type.Save
    competing = None

    def Save(self, proposal, **options):
        """Publish one independent actual owner update before attempting the original stale save."""

        nonlocal competing
        current = self.Open()

        if owner == "model":
            decision = ModelProvenance("owned.writer", "run:writer", TIME.isoformat(),
                                       "scope:owned", context[2].Reference())
            changed, _ = current.Apply(observations=(Observation(
                "owned-competing-writer", context[2].Reference(), {"owned": True}, decision,
            ),))
            competing = original(self, changed, expected_revision=current.revision)

        else:
            competing = original(self, current)

        return original(self, proposal, **options)

    monkeypatch.setattr(store_type, "Save", Save)
    status, outcome = Run(Arguments(context), clock=lambda: TIME)
    assert status == 4 and outcome["failure"] == owner + "-conflict", "Competing CAS was lost"
    assert outcome[owner + "_commit"] == "not-committed", "Stale product save claimed commitment"
    assert store_type(context[0]).Open() == competing, "Competing actual owner's state was lost"


@pytest.mark.parametrize("role,media_type,size", [
    ("stdout", "application/json", 1), ("docker-inspect", "text/plain", 1),
    ("docker-inspect", "application/json", 1024 * 1024 + 1),
])
def test_ActualRetainedRoleMediaAndByteBoundsRefuseBeforeBlobRead(
    tmp_path, monkeypatch, role, media_type, size,
):
    """Actual manifest role/media/size bounds apply before Get's owning raw read."""

    context = Context(tmp_path)
    record = context[3].Put(b"x" * size, role, media_type, EvidenceProvenance(
        "runtime-test", "scope:owned", "inventory.docker-inspect",
        "owned-docker-container-inspect-v1", None, TIME.isoformat(), TIME.isoformat(),
    ))

    def NoBlob(*args, **kwargs):
        """Fail if refused actual role/media/size reaches the ordinary owning blob reader."""

        pytest.fail("Refused original manifest reached raw blob reading")

    monkeypatch.setattr(LocalEvidenceStore, "Read", NoBlob)
    status, outcome = Run(Arguments(context, evidence_id=record.evidence_id))
    assert status == 4 and outcome["failure"] == "integrity", "Actual retained bounds were ignored"
    assert outcome["model_commit"] == "not-attempted", "Refused manifest reached application"


def test_SourceFactAndReferenceTransformsPerformNoStorageOrExecution(tmp_path, monkeypatch):
    """Prepared original source context remains a pure one-revision model transformation."""

    context = Context(tmp_path)
    root, basis, host, evidence, source = context
    record = evidence.Put(source.read_bytes(), "docker-inspect", "application/json",
        EvidenceProvenance("runtime-test", "scope:owned", "inventory.docker-inspect",
            "owned-docker-container-inspect-v1", None, TIME.isoformat(), TIME.isoformat()))
    provenance = ModelProvenance("inventory.docker-inspect", "run:owned-inspect", TIME.isoformat(),
        "scope:owned", host.Reference(), evidence_references=(record.reference,))
    proposal, delta = commands.ApplyVerifiedDockerInspect(basis, record, provenance,
        host_reference=host.Reference(), workspace_root=root)
    workspace = LocalWorkspaceStore(root).Open()
    scope = LocalScopeStore(root).Open("owned")

    def Refuse(*args, **kwargs):
        """Fail any storage read/write introduced into the pure transformation phase."""

        pytest.fail("Pure source/reference transformation attempted storage access")

    with monkeypatch.context() as guard:
        guard.setattr("builtins.open", Refuse)
        guard.setattr(Path, "open", Refuse)
        guard.setattr(LocalEvidenceStore, "Get", Refuse)
        fact = commands.SourceFact(basis, record, provenance, None)
        updated, combined = commands.ApplySourceFact(proposal, delta, fact)
        retained = commands.ReferenceProposal(workspace, updated, record, scope)

    assert updated.revision == basis.revision + 1 and combined.revision == updated.revision, (
        "Source fact created an implicit second canonical revision"
    )
    assert record.evidence_id in retained.evidence_record_references, "Pure proposal lost source ID"


@pytest.mark.parametrize("path", ["../source", "source/../input", "source\x1b", "x" * 4097])
def test_LexicalPathRefusalDoesNotTraverseRejectedSource(path):
    """Parent traversal, controls and resource excess fail before any physical lookup."""

    with pytest.raises(commands.RuntimeFailure, match="configuration"):
        commands.RuntimePath(Path(path))


@pytest.mark.parametrize("field,value", [
    ("asset_type", "other"), ("cluster_id", "different"), ("cluster_id", "invalid\ncluster"),
])
def test_KubernetesDeclaredAnchorRefusesBeforeAnyOriginalOrRetainedBlobRead(
    tmp_path, monkeypatch, field, value,
):
    """A selected existing ASSET cannot substitute its literal declared cluster context."""

    context = KubernetesContext(tmp_path)
    root, basis, cluster, evidence, source = context
    record = evidence.Put(source.read_bytes(), "kubernetes-list", "application/json",
        EvidenceProvenance("runtime-test", "scope:owned", "inventory.kubernetes-list",
            "owned-kubernetes-list-v1", None, TIME.isoformat(), TIME.isoformat()))
    workspace = LocalWorkspaceStore(root)
    workspace.Save(replace(workspace.Open(), evidence_references=(record.reference,),
                           evidence_record_references=(record.evidence_id,)))
    changed = replace(cluster, attributes={**cluster.attributes, field: value})
    proposal, _ = basis.Apply(objects=(changed,))
    LocalModelStore(root).Save(proposal, expected_revision=basis.revision)

    def NoRead(*args, **kwargs):
        """Reject all raw evidence or current source reads during invalid anchor selection."""

        pytest.fail("Invalid declared cluster reached original byte reading")

    monkeypatch.setattr(LocalEvidenceStore, "Read", NoRead)
    monkeypatch.setattr(commands, "ReadOwnedInspect", NoRead)

    for evidence_id in (None, record.evidence_id):
        status, outcome = Run(Arguments(context, profile="kubernetes-list",
                                       evidence_id=evidence_id))
        assert status == 2 and outcome["failure"] == "cluster", "Invalid cluster was inferred"
        assert outcome["acquisition_commit"] == "not-attempted", "Invalid anchor read original"


@pytest.mark.parametrize("profile,flag", [
    ("docker-inspect", "--cluster"), ("kubernetes-list", "--host"),
])
def test_RuntimeProfileRequiresItsOwnExplicitAnchorGrammar(tmp_path, profile, flag):
    """The other profile's anchor cannot act as a fallback even when it names an existing object."""

    context = Context(tmp_path) if profile == "docker-inspect" else KubernetesContext(tmp_path)
    arguments = Arguments(context, profile=profile)
    arguments[arguments.index("--host" if profile == "docker-inspect" else "--cluster")] = flag
    status, outcome = Run(arguments)
    assert status == 2 and outcome["failure"] == "configuration", "Profile inferred an anchor"
    assert outcome["acquisition_commit"] == "not-attempted", "Wrong anchor grammar read source"


@pytest.mark.parametrize("field,value", [
    ("role", "docker-inspect"), ("media_type", "text/plain"), ("size", 1024 * 1024 + 1),
    ("source_id", "inventory.docker-inspect"), ("source_version", "other"),
    ("workspace_id", "foreign"), ("scope_reference", "scope:foreign"),
    ("invocation_sha256", "a" * 64),
])
def test_KubernetesActualManifestProfileAndContextRefuseBeforeEveryBlobRead(
    tmp_path, monkeypatch, field, value,
):
    """Preflight precedes even existing workspace-retained evidence verification reads."""

    context = KubernetesContext(tmp_path)
    root, basis, _, evidence, source = context
    provenance = EvidenceProvenance("runtime-test", "scope:owned", "inventory.kubernetes-list",
        "owned-kubernetes-list-v1", None, TIME.isoformat(), TIME.isoformat())
    raw = b"x" * value if field == "size" else source.read_bytes()
    role = value if field == "role" else "kubernetes-list"
    media = value if field == "media_type" else "application/json"

    if field not in {"role", "media_type", "size"}:
        provenance = replace(provenance, **{field: value})

    record = evidence.Put(raw, role, media, provenance)
    workspace = LocalWorkspaceStore(root)
    workspace.Save(replace(workspace.Open(), evidence_references=(record.reference,),
                           evidence_record_references=(record.evidence_id,)))

    def NoBlob(*args, **kwargs):
        """Fail any eager raw read of the selected, already retained rejected manifest."""

        pytest.fail("Rejected selected Kubernetes manifest reached original blob reading")

    monkeypatch.setattr(LocalEvidenceStore, "Read", NoBlob)
    status, outcome = Run(Arguments(context, profile="kubernetes-list",
                                    evidence_id=record.evidence_id))
    assert status == 4 and outcome["failure"] == "integrity", "Manifest preflight was omitted"
    assert outcome["model_commit"] == "not-attempted" and LocalModelStore(root).Open() == basis, (
        "Rejected selected manifest changed the owning model"
    )


@pytest.mark.parametrize("mode", ["Secret", "ConfigMap", "Node", "pagination", "duplicate-uid"])
def test_KubernetesUnsupportedOrIncompleteOriginalRetainsHonestAcquisitionRefusal(tmp_path, mode):
    """Explicit unredacted custody succeeds independently of whole-export SDK refusal."""

    context = KubernetesContext(tmp_path)
    payload = json.loads(context[4].read_bytes())

    if mode == "pagination":
        payload["metadata"] = {"continue": "owned-next-page"}

    elif mode == "duplicate-uid":
        payload["items"][1]["metadata"]["uid"] = payload["items"][0]["metadata"]["uid"]

    else:
        payload["items"][0]["kind"] = mode
        payload["items"][0]["data"] = {"owned-inert": "SYNTHETIC_PRIVATE_MARKER"}

    original = json.dumps(payload).encode()
    context[4].write_bytes(original)
    status, outcome = Run(Arguments(context, profile="kubernetes-list"), clock=lambda: TIME)
    assert status == 4 and outcome["failure"] == "normalization", "Unsupported export was applied"
    assert outcome["acquisition_commit"] == "confirmed" and (
        outcome["model_commit"] == outcome["workspace_commit"] == "not-attempted"
    ), "Normalization refusal invented rollback or failed original acquisition"
    record = context[3].Get(outcome["evidence_id"])
    assert context[3].Read(record.reference) == original, "Explicit original bytes were redacted"
    assert LocalModelStore(context[0]).Open() == context[1] and (
        "SYNTHETIC_PRIVATE_MARKER" not in json.dumps(outcome)
    ), "Unsupported export changed the saved graph or leaked raw values"


@pytest.mark.parametrize("value", [0, True, 1024 * 1024 + 1])
def test_RuntimeOriginalReadCeilingCannotBeRelaxedBeforePhysicalAccess(
    tmp_path, monkeypatch, value,
):
    """Shared Internal file-read reuse preserves the original exact typed byte budget."""

    def NoPath(*args, **kwargs):
        """Reject attempts to observe physical source before a malformed ceiling is refused."""

        pytest.fail("Malformed source ceiling reached physical access")

    monkeypatch.setattr(commands, "RuntimePath", NoPath)

    with pytest.raises(commands.RuntimeFailure, match="configuration"):
        commands.ReadOwnedInspect(tmp_path / "absent", ArtifactReadConsent("owner:x", "consent:x"),
                                  lambda: TIME, maximum=value)


def test_RuntimeClosedProfilesRefuseUnknownAndTypedSubstitutions():
    """Closed profile selection cannot relax source roles or invent extension dispatch."""

    derived = type("Derived", (str,), {"__doc__": "Rejected profile text subclass."})

    for value in ("other", derived("kubernetes-list"), None):
        with pytest.raises(commands.RuntimeFailure, match="configuration"):
            commands.RuntimeProfile(value)


@pytest.mark.parametrize("field", ["run", "cluster", "custody-profile"])
def test_KubernetesOriginalCustodyCannotBeReboundToAnotherContext(tmp_path, field):
    """Original manifest identity fixes its first selected cluster/run and custody profile."""

    context = KubernetesContext(tmp_path)
    status, original = Run(Arguments(context, profile="kubernetes-list"), clock=lambda: TIME)
    assert status == 0, "Original Kubernetes setup did not import"
    model = LocalModelStore(context[0])
    state = model.Open()
    arguments = Arguments(context, profile="kubernetes-list", evidence_id=original["evidence_id"])

    if field == "run":
        arguments = Value(arguments, "--run", "run:other")

    elif field == "cluster":
        cluster = SecurityObject(ObjectIdentity(state.workspace_id, ObjectKind.ASSET,
            "kubernetes-cluster:other"),
            {"asset_type": "kubernetes-cluster", "cluster_id": "other"},
            context[2].provenance)
        proposal, _ = state.Apply(objects=(cluster,))
        model.Save(proposal, expected_revision=state.revision)
        arguments = Value(Arguments(context, profile="kubernetes-list",
            evidence_id=original["evidence_id"]), "--cluster", cluster.Reference())

    else:
        observations = tuple(replace(item,
            attributes={**item.attributes, "profile": "docker-inspect"})
            if item.kind == "runtime-import-source" else item for item in state.observations)
        model.Save(replace(state, revision=state.revision + 1, observations=observations),
                   expected_revision=state.revision)
        arguments = Arguments(context, profile="kubernetes-list",
                              evidence_id=original["evidence_id"])

    before = model.Open()
    status, outcome = Run(arguments)
    assert status == 4 and outcome["failure"] == "source-context", "Original context was rebound"
    assert model.Open() == before, "Rejected original Kubernetes context mutated the saved basis"
