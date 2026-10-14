# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Original API import admission, pre-read refusals and physical custody boundaries."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest

from fuzzy1337 import api_commands as commands
from fuzzy1337 import artifact_inputs, graphql_import, report_commands
from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.evidence import EvidenceProvenance, EvidenceRecord, LocalEvidenceStore
from fuzzy1337.model import LocalModelStore, ModelProvenance, SecurityObject
from fuzzy1337.requests import Endpoint
from fuzzy1337.scope import AuthorizationState, LocalScopeStore, Target, TargetKind
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.api_import_helpers import (
    ENDPOINT,
    TIME,
    Arguments,
    Context,
    Files,
    Imported,
    Run,
    Value,
)


def RefuseRead(*args, **kwargs):
    """Fail explicitly if a denial reaches any original byte-consumer boundary."""

    pytest.fail("Refused original source reached a raw read")


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["fetch", "PRIVATE_ARGUMENT_MARKER"],
        ["import", "openapi", "PRIVATE_ARGUMENT_MARKER"],
        ["import", "graphql-introspection"],
        ["import", "graphql-introspection", "PRIVATE_ARGUMENT_MARKER", "--execute"],
    ],
)
def test_ClosedGrammarRejectsUnsupportedModesWithoutRenderingValues(arguments):
    """Missing selections, retrieval and other import profiles yield one safe configuration
    result.
    """

    status, outcome = Run(arguments)
    assert status == 2 and outcome["failure"] == "configuration", "Unsupported grammar was accepted"
    assert "PRIVATE_ARGUMENT_MARKER" not in json.dumps(outcome), "Rejected argument was exposed"
    assert all(
        outcome[field] == "not-attempted"
        for field in (
            "acquisition_commit",
            "model_commit",
            "workspace_commit",
        )
    ), "Invalid grammar attempted a storage boundary"


def test_HelpAndHumanOutputUseOnlySafeOwnedPresentation(tmp_path):
    """Static help needs no owner state and summaries do not expose raw source or physical paths."""

    status, output = Run(["--help"], json_output=False)
    assert status == 0 and "--endpoint URL" in output, "Mandatory explicit endpoint help was lost"
    context = Context(tmp_path)
    status, output = Run(Arguments(context), json_output=False)
    assert status == 0 and "model_commit: confirmed" in output, "Human acknowledgement failed"
    assert str(context[4]) not in output and "synthetic-private-default" not in output, (
        "Source information escaped summary presentation"
    )


@pytest.mark.parametrize("flag", ["--owner", "--read-consent-reference", "--endpoint"])
def test_FileSelectionNeedsExplicitReadConsentAndEndpointBeforeReading(tmp_path, monkeypatch, flag):
    """The workspace and source description infer neither current file consent nor endpoint."""

    context = Context(tmp_path)
    arguments = Arguments(context)
    index = arguments.index(flag)
    del arguments[index : index + 2]
    monkeypatch.setattr(commands, "ReadOwnedGraphQl", RefuseRead)
    status, outcome = Run(arguments)
    assert status == 2 and outcome["acquisition_commit"] == "not-attempted", (
        "Missing explicit context reached source acquisition"
    )


@pytest.mark.parametrize(
    "flag,value",
    [
        ("--expected-revision", -1),
        ("--expected-workspace-revision", -1),
        ("--endpoint", "http://actor:PRIVATE_ARGUMENT_MARKER@127.0.0.1/graphql"),
        ("--endpoint", ENDPOINT + "?"),
        ("--endpoint", ENDPOINT + "?x=PRIVATE_ARGUMENT_MARKER"),
        ("--endpoint", "http://127.0.0.1/{endpoint}"),
        ("--run", "PRIVATE_ARGUMENT_MARKER\n"),
        ("--scope", "../PRIVATE_ARGUMENT_MARKER"),
    ],
)
def test_MalformedExplicitContextFailsBeforeRawReads(tmp_path, monkeypatch, flag, value):
    """Ambiguous URLs and invalid context never reach existing or external source consumers."""

    context = Context(tmp_path)
    monkeypatch.setattr(commands, "OpenReportInput", RefuseRead)
    monkeypatch.setattr(commands, "ReadOwnedGraphQl", RefuseRead)
    status, outcome = Run(Value(Arguments(context), flag, value))
    assert status == 2 and outcome["acquisition_commit"] == "not-attempted", (
        "Malformed context read"
    )
    assert "PRIVATE_ARGUMENT_MARKER" not in json.dumps(outcome), "Malformed context leaked"


@pytest.mark.parametrize("flag", ["--expected-revision", "--expected-workspace-revision"])
def test_StaleOwnerRevisionsRefuseBeforeAnyRawRead(tmp_path, monkeypatch, flag):
    """Explicit independent revision pins are never replaced silently with current state."""

    context = Context(tmp_path)
    monkeypatch.setattr(commands, "OpenReportInput", RefuseRead)
    monkeypatch.setattr(commands, "ReadOwnedGraphQl", RefuseRead)
    status, outcome = Run(Value(Arguments(context), flag, 99))
    assert status == 4 and outcome["failure"] == (
        "revision-conflict" if flag == "--expected-revision" else "workspace-conflict"
    ), "Stale independent owner revision was accepted"


@pytest.mark.parametrize("mode", ["unknown", "deny", "unregistered", "not-allowed", "expired"])
@pytest.mark.parametrize("retained", [False, True])
def test_CurrentExactScopeRefusesBeforeAllSourceReads(tmp_path, monkeypatch, mode, retained):
    """A historical acquisition never substitutes for current exact endpoint consent/membership."""

    if retained:
        context, first = Imported(tmp_path)
        arguments = Arguments(context, evidence_id=first["evidence_id"])

    else:
        context = Context(tmp_path)
        arguments = Arguments(context)

    scope = context[2]
    changes = {
        "unknown": {
            "authorization": replace(scope.authorization, state=AuthorizationState.UNKNOWN)
        },
        "deny": {"deny": (Target(TargetKind.IP, "127.0.0.1"),)},
        "unregistered": {"targets": ()},
        "not-allowed": {"allow": ()},
        "expired": {
            "authorization": replace(
                scope.authorization, valid_until=(TIME - timedelta(seconds=1)).isoformat()
            )
        },
    }
    LocalScopeStore(context[0]).Save(replace(scope, **changes[mode]))
    monkeypatch.setattr(commands, "OpenReportInput", RefuseRead)
    monkeypatch.setattr(commands, "ReadOwnedGraphQl", RefuseRead)
    monkeypatch.setattr(LocalEvidenceStore, "Read", RefuseRead)
    status, outcome = Run(arguments)
    assert status == 4 and outcome["failure"] == "scope", "Current scope denial was ignored"
    assert outcome["acquisition_commit"] == "not-attempted", "Scope denial acquired source"


@pytest.mark.parametrize(
    "variant",
    [
        "role",
        "media",
        "size",
        "workspace",
        "scope",
        "source",
        "version",
        "tool",
        "invocation",
        "missing-custody",
    ],
)
def test_ManifestProfileContextAndKnownCustodyPrecedeAnyRawRead(tmp_path, monkeypatch, variant):
    """Even eager workspace/report verification cannot read a selected incompatible acquisition."""

    context = Context(tmp_path)
    root, _, scope, evidence, source = context
    raw = source.read_bytes()
    provenance = EvidenceProvenance(
        "api-owned",
        scope.Reference(),
        "graphql-import",
        "1",
        None,
        TIME.isoformat(),
        TIME.isoformat(),
    )
    changes = {
        "workspace": {"workspace_id": "foreign"},
        "scope": {"scope_reference": "scope:other"},
        "source": {"source_id": "openapi"},
        "version": {"source_version": "2"},
        "tool": {"tool_version": "invented"},
        "invocation": {"invocation_sha256": "a" * 64},
    }
    provenance = replace(provenance, **changes.get(variant, {}))
    record = evidence.Put(
        b"x" * (512 * 1024 + 1) if variant == "size" else raw,
        "api-structure" if variant == "role" else "graphql-introspection",
        "text/plain" if variant == "media" else "application/json",
        provenance,
    )
    monkeypatch.setattr(LocalEvidenceStore, "Read", RefuseRead)
    monkeypatch.setattr(commands, "OpenReportInput", RefuseRead)
    status, outcome = Run(Arguments(context, evidence_id=record.evidence_id))
    assert status == 4 and outcome["failure"] == (
        "source-context" if variant == "missing-custody" else "integrity"
    ), "Original manifest profile/context or known custody was inferred"
    assert not LocalModelStore(root).Open().objects, (
        "Denied original acquisition created an endpoint"
    )


@pytest.mark.parametrize(
    "flag,value",
    [
        ("--run", "run:other"),
        ("--endpoint", "http://127.0.0.1:8080/other"),
    ],
)
def test_KnownOriginalCustodyCannotChangeRunOrEndpointBeforeRead(
    tmp_path, monkeypatch, flag, value
):
    """An acquisition identity pins attribution independently from its reusable raw digest."""

    context, first = Imported(tmp_path)

    if flag == "--endpoint":
        other = Target(TargetKind.URL, value)
        scope = context[2]
        LocalScopeStore(context[0]).Save(
            replace(scope, targets=(*scope.targets, other), allow=(*scope.allow, other))
        )

    monkeypatch.setattr(commands, "OpenReportInput", RefuseRead)
    monkeypatch.setattr(LocalEvidenceStore, "Read", RefuseRead)
    status, outcome = Run(Value(Arguments(context, evidence_id=first["evidence_id"]), flag, value))
    assert status == 4 and outcome["failure"] == "source-context", "Original context was replaced"


@pytest.mark.parametrize(
    "flag", ["--owner", "--read-consent-reference", "--provider-version", "--session", "--execute"]
)
def test_RetainedModeHasNoReadOrExecutionOverrides(tmp_path, monkeypatch, flag):
    """Replay cannot reinterpret original custody or introduce authentication/execution defaults."""

    context, first = Imported(tmp_path)
    monkeypatch.setattr(LocalEvidenceStore, "Read", RefuseRead)
    status, outcome = Run(Arguments(context, evidence_id=first["evidence_id"]) + [flag, "other"])
    assert status == 2 and outcome["failure"] == "configuration", "Retained override was accepted"


@pytest.mark.parametrize("mode", ["missing", "directory", "empty", "oversized", "malformed"])
def test_OriginalFileFailuresKeepAcquisitionTruthDistinctFromNormalization(tmp_path, mode):
    """Unparseable acquired original bytes remain distinct from a source never acquired."""

    context = Context(tmp_path)
    source = context[4]

    if mode == "missing":
        source.unlink()

    elif mode == "directory":
        source.unlink()
        source.mkdir()

    else:
        source.write_bytes(
            {
                "empty": b"",
                "oversized": b"x" * (512 * 1024 + 1),
                "malformed": b'{"private":"PRIVATE_SOURCE_MARKER"}',
            }[mode]
        )

    status, outcome = Run(Arguments(context))
    assert status == 4 and outcome["model_commit"] == "not-attempted", "Invalid source saved model"
    assert outcome["acquisition_commit"] == (
        "confirmed" if mode == "malformed" else "not-attempted"
    ), "Acquisition truth was guessed"
    assert "PRIVATE_SOURCE_MARKER" not in json.dumps(outcome), "Source diagnostics leaked"
    assert LocalModelStore(context[0]).Open() == context[1], (
        "Refused source changed canonical model"
    )


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_SelectedPhysicalLinksAreRefusedBeforeAcquisition(tmp_path, kind):
    """Artifact-read references never authorize following a link or shared hard-linked source."""

    context = Context(tmp_path)
    selected = tmp_path / "linked.json"

    try:
        if kind == "symlink":
            selected.symlink_to(context[4])

        else:
            os.link(context[4], selected)

    except (OSError, NotImplementedError):
        pytest.skip("Owned physical link creation is unavailable")

    status, outcome = Run(Value(Arguments(context), "--file", selected))
    assert status in {2, 4} and outcome["acquisition_commit"] == "not-attempted", (
        "Linked source read"
    )


def Metadata(info, **changes):
    """Keep inode/size/restored mtime stable while describing independently changed physical
    views.
    """

    return SimpleNamespace(
        **{
            **{
                name: getattr(info, name)
                for name in (
                    "st_dev",
                    "st_ino",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                    "st_nlink",
                )
            },
            **changes,
        }
    )


@pytest.mark.parametrize("view", ["path", "handle"])
@pytest.mark.parametrize("windows", [False, True])
def test_SameViewCtimeDriftRefusesBeforeEvidencePublication(tmp_path, monkeypatch, view, windows):
    """Same inode/size/restored mtime never permits different ctime within the same observed
    view.
    """

    context = Context(tmp_path)
    original_path, original_handle = commands.CheckStorageEntry, commands.os.fstat
    calls = 0

    def Observe(*args, **kwargs):
        """Change only the selected physical view's second ctime observation."""

        nonlocal calls
        result = (original_path if view == "path" else original_handle)(*args, **kwargs)

        if view == "handle" or args[0] == context[4]:
            calls += 1
            result = Metadata(result, st_ctime_ns=result.st_ctime_ns + (calls > 1))

        return result

    monkeypatch.setattr(artifact_inputs, "_WINDOWS_STAT_VIEWS", windows)
    monkeypatch.setattr(
        commands if view == "path" else commands.os,
        "CheckStorageEntry" if view == "path" else "fstat",
        Observe,
    )
    status, outcome = Run(Arguments(context))
    assert status == 4 and outcome["failure"] == "source-changed", "Same-view ctime drift accepted"
    assert outcome["acquisition_commit"] == "not-attempted", "Unstable source was published"


def test_WindowsCrossViewCtimeDifferenceAcceptsStableViewsAndOriginalBytes(tmp_path, monkeypatch):
    """The platform exception applies only across stable path/handle identities, retaining raw
    hash.
    """

    context = Context(tmp_path)
    original = commands.os.fstat

    def Handle(fd):
        """Expose a stable different handle ctime with all other identity fields unchanged."""

        result = original(fd)

        return Metadata(result, st_ctime_ns=result.st_ctime_ns + 100)

    monkeypatch.setattr(artifact_inputs, "_WINDOWS_STAT_VIEWS", True)
    monkeypatch.setattr(commands.os, "fstat", Handle)
    raw, _, _ = commands.ReadOwnedGraphQl(
        context[4], ArtifactReadConsent("actor:owned", "consent:original"), lambda: TIME
    )
    assert raw == context[4].read_bytes(), "Cross-view metadata exception changed original bytes"


@pytest.mark.parametrize("variant", ["subclass", "role", "evidence-id", "scope"])
def test_NominalAndFrozenManifestMutantsRefuseBeforeRawRead(tmp_path, monkeypatch, variant):
    """Controller boundaries reject typed subclasses and mutated frozen records before blob
    access.
    """

    context, first = Imported(tmp_path)
    record = context[3].Get(first["evidence_id"])

    class DerivedRecord(EvidenceRecord):
        """Represent an unsupported caller-owned nominal record subclass."""

    if variant == "subclass":
        record = DerivedRecord(record.reference, record.provenance)

    elif variant == "role":
        object.__setattr__(record.reference, "role", "api-structure")

    elif variant == "evidence-id":
        object.__setattr__(record, "evidence_id", "sha256:" + "a" * 64)

    else:
        object.__setattr__(record.provenance, "scope_reference", "scope:other")

    monkeypatch.setattr(commands.ApiEvidenceStore, "Manifest", lambda *args: record)
    monkeypatch.setattr(LocalEvidenceStore, "Read", RefuseRead)
    monkeypatch.setattr(commands, "OpenReportInput", RefuseRead)
    status, outcome = Run(Arguments(context, evidence_id=first["evidence_id"]))
    assert status == 4 and outcome["failure"] == "integrity", "Nominal/frozen manifest mutant read"


@pytest.mark.parametrize(
    "occupied", ["templates", "metadata", "different-source", "different-list"]
)
def test_OccupiedIncompatibleEndpointIsRefusedWithoutReplacingCollections(tmp_path, occupied):
    """Admission never guesses a refresh or combines complete collections from unrelated sources."""

    context = Context(tmp_path)
    imported = graphql_import.ImportGraphQl(
        context[4].read_bytes(), workspace_id=context[1].workspace_id, endpoint_url=ENDPOINT
    )
    attribution = ModelProvenance(
        "other", "run:other", TIME.isoformat(), "scope:owned", context[2].targets[0].Reference()
    )
    projection = graphql_import.ProjectGraphQl(imported, provenance=(attribution,))
    attributes = dict(projection.attributes)

    if occupied == "templates":
        del attributes["graphql_import"]

    elif occupied == "metadata":
        del attributes["request_templates"]

    elif occupied == "different-source":
        attributes["graphql_import"] = {**attributes["graphql_import"], "source_digest": "sha256:x"}

    else:
        attributes["request_templates"] = attributes["request_templates"][:-1]

    attributes["operator_note"] = "retain-owned-description"
    patch = SecurityObject(projection.identity, attributes, (attribution,))
    changed, _ = context[1].Apply(objects=(patch,))
    saved = LocalModelStore(context[0]).Save(changed, expected_revision=context[1].revision)
    workspace_before = (context[0] / "workspace.json").read_bytes()
    status, outcome = Run(Arguments(context))
    assert status == 4 and outcome["failure"] == "occupied-endpoint", (
        "Incompatible collection updated"
    )
    assert outcome["acquisition_commit"] == "confirmed" and (
        outcome["model_commit"] == "not-attempted"
    ), "Occupied refusal guessed acquisition/model commit truth"
    assert LocalModelStore(context[0]).Open() == saved, "Occupied collection was replaced"
    assert (context[0] / "workspace.json").read_bytes() == workspace_before, (
        "Occupied refusal saved owner"
    )


def test_ExistingEndpointWithoutApiCollectionsRetainsUnrelatedAttributesAndProvenance(tmp_path):
    """A descriptive endpoint can receive a first API collection without losing earlier facts."""

    context = Context(tmp_path)
    attribution = ModelProvenance(
        "other", "run:other", TIME.isoformat(), "scope:owned", context[2].targets[0].Reference()
    )
    endpoint = Endpoint(context[1].workspace_id, "http://127.0.0.1:8080", "/graphql", "POST")
    patch = SecurityObject(
        endpoint.Identity(), {"operator_note": "retain", "reachability": None}, (attribution,)
    )
    changed, _ = context[1].Apply(objects=(patch,))
    LocalModelStore(context[0]).Save(changed, expected_revision=context[1].revision)
    status, _ = Run(Arguments(context))
    current = LocalModelStore(context[0]).Open().objects[0]
    assert (
        status == 0
        and current.attributes["operator_note"] == "retain"
        and (current.attributes["reachability"] is None and attribution in current.provenance)
    ), "Import replaced unrelated descriptions, UNKNOWN values or attribution"


def test_NoGeneratorTransportOrNativeExecutionIsNeeded(tmp_path, monkeypatch):
    """Original structural imports never call preview, socket, HTTP or native execution owners."""

    import socket
    import subprocess

    context = Context(tmp_path)
    monkeypatch.setattr(graphql_import, "GenerateGraphQlRequest", RefuseRead)
    monkeypatch.setattr(socket, "socket", RefuseRead)
    monkeypatch.setattr(subprocess, "Popen", RefuseRead)
    status, _ = Run(Arguments(context))
    assert status == 0, "Import depended on preview generation, transport or a native process"


def test_OriginalReplacementAtObservationRefusesBeforePublication(tmp_path):
    """A source change after the bounded read cannot be published as the selected original file."""

    context = Context(tmp_path)
    calls = 0

    def Clock():
        """Replace only the owned original at the read-finished observation."""

        nonlocal calls
        calls += 1

        if calls == 3:
            context[4].write_bytes(b"owned replacement")

        return TIME

    status, outcome = Run(Arguments(context), clock=Clock)
    assert status == 4 and outcome["failure"] == "source-changed", "Observed replacement admitted"
    assert outcome["acquisition_commit"] == "not-attempted", "Changed source was retained"


def test_ScopeExpiryDuringAcquisitionRefusesBeforeModelWrite(tmp_path):
    """The final symbolic target check consumes a fresh current time after source acquisition."""

    context = Context(tmp_path)
    scope = context[2]
    LocalScopeStore(context[0]).Save(replace(scope, authorization=replace(scope.authorization,
        valid_until=(TIME + timedelta(seconds=1)).isoformat())))
    times = iter([TIME, TIME, TIME, TIME + timedelta(seconds=2)])
    status, outcome = Run(Arguments(context), clock=lambda: next(times))
    assert status == 4 and outcome["acquisition_commit"] == "confirmed" and (
        outcome["model_commit"] == "not-attempted"
    ), "Expired current target scope was replaced with historical acquisition membership"
    assert LocalModelStore(context[0]).Open() == context[1], "Expired scope changed saved model"


def test_SameManifestCannotChangeOriginalReadConsent(tmp_path):
    """A repeated exact acquisition identity cannot silently replace its original custody actor."""

    context, _ = Imported(tmp_path)
    before = Files(context[0])
    status, outcome = Run(Value(Arguments(context), "--owner", "actor:other"))
    assert status == 4 and outcome["failure"] == "source-context" and (
        outcome["acquisition_commit"] == "confirmed"
    ), "Original same-manifest read descriptions were replaced or acknowledgement lost"
    assert Files(context[0]) == before, "Original custody mutation rewrote owner state"


def test_GrownSelectedBlobRefusesBeforeAnyGenericRetainedRead(tmp_path, monkeypatch):
    """Refuse a real grown selected blob before any generic report or raw consumer."""

    context, first = Imported(tmp_path)
    root = context[0]
    record = context[3].Get(first["evidence_id"])
    blob = root / "evidence" / record.reference.locator
    blob.write_bytes(b"x" * (512 * 1024 + 1))
    before = LocalModelStore(root).Open()
    workspace_before = (root / "workspace.json").read_bytes()
    monkeypatch.setattr(commands, "OpenReportInput", RefuseRead)
    monkeypatch.setattr(LocalEvidenceStore, "Read", RefuseRead)
    status, outcome = Run(Arguments(context, evidence_id=record.evidence_id))
    assert status == 4 and outcome["failure"] == "integrity", "Grown blob reached raw access"
    assert outcome["acquisition_commit"] == "not-attempted", "Grown blob was acknowledged"
    assert LocalModelStore(root).Open() == before, "Grown selected blob changed model state"
    assert (root / "workspace.json").read_bytes() == workspace_before, "Grown blob saved workspace"


@pytest.mark.parametrize("owner", ["workspace", "model"])
def test_LargerSameBlobAliasRefusesBeforeAnyGenericRetainedRead(tmp_path, monkeypatch, owner):
    """A real larger declared alias cannot reach the generic owner's looser raw-read bound."""

    context, first = Imported(tmp_path)
    root = context[0]
    record = context[3].Get(first["evidence_id"])
    reference = record.reference
    alias = EvidenceReference(reference.role, reference.locator, reference.sha256,
                              reference.media_type, 512 * 1024 + 1)

    if owner == "workspace":
        workspace = LocalWorkspaceStore(root).Open()
        LocalWorkspaceStore(root).Save(replace(workspace, evidence_references=(alias,)))

    else:
        basis = LocalModelStore(root).Open()
        attribution = ModelProvenance("owned.alias", "run:alias", TIME.isoformat(), "scope:owned",
            context[2].targets[0].Reference(), evidence_references=(alias,))
        patch = SecurityObject(basis.objects[0].identity, {"owned_alias_note": "retain"},
                               (attribution,))
        changed, _ = basis.Apply(objects=(patch,))
        LocalModelStore(root).Save(changed, expected_revision=basis.revision)

    before = LocalModelStore(root).Open()
    workspace_before = (root / "workspace.json").read_bytes()
    monkeypatch.setattr(commands, "OpenReportInput", RefuseRead)
    monkeypatch.setattr(LocalEvidenceStore, "Read", RefuseRead)
    status, outcome = Run(Arguments(context, evidence_id=record.evidence_id))
    assert status == 4 and outcome["failure"] == "integrity", "Larger alias reached raw access"
    assert outcome["acquisition_commit"] == "not-attempted", "Refused alias was acknowledged"
    assert LocalModelStore(root).Open() == before, "Alias refusal changed the actual model owner"
    assert (root / "workspace.json").read_bytes() == workspace_before, "Alias saved workspace"


@pytest.mark.parametrize("selection", ["file", "retained"])
def test_SameLocatorDifferentDigestAliasRefusesBeforeGenericRead(tmp_path, monkeypatch, selection):
    """An incompatible locator alias is refused before generic reading in either source mode."""

    context, first = Imported(tmp_path)
    root = context[0]
    reference = context[3].Get(first["evidence_id"]).reference
    blob = root / "evidence" / reference.locator
    original = blob.read_bytes()
    digest = "0" * 64 if reference.sha256 != "0" * 64 else "1" * 64
    alias = replace(reference, role="a-other-role", sha256=digest)
    assert alias.locator == reference.locator and alias.sha256 != reference.sha256, (
        "The incompatible specimen must select the original locator with a different digest"
    )
    workspace = LocalWorkspaceStore(root).Open()
    LocalWorkspaceStore(root).Save(replace(workspace, evidence_references=(alias,)))
    before = Files(root)
    monkeypatch.setattr(report_commands.BoundedReportEvidenceStore, "Read", RefuseRead)
    monkeypatch.setattr(commands, "ReadOwnedGraphQl", RefuseRead)
    arguments = Arguments(context, evidence_id=first["evidence_id"]
                          if selection == "retained" else None)
    status, outcome = Run(arguments)
    assert status == 4 and outcome["failure"] == "integrity", "Locator alias reached generic read"
    assert all(outcome[name] == "not-attempted" for name in (
        "acquisition_commit", "model_commit", "workspace_commit"
    )), "Refused locator alias reached a storage boundary"
    assert Files(root) == before and blob.read_bytes() == original, (
        "Locator alias refusal changed original bytes or owning state"
    )


@pytest.mark.parametrize("selection", ["file", "retained"])
def test_KnownGraphQlCustodyCannotRelabelOversizedNonProfileOriginal(
    tmp_path, monkeypatch, selection,
):
    """Known custody binds the original profile before generic verification can read its bytes."""

    context, first = Imported(tmp_path)
    root, _, _, evidence, _ = context
    original = evidence.Get(first["evidence_id"])
    unrelated = evidence.Put(b"owned offline original\n" * 25000, "stdout", "text/plain",
                             original.provenance)
    assert unrelated.reference.size_bytes > commands.MAX_GRAPHQL_BYTES, (
        "The non-profile original must exceed the GraphQL read ceiling"
    )
    basis = LocalModelStore(root).Open()
    fact = next(item for item in basis.observations if item.kind == "api-import-source")
    substituted = replace(fact, attributes={**fact.attributes, "evidence_id": unrelated.evidence_id,
        "source_sha256": unrelated.reference.sha256}, provenance=replace(
            fact.provenance, evidence_references=(unrelated.reference,)))
    changed, _ = basis.Apply(observations=(substituted,))
    LocalModelStore(root).Save(changed, expected_revision=basis.revision)
    before = Files(root)
    owning_read = LocalEvidenceStore.Read

    def Read(store, reference):
        """Expose the claimed non-profile original at the actual generic raw-reader boundary."""

        if reference == unrelated.reference:
            RefuseRead()

        return owning_read(store, reference)

    monkeypatch.setattr(LocalEvidenceStore, "Read", Read)
    arguments = Arguments(context, evidence_id=first["evidence_id"]
                          if selection == "retained" else None)
    status, outcome = Run(arguments)
    assert status == 4 and outcome["failure"] == "integrity", "Custody relabel reached raw bytes"
    assert all(outcome[name] == "not-attempted" for name in (
        "acquisition_commit", "model_commit", "workspace_commit"
    )), "Refused custody relabel reached a storage boundary"
    assert Files(root) == before, "Custody relabel refusal changed original bytes or owner state"


def test_FileModePreflightsKnownGraphQlOriginalBeforeGenericReportRead(tmp_path, monkeypatch):
    """A valid file cannot expose a grown known GraphQL blob through a larger role alias."""

    context, first = Imported(tmp_path)
    root = context[0]
    record = context[3].Get(first["evidence_id"])
    reference = record.reference
    alias = EvidenceReference("a-other-role", reference.locator, reference.sha256,
                              reference.media_type, 512 * 1024 + 1)
    workspace = LocalWorkspaceStore(root).Open()
    LocalWorkspaceStore(root).Save(replace(workspace, evidence_references=(alias,)))
    (root / "evidence" / reference.locator).write_bytes(b"x" * (512 * 1024 + 1))
    before = LocalModelStore(root).Open()
    workspace_before = (root / "workspace.json").read_bytes()
    monkeypatch.setattr(commands, "OpenReportInput", RefuseRead)
    monkeypatch.setattr(LocalEvidenceStore, "Read", RefuseRead)
    monkeypatch.setattr(commands, "ReadOwnedGraphQl", RefuseRead)
    status, outcome = Run(Arguments(context))
    assert status == 4 and outcome["failure"] == "integrity", "File mode reached known grown blob"
    assert outcome["acquisition_commit"] == "not-attempted", "File mode skipped source guard"
    assert LocalModelStore(root).Open() == before, "File-mode guard changed the model owner"
    assert (root / "workspace.json").read_bytes() == workspace_before, "File guard saved workspace"


@pytest.mark.parametrize("known_by", ["manifest-only", "model-reference", "custody-only"])
def test_FileModePreflightsKnownGraphQlWithoutAdoptingCustody(tmp_path, monkeypatch, known_by):
    """Metadata-only discovery bounds old GraphQL sources without requiring or inventing custody."""

    if known_by == "custody-only":
        context, first = Imported(tmp_path)

    else:
        context = Context(tmp_path)

    root, basis, scope, evidence, source = context

    if known_by == "custody-only":
        record = evidence.Get(first["evidence_id"])

    else:
        record = evidence.Put(source.read_bytes(), "graphql-introspection", "application/json",
            EvidenceProvenance(basis.workspace_id, scope.Reference(), "graphql-import", "1", None,
                               TIME.isoformat(), TIME.isoformat()))
    reference = record.reference
    alias = EvidenceReference("a-other-role", reference.locator, reference.sha256,
                              reference.media_type, 512 * 1024 + 1)
    workspace = LocalWorkspaceStore(root).Open()
    LocalWorkspaceStore(root).Save(replace(workspace, evidence_references=(alias,),
        evidence_record_references=(record.evidence_id,) if known_by == "manifest-only" else ()))

    if known_by == "model-reference":
        attribution = ModelProvenance(
            "graphql-import", "run:sdk", TIME.isoformat(), scope.Reference(),
            scope.targets[0].Reference(), evidence_references=(reference,))
        imported = graphql_import.ImportGraphQl(source.read_bytes(),
            workspace_id=basis.workspace_id, endpoint_url=ENDPOINT)
        patch = graphql_import.ProjectGraphQl(imported, provenance=(attribution,))
        changed, _ = basis.Apply(objects=(patch,))
        LocalModelStore(root).Save(changed, expected_revision=basis.revision)

    (root / "evidence" / reference.locator).write_bytes(b"x" * (512 * 1024 + 1))
    before = LocalModelStore(root).Open()
    workspace_before = (root / "workspace.json").read_bytes()
    monkeypatch.setattr(commands, "OpenReportInput", RefuseRead)
    monkeypatch.setattr(LocalEvidenceStore, "Read", RefuseRead)
    monkeypatch.setattr(commands, "ReadOwnedGraphQl", RefuseRead)
    status, outcome = Run(Arguments(context))
    assert status == 4 and outcome["failure"] == "integrity", "Known GraphQL blob reached raw"
    assert LocalModelStore(root).Open() == before, "Budget preflight adopted or changed SDK custody"
    assert (root / "workspace.json").read_bytes() == workspace_before, "Budget guard saved state"
