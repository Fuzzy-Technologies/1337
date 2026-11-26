# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify bounded MCP normalization and shared local custody without external services."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from fuzzy1337 import mcp_metadata_http
from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.evidence import EvidenceProvenance, EvidenceRecord, LocalEvidenceStore
from fuzzy1337.mcp_inventory import (
    CollectAndImportMcpMetadata,
    ImportMcpInventory,
    ParseMcpInventory,
)
from fuzzy1337.mcp_metadata import (
    MCP_PROTOCOL_VERSION,
    McpMetadataDenied,
    McpMetadataIssue,
    McpMetadataResult,
)
from fuzzy1337.model import LocalModelStore
from fuzzy1337.policy import ImpactPolicy
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration, WorkspaceConflictError

_CANARY = "synthetic-value-never-retained"
_OBSERVED = "2026-11-26T12:00:00+00:00"
_SOURCE = Path(__file__).parents[1] / "contract" / "fixtures" / "mcp.inventory.v1.json"
_LIVE_SOURCE = Target(TargetKind.URL, "http://127.0.0.1:4819/catalog")
_LIVE_ADDRESS = Target(TargetKind.IP, "127.0.0.1")


def Sample() -> Any:
    """Return a fresh benign inventory to use as version-one input."""

    return json.loads(_SOURCE.read_bytes())


def Encode(value: object) -> bytes:
    """Encode synthetic source independently of the normalized output."""

    return json.dumps(value).encode("utf-8")


def Import(path: Path, model: LocalModelStore, revision: int, observedAt: str = _OBSERVED) -> Any:
    """Use the normal file, scope, evidence and model owners for an explicit local import."""

    return ImportMcpInventory(
        model, path, serverKey="sample", scopeId="catalog",
        consent=ArtifactReadConsent("actor:operator", "consent:local-read"),
        observedAt=observedAt, expectedRevision=revision,
    )


def CreateModel(path: Path) -> LocalModelStore:
    """Set up the real owners without writing any source or normalized evidence."""

    LocalWorkspaceStore(path).Create(WorkspaceConfiguration("MCP catalog"), "catalog-workspace")
    LocalScopeStore(path).Create(ScopeSnapshot("catalog", "catalog-workspace"))
    model = LocalModelStore(path)
    model.Create()

    return model


def test_SanitizesCredentialsBeforeProjecting() -> None:
    """Keep the useful declaration shape and omit literal credential values and metadata."""

    source = Sample()
    source["instructions"] = "Use the local catalog. Authorization: Bearer " + _CANARY
    source["server"]["_meta"] = {"arbitrary": _CANARY}
    tool = source["tools"]["items"][0]
    tool["description"] = f"password='{_CANARY}' and " + json.dumps({
        "password": f'fixture "value" with spaces: {_CANARY}',
    })
    tool["annotations"]["title"] = f"API key: {_CANARY}"
    embeddedToken = "fixture_ghp_" + _CANARY
    tool["inputSchema"]["properties"][embeddedToken] = {"type": "string"}
    tool["inputSchema"]["required"].append(embeddedToken)
    tool["inputSchema"]["properties"]["api_key"] = {
        "type": ["string", "null"],
        "const": _CANARY,
        "default": _CANARY,
        "examples": [{"nested": [_CANARY]}],
        "enum": [_CANARY],
        "pattern": "Bearer " + _CANARY,
        "readOnly": True,
    }
    tool["inputSchema"]["additionalProperties"] = {"oneOf": [True, {"type": "string"}]}
    tool["inputSchema"]["$defs"] = {"non identifier": {"type": "string"}}
    tool["inputSchema"]["prefixItems"] = [False, True]
    tool["inputSchema"]["if"] = {"minLength": 1}
    tool["inputSchema"]["unknown"] = _CANARY
    source["resources"]["items"][0]["uri"] = (
        f"catalog://user:{_CANARY}@documents/index?api_key={_CANARY}#redact"
    )
    source["capabilities"]["items"][1]["declaration"]["other"] = {"password": _CANARY}
    source["prompts"]["items"][0]["arguments"].append({"name": "filter"})
    projection = ParseMcpInventory(Encode(source))
    sections = projection["sections"]
    assert isinstance(sections, dict), "Normalized sections must remain independent records"
    projected = sections["tools"]["items"][1]
    schema = projected["input_schema"]
    prop = schema["properties"]["api_key"]

    assert _CANARY not in json.dumps(projection), "A credential survived normalization"
    assert any(key.startswith("sha256:") for key in schema["properties"]), (
        "A credential-shaped field name must be redacted before fingerprinting"
    )
    assert set(schema["required"]) <= schema["properties"].keys(), (
        "Redaction must preserve the correspondence between property and required keys"
    )
    assert projected["annotations"]["openWorldHint"] is None, "Omitted hints must stay unknown"
    assert projected["annotations"]["destructiveHint"] is False, "Explicit false became unknown"
    assert prop["type"] == ["null", "string"], "Types must be canonicalized"
    assert all(prop[key] == "redacted" for key in ("const", "default", "examples", "enum")), (
        "Schema literal values must be omitted independently of their key context"
    )
    assert schema["additionalProperties"] == {"oneOf": [True, {"type": "string"}]}, (
        "Structural schema alternatives must remain useful"
    )
    assert schema["prefixItems"] == [False, True], "Positional schema items must retain order"
    assert schema["has_unsupported_keywords"] is True, "Unprojected keywords require a marker"
    assert sections["capabilities"]["items"][1]["has_unsupported_fields"] is True, (
        "Extension payload omission must be visible"
    )
    assert sections["prompts"]["items"][0]["arguments"][0]["required"] is None, (
        "An omitted prompt argument requirement must remain unknown"
    )
    rotated = Encode(source).replace(_CANARY.encode(), b"different-synthetic-value")
    assert ParseMcpInventory(rotated) == projection, "Recognized credential rotation created drift"


@pytest.mark.parametrize(("source", "message"), [
    (b"", "nonempty UTF-8 JSON"),
    (b" " * (256 * 1024 + 1), "at most"),
    (b'{"schema_version":', "line 1"),
    (b"\xff", "valid UTF-8"),
    (b'"\\ud800"', "strings must be valid UTF-8"),
    (b'{"sample-canary": 0, "sample-canary": 1}', "duplicate key"),
    (b'{"x": NaN}', "invalid numeric literal"),
    (b'{"x": 1e309}', "numbers must be finite"),
    (Encode({"x": "a" * 8193}), "string exceeds"),
    (Encode({"x": [None] * 12001}), "node or depth limit"),
    (b"[" * 25 + b"null" + b"]" * 25, "node or depth limit"),
    (b"[" * 2000 + b"null" + b"]" * 2000, "node or depth limit"),
    (b"[]", "expected an object"),
    (b'{"schema_version": true, "server": {}}', "#/schema_version"),
    (b'{"schema_version": 1, "server": {}}', "missing name, version"),
    (b'{"schema_version": 1, "server": {"name": "", "version": ""}, "extra": 1}',
     "unsupported fields"),
])
def test_RejectsUnusableJson(source: bytes, message: str) -> None:
    """Reject invalid encoding, unsupported envelopes and unbounded JSON without echoing values."""

    with pytest.raises(ValueError, match=message) as failure:
        ParseMcpInventory(source)

    assert "sample-canary" not in str(failure.value), "A duplicate raw key escaped the diagnostic"


@pytest.mark.parametrize(("path", "invalid", "message"), [
    (("server", "protocolVersion"), "bad-revision", "#/server/protocolVersion"),
    (("tools", "status"), "truncated", "#/tools/status"),
    (("tools", "status"), "unsupported", "require an empty array"),
    (("tools", "items"), [{}] * 129, "at most 128"),
    (("tools", "items", 0, "name"), "ghp_sample_canary", "#/tools/items/0/name"),
    (("tools", "items", 0, "name"), "fixture_ghp_sample_canary", "#/tools/items/0/name"),
    (("tools", "items", 0, "inputSchema"), {"type": "string"}, "object-root schema"),
    (("tools", "items", 0, "inputSchema"), {"type": "object", "required": [3]}, "string"),
    (("tools", "items", 0, "inputSchema"), {"type": "object", "required": ["x", "x"]},
     "required contains colliding"),
    (("tools", "items", 0, "inputSchema"), {"type": "object", "properties": []},
     "object of schemas"),
    (("tools", "items", 0, "inputSchema"), {"type": "object", "minLength": "1"},
     "must be a number"),
    (("tools", "items", 0, "inputSchema"), {"type": "object", "items": []}, "expected a schema"),
    (("tools", "items", 0, "inputSchema"), {"type": "object", "items": {"type": "typo"}},
     "JSON Schema type name"),
    (("tools", "items", 0, "inputSchema"), {"type": "object", "items": {"type": []}},
     "unique schema types"),
    (("tools", "items", 0, "inputSchema"), {"type": "object", "examples": True},
     "expected an array"),
    (("tools", "items", 0, "annotations", "readOnlyHint"), 1, "expected a boolean"),
    (("tools", "items", 1, "name"), "catalog_list", "duplicate declaration identity"),
    (("resources", "items", 0, "uri"), "relative.txt", "#/resources/items/0/uri"),
    (("resources", "items", 0, "uri"), "sk-canary://local", "credential-shaped text"),
    (("resources", "items", 0, "mimeType"), "text/plain; key=secret",
     "#/resources/items/0/mimeType"),
    (("resources", "items", 0, "size"), -1, "#/resources/items/0/size"),
    (("prompts", "items", 0, "arguments"),
     [{"name": "section"}, {"name": "section"}], "duplicate prompt argument"),
    (("capabilities", "items", 0, "declaration"), False, "#/capabilities/items/0/declaration"),
])
def test_ReportsProfileField(path: tuple[object, ...], invalid: object, message: str) -> None:
    """Locate an unsupported declaration property without displaying its raw value."""

    document = Sample()
    parent = document

    for key in path[:-1]:
        parent = parent[key]

    parent[path[-1]] = invalid

    with pytest.raises(ValueError, match=message):
        ParseMcpInventory(Encode(document))


def test_RejectsMalformedFileBeforeAnyPublication(tmp_path: Path) -> None:
    """Keep the authoritative model and evidence unchanged after a late descriptor refusal."""

    model = CreateModel(tmp_path / "work")
    path = tmp_path / "source.json"
    source = Sample()
    source["prompts"]["items"].append({"description": _CANARY})
    path.write_bytes(Encode(source))
    before = model.Open()

    with pytest.raises(ValueError, match="#/prompts/items/1: missing name") as failure:
        Import(path, model, before.revision)

    assert _CANARY not in str(failure.value), "The error echoed source data"
    assert model.Open() == before, "An invalid final declaration mutated the model"
    assert list((model.root / "evidence").iterdir()) == [], "Malformed source created evidence"

    with pytest.raises(WorkspaceConflictError, match="revision changed"):
        Import(path, model, before.revision + 1)


@pytest.mark.parametrize(("serverKey", "recordRef"), [
    ("ghp_synthetic", "consent:local-read"),
    ("fixture_ghp_synthetic", "consent:local-read"),
    ("sample", "consent:fixture_ghp_synthetic"),
])
def test_RejectsCredentialShapedAttributionBeforeReading(
    tmp_path: Path, serverKey: str, recordRef: str,
) -> None:
    """Never select or publish attribution with recognized credential spellings."""

    model = LocalModelStore(tmp_path / "nonexistent")

    with pytest.raises(ValueError, match="must be non-secret references") as failure:
        ImportMcpInventory(
            model, tmp_path / "absent.json", serverKey=serverKey,
            scopeId="catalog", consent=ArtifactReadConsent("actor:operator", recordRef),
            observedAt=_OBSERVED, expectedRevision=0,
        )

    assert "ghp_synthetic" not in str(failure.value), "Attribution error leaked its source value"


def test_RejectsUnsafeInputPathAndOversizedProjection(tmp_path: Path) -> None:
    """Refuse unsafe paths and model-sized declarations before evidence publication."""

    model = CreateModel(tmp_path / "work")
    path = tmp_path / "source.json"
    source = Sample()
    source["tools"]["items"][0]["inputSchema"]["properties"] = {
        str(index): {"$comment": "about field " + str(index)} for index in range(1200)
    }
    path.write_bytes(Encode(source))
    link = tmp_path / "another-name.json"
    os.link(path, link)

    with pytest.raises(ValueError, match="singly linked"):
        Import(link, model, 0)

    link.unlink()

    with pytest.raises(ValueError, match="attributes exceed the size limit"):
        Import(path, model, 0)

    assert model.Open().revision == 0, "A rejected projection advanced the model version"
    assert not list((model.root / "evidence").iterdir()), "Rejected projection retained evidence"


def test_PublishedEvidenceAndNewAcquisitionStayAttributable(tmp_path: Path) -> None:
    """Reuse content across acquisition times while retaining unique manifests and observations."""

    model = CreateModel(tmp_path / "work")
    path = tmp_path / "source.json"
    path.write_bytes(_SOURCE.read_bytes())
    first = Import(path, model, 0)
    second = Import(path, model, 1, "2026-11-26T12:01:00+00:00")
    evidence = LocalEvidenceStore(model.root / "evidence")

    assert first.serverReference == second.serverReference, "New acquisition replaced server ID"
    assert first.evidence.reference == second.evidence.reference, "Same normalized bytes changed"
    assert first.evidence.evidence_id != second.evidence.evidence_id, "Acquisition history was lost"
    assert evidence.Get(second.evidence.evidence_id) == second.evidence, "Evidence failed replay"
    assert first.snapshotReference != second.snapshotReference, "Observation history was lost"
    assert second.delta.revision == 2, "A separately attributed acquisition must advance once"


def ApprovedMetadataScope(model: LocalModelStore, scopeId: str = "live") -> ScopeSnapshot:
    """Register the synthetic literal endpoint and receipt in the selected owner."""

    targets = (_LIVE_SOURCE, _LIVE_ADDRESS)

    return LocalScopeStore(model.root).Create(ScopeSnapshot(
        scopeId, model.Open().workspace_id,
        ScopeAuthorization(AuthorizationState.GRANTED, "actor:operator", "consent:local-peer"),
        targets=targets, allow=targets,
    ))


def RunMetadataImport(
    model: LocalModelStore, *, scopeId: str = "live", revision: int = 0,
    endpoint: str = _LIVE_SOURCE.value, approved: bool = True,
) -> Any:
    """Select the real owner workflow with a policy that cannot send any request by itself."""

    return CollectAndImportMcpMetadata(
        model, endpoint, serverKey="sample", scopeId=scopeId, approved=approved,
        expectedRevision=revision, policyProvider=lambda: ImpactPolicy("fixture-policy"),
    )


def FakeMetadata(scope: ScopeSnapshot, **changes: Any) -> McpMetadataResult:
    """Return a synthetic result for the narrow reviewed collector boundary in owner tests."""

    complete = McpMetadataResult(
        _LIVE_SOURCE.Reference(), scope.Reference(), scope.revision, MCP_PROTOCOL_VERSION,
        ParseMcpInventory(_SOURCE.read_bytes()), (),
    )

    return replace(complete, **changes)


def test_FailedMetadataInitializationLeavesExistingOwnersUnchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Return fixed initialization diagnostics without publishing any model or evidence."""

    model = CreateModel(tmp_path / "workspace")
    scope = ApprovedMetadataScope(model)
    failure = FakeMetadata(
        scope, protocolVersion=None, inventory=None,
        issues=(McpMetadataIssue("initialize", "timeout"),),
    )
    monkeypatch.setattr(mcp_metadata_http, "CollectMcpMetadataHttp", lambda *a, **k: failure)
    outcome, imported = RunMetadataImport(model)

    assert outcome == failure and imported is None, "Failed initialization created an inventory"
    assert model.Open().revision == 0, "Failed initialization advanced shared model state"
    assert list((model.root / "evidence").iterdir()) == [], "Failure published evidence"


@pytest.mark.parametrize(("changes", "exception", "diagnostic"), [
    ({"scopeReference": "scope:other"}, McpMetadataDenied, "exact scope"),
    ({"scopeRevision": 1}, McpMetadataDenied, "exact scope"),
    ({"sourceReference": "target:" + "a" * 64}, McpMetadataDenied, "exact scope"),
    ({"protocolVersion": None}, ValueError, "negotiated protocol disagrees"),
    ({"issues": (McpMetadataIssue("tools", "synthetic-secret-diagnostic"),)}, ValueError,
     "fixed unique collection diagnostics"),
])
def test_MetadataAttributionMismatchDoesNotPublish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changes: dict[str, Any],
    exception: type[Exception], diagnostic: str,
) -> None:
    """Fail before evidence creation when the approved collector's facts do not bind."""

    model = CreateModel(tmp_path / "workspace")
    scope = ApprovedMetadataScope(model)
    result = FakeMetadata(scope, **changes)
    monkeypatch.setattr(mcp_metadata_http, "CollectMcpMetadataHttp", lambda *a, **k: result)

    with pytest.raises(exception, match=diagnostic):
        RunMetadataImport(model)

    assert model.Open().revision == 0, "Inconsistent source attribution changed shared state"
    assert list((model.root / "evidence").iterdir()) == [], "Inconsistent attribution was retained"


def test_CollectedMetadataCannotRebindServerOrUseAnUnselectedBasis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refuse unapproved, stale, malformed and cross-scope selections before calling HTTP."""

    model = CreateModel(tmp_path / "workspace")
    scope = ApprovedMetadataScope(model)
    result = FakeMetadata(scope, issues=(McpMetadataIssue("prompts", "timeout"),))
    result.inventory["sections"]["prompts"]["status"] = "incomplete"
    monkeypatch.setattr(mcp_metadata_http, "CollectMcpMetadataHttp", lambda *a, **k: result)
    _, imported = RunMetadataImport(model)
    assert imported is not None and imported.state.revision == 1, "Partial evidence was lost"
    ApprovedMetadataScope(model, "other")
    evidence = LocalEvidenceStore(model.root / "evidence")
    acquisition = json.loads(evidence.Read(imported.evidence.reference))["acquisition"]
    assert acquisition["issues"] == [{"stage": "prompts", "reason": "timeout"}], (
        "The fixed incompleteness reason was not retained with the snapshot"
    )

    def DenyExchange(*args: object, **kwargs: object) -> None:
        """Prove a rejected selection never reaches the transport boundary."""

        pytest.fail("An unauthorized owner selection reached the HTTP collector")

    monkeypatch.setattr(mcp_metadata_http, "CollectMcpMetadataHttp", DenyExchange)

    with pytest.raises(McpMetadataDenied, match="explicit approval"):
        RunMetadataImport(model, revision=1, approved=False)

    with pytest.raises(WorkspaceConflictError, match="model revision changed"):
        RunMetadataImport(model)

    with pytest.raises(ValueError, match="endpoint selection is invalid"):
        RunMetadataImport(model, revision=1, endpoint=_LIVE_SOURCE.value + "?secret=canary")

    with pytest.raises(ValueError, match="already bound"):
        RunMetadataImport(model, revision=1, scopeId="other")

    assert model.Open() == imported.state, "A rejected selection changed the collected model"
    assert len(list((model.root / "evidence" / "records").iterdir())) == 1, (
        "A rejected selection created extra evidence"
    )


def test_MetadataScopeChangesAfterCollectionBeforeCommit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reopen the same scope after the final reply and refuse a changed owner basis."""

    model = CreateModel(tmp_path / "workspace")
    scope = ApprovedMetadataScope(model)
    result = FakeMetadata(scope)

    def ChangeScope(*args: object, **kwargs: object) -> McpMetadataResult:
        """Simulate an approved receipt update after the last network boundary."""

        LocalScopeStore(model.root).Save(replace(scope, authorization=ScopeAuthorization(
            AuthorizationState.GRANTED, "actor:operator", "consent:new-receipt",
        )))

        return result

    monkeypatch.setattr(mcp_metadata_http, "CollectMcpMetadataHttp", ChangeScope)

    with pytest.raises(McpMetadataDenied, match="exact scope"):
        RunMetadataImport(model)

    assert model.Open().revision == 0, "A stale scope allowed a model update"
    assert list((model.root / "evidence").iterdir()) == [], "A stale scope created evidence"


def test_ModelChangeDuringMetadataCollectionStopsNewEvidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preserve a competing local import when collection outlives its model CAS basis."""

    model = CreateModel(tmp_path / "workspace")
    scope = ApprovedMetadataScope(model)
    result = FakeMetadata(scope)

    def ChangeModel(*args: object, **kwargs: object) -> McpMetadataResult:
        """Commit an independent offline import before returning accepted metadata."""

        Import(_SOURCE, model, 0)

        return result

    monkeypatch.setattr(mcp_metadata_http, "CollectMcpMetadataHttp", ChangeModel)

    with pytest.raises(WorkspaceConflictError, match="model changed during"):
        RunMetadataImport(model)

    assert model.Open().revision == 1, "Collection overwrote the competing model transition"
    assert len(list((model.root / "evidence" / "records").iterdir())) == 1, (
        "Collection published evidence after discovering a stale model basis"
    )


def test_RevocationAfterEvidencePublicationLeavesTheModelUnchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Recheck publication authority after evidence Put and before model CAS."""

    model = CreateModel(tmp_path / "workspace")
    scope = ApprovedMetadataScope(model)
    result = FakeMetadata(scope)
    publish = LocalEvidenceStore.Put

    def PutThenRevoke(
        store: LocalEvidenceStore, data: bytes, role: str, mediaType: str,
        provenance: EvidenceProvenance,
    ) -> EvidenceRecord:
        """Revoke the exact scope once evidence publication has acknowledged."""

        record = publish(store, data, role, mediaType, provenance)
        LocalScopeStore(model.root).Save(replace(scope, authorization=ScopeAuthorization()))

        return record

    monkeypatch.setattr(mcp_metadata_http, "CollectMcpMetadataHttp", lambda *a, **k: result)
    monkeypatch.setattr(LocalEvidenceStore, "Put", PutThenRevoke)

    with pytest.raises(McpMetadataDenied, match="scope denied"):
        RunMetadataImport(model)

    assert model.Open().revision == 0, "Revoked scope still published a model transition"
    assert len(list((model.root / "evidence" / "records").iterdir())) == 1, (
        "Revocation erased independently published redacted evidence"
    )
