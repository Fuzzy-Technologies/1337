# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bounded original SARIF source facts, exact custody joins and inert external locators."""

from __future__ import annotations

import builtins
import hashlib
import json
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import pytest

from fuzzy1337 import bridge_sarif as sarif
from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.evidence import LocalEvidenceStore
from tests.sarif_helpers import (
    SHA256, Document, Files, Golden, ImportArguments, InspectArguments, Owned, Raw, Run,
)


def Encoded(document):
    """Encode an independently mutated source without using the production parser."""

    return json.dumps(document, ensure_ascii=False).encode("utf-8")


def Row(document):
    """Select the one source row of the official sample for a local boundary mutation."""

    return document["runs"][0]["results"][0]


def Artifact(document):
    """Select the original physical locator without opening its declared Windows file."""

    return Row(document)["locations"][0]["physicalLocation"]["artifactLocation"]


def test_OfficialExternalSamplePreservesGoldenFieldsWithoutAnyDereference(monkeypatch):
    """The producer's locators remain inert while exact source facts are projected."""

    raw = Raw()
    expected = Golden()
    assert hashlib.sha256(raw).hexdigest() == SHA256, "Retain the pinned external body"

    def Denied(*arguments, **options):
        """Trip any attempted source-file/schema/help read during pure source normalization."""

        raise AssertionError("A saved SARIF source URI was dereferenced")

    monkeypatch.setattr(builtins, "open", Denied)
    monkeypatch.setattr(Path, "open", Denied)
    assert sarif.ParseSarif(raw) == expected, "The external source-fact oracle changed"


@pytest.mark.parametrize("raw", [
    b"", b"{", b"\xff", b"[]", b'{"version":"2.1.0","version":"2.1.0","runs":[]}',
    b'{"version":"2.1.0","runs":[],"ignored":NaN}',
    b'{"version":"2.1.0","runs":[],"ignored":1e999}',
    b'{"version":"2.1.0","runs":[],"ignored":"\uD800"}',
    b"x" * (1024 * 1024 + 1),
], ids=["empty", "truncated", "utf8", "root-array", "duplicate-key", "nan", "overflow",
        "surrogate", "byte-limit"])
def test_OriginalJsonRefusesBeforeAnyProjection(raw):
    """Full original syntax/encoding/byte validation cannot become a partially usable log."""

    with pytest.raises(ValueError):
        sarif.ParseSarif(raw)


@pytest.mark.parametrize("fault", [
    "version", "runs", "driver", "name", "extensions", "external", "inline-external",
    "rules", "rule-id", "artifacts", "column-kind", "results", "message", "message-null",
    "rule-bool", "rule-range", "rule-negative", "rule-mismatch", "empty-rule",
    "level", "kind", "baseline", "kind-level", "suppression-kind", "suppression-status",
    "suppression-array", "location-array", "physical", "artifact-bool", "artifact-negative",
    "artifact-range", "artifact-conflict", "artifact-missing", "line-zero", "line-bool",
    "backwards-region", "backwards-column", "invocation-array", "invocation-success",
])
def test_SelectedSourceShapesRefuseTheWholeLog(fault):
    """Each admitted source field has its own finite type, index, enum or relationship boundary."""

    document = Document()
    run = document["runs"][0]
    row = Row(document)
    location = Artifact(document)
    region = row["locations"][0]["physicalLocation"]["region"]

    if fault == "version":
        document["version"] = "2.0"

    elif fault == "runs":
        document["runs"] = {}

    elif fault == "driver":
        run["tool"]["driver"] = None

    elif fault == "name":
        run["tool"]["driver"]["name"] = ""

    elif fault == "extensions":
        run["tool"]["extensions"] = [{"name": "external"}]

    elif fault == "external":
        run["externalPropertyFileReferences"] = {"results": [{"location": {
            "uri": "https://never-fetch.invalid/external.sarif"}}]}

    elif fault == "inline-external":
        document["inlineExternalProperties"] = []

    elif fault == "rules":
        run["tool"]["driver"]["rules"] = {}

    elif fault == "rule-id":
        run["tool"]["driver"]["rules"] = [{}]

    elif fault == "artifacts":
        run["artifacts"] = {}

    elif fault == "column-kind":
        run["columnKind"] = "bytes"

    elif fault == "results":
        run["results"] = {}

    elif fault == "message":
        row["message"] = {}

    elif fault == "message-null":
        row["message"] = {"text": None}

    elif fault == "rule-bool":
        row["ruleIndex"] = True

    elif fault == "rule-range":
        row["ruleIndex"] = 1

    elif fault == "rule-negative":
        row["ruleIndex"] = -2

    elif fault == "rule-mismatch":
        row["ruleId"] = "different"

    elif fault == "empty-rule":
        row["ruleId"] = ""

    elif fault == "level":
        row["level"] = "critical"

    elif fault == "kind":
        row["kind"] = "vulnerability"

    elif fault == "baseline":
        row["baselineState"] = "resolved"

    elif fault == "kind-level":
        row["kind"] = "pass"

    elif fault == "suppression-kind":
        row["suppressions"] = [{"kind": "dismissed"}]

    elif fault == "suppression-status":
        row["suppressions"] = [{"kind": "external", "status": "confirmed"}]

    elif fault == "suppression-array":
        row["suppressions"] = {}

    elif fault == "location-array":
        row["locations"] = {}

    elif fault == "physical":
        row["locations"][0]["physicalLocation"] = []

    elif fault == "artifact-bool":
        location["index"] = False

    elif fault == "artifact-negative":
        location["index"] = -1

    elif fault == "artifact-range":
        location["index"] = 1

    elif fault == "artifact-conflict":
        location["uri"] = "file:///different-source.py"

    elif fault == "artifact-missing":
        row["locations"][0]["physicalLocation"]["artifactLocation"] = {}

    elif fault == "line-zero":
        region["startLine"] = 0

    elif fault == "line-bool":
        region["startColumn"] = True

    elif fault == "backwards-region":
        region.update({"startLine": 2, "endLine": 1})

    elif fault == "backwards-column":
        region.update({"startColumn": 5, "endColumn": 4})

    elif fault == "invocation-array":
        run["invocations"] = {}

    else:
        run["invocations"] = [{"executionSuccessful": None}]

    with pytest.raises(ValueError):
        sarif.ParseSarif(Encoded(document))


def test_DuplicateDescriptorIdsSubruleAndIndexOnlyLocationKeepActualSourceOrdinals():
    """An explicit index selects the second descriptor/artifact, with no first-ID or path guess."""

    document = Document()
    run = document["runs"][0]
    run["tool"]["driver"]["rules"] = [{"id": "demo-rule"}, {"id": "demo-rule"}]
    run["artifacts"] = [{"location": {"uri": "first.py"}},
        {"location": {"uri": "second.py", "uriBaseId": "SRCROOT"}}]
    row = Row(document)
    row.update({"ruleId": "demo-rule/variant", "ruleIndex": 1})
    row["locations"][0]["physicalLocation"] = {
        "artifactLocation": {"index": 1},
        "region": {"startLine": 1, "startColumn": 1, "endColumn": 2},
    }
    run["results"].append(json.loads(json.dumps(row)))
    run["columnKind"] = "utf16CodeUnits"
    projected = sarif.ParseSarif(Encoded(document))["runs"][0]
    rows = projected["results"]
    assert [item["result_index"] for item in rows] == [0, 1], "Do not deduplicate source results"
    assert rows[0]["rule_id"] == "demo-rule/variant" and rows[0]["rule_index"] == 1, (
        "Preserve hierarchical source rule IDs and zero-based descriptor indices"
    )
    location = rows[0]["locations"][0]
    assert location == {"uri": "second.py", "declared_uri": None, "uri_base_id": "SRCROOT",
        "declared_uri_base_id": None, "artifact_index": 1, "start_line": 1, "start_column": 1,
        "end_line": None, "end_column": 2}, "Join only the indexed in-document declaration"
    assert projected["column_kind"] == "utf16CodeUnits", "Preserve declared column interpretation"


def test_MissingClassificationsLocationsAndResultsStayUnknownRatherThanCleanOrConfirmed():
    """Absence, empty arrays and source review/suppression claims stay distinct."""

    document = Document()
    run = document["runs"][0]
    row = Row(document)
    row.pop("level")
    row.pop("ruleId")
    row["ruleIndex"] = -1
    row["message"] = {"id": "message-key", "markdown": "Literal **source**"}
    row["locations"] = [{}, {"physicalLocation": {"region": {"startLine": 2}}}]
    row["kind"] = "review"
    row["baselineState"] = "absent"
    row["suppressions"] = [{"kind": "external", "status": "accepted"}, {"kind": "inSource"}]
    run["invocations"] = [{"executionSuccessful": False}, {}]
    second = json.loads(json.dumps(run))
    second["results"] = []
    third = json.loads(json.dumps(run))
    third.pop("results")
    fourth = json.loads(json.dumps(run))
    fourth["results"] = None
    document["runs"] += [second, third, fourth]
    parsed = sarif.ParseSarif(Encoded(document))
    selected = parsed["runs"][0]["results"][0]
    assert selected["source_level"] is None and selected["rule_id"] is None, (
        "Do not compute source severity defaults or rule IDs from missing declarations"
    )
    assert selected["message_text"] is None and selected["source_kind"] == "review", (
        "Source review/message-ID assertions must not become confirmed findings"
    )
    assert selected["locations"][0]["uri"] is None and selected["locations"][1][
        "start_column"
    ] is None, "Missing physical coordinates must not become guessed files or column one"
    assert [entry["results"] for entry in parsed["runs"][1:]] == [[], None, None], (
        "Empty reported results and unavailable result sets cannot become one clean-state claim"
    )
    assert parsed["runs"][0]["invocations"] == [
        {"declared_execution_successful": False}, {"declared_execution_successful": None}
    ], "Preserve source failure without inventing a local executor outcome"


@pytest.mark.parametrize("fault", ["depth", "nodes", "string", "runs", "rules", "artifacts",
                                  "locations", "results", "total-results", "projection"])
def test_FixedInputAndProjectionBudgetsRefuseActualExcess(fault):
    """Original and index-amplified projections have independent real resource ceilings."""

    document = Document()
    run = document["runs"][0]

    if fault == "depth":
        nested = []

        for _ in range(25):
            nested = [nested]

        document["ignored"] = nested

    elif fault == "nodes":
        document["ignored"] = [None] * 20001

    elif fault == "string":
        document["ignored"] = "x" * 65537

    elif fault == "runs":
        document["runs"] *= 17

    elif fault == "rules":
        run["tool"]["driver"]["rules"] = [{"id": "rule"}] * 1025

    elif fault == "artifacts":
        run["artifacts"] *= 1025

    elif fault == "locations":
        Row(document)["locations"] *= 17

    elif fault == "results":
        run["results"] *= 257

    elif fault == "total-results":
        run["results"] *= 129
        document["runs"].append(json.loads(json.dumps(run)))

    else:
        run["artifacts"][0]["location"]["uri"] = "x" * 4096
        location = {"physicalLocation": {"artifactLocation": {"index": 0}}}
        Row(document)["locations"] = [location] * 16
        run["results"] *= 25

    with pytest.raises(ValueError):
        sarif.ParseSarif(Encoded(document))


def test_RetainedOriginalReopensWithoutSourceTimeOrOwnerWrites(tmp_path, monkeypatch):
    """Original custody survives caller-file deletion and relocation without acquisition."""

    root, source = Owned(tmp_path)
    status, imported = Run(ImportArguments(root, source))
    assert status == 0, "Acquire the existing external report before testing exact original replay"
    source.unlink()
    moved = tmp_path / "moved"
    root.rename(moved)
    before = Files(moved)

    def Denied(*arguments, **options):
        """Reject hidden persistence or file-copy clocks during read-only original verification."""

        raise AssertionError("Retained SARIF inspection attempted new acquisition or persistence")

    monkeypatch.setattr(LocalEvidenceStore, "Put", Denied)
    status, inspected = Run(InspectArguments(moved, imported), clock=Denied)
    assert status == 0 and inspected["projection"] == Golden(), "Reparse retained source facts"
    assert inspected["ack_basis"] == "verified-present" and Files(moved) == before, (
        "Inspection must leave every saved owner byte unchanged and preserve ACK meanings"
    )


@pytest.mark.parametrize("fault", ["pin", "mixed", "raw", "receipt", "receipt-body", "wrong-role",
                                  "source", "version", "provider", "execution", "foreign", "scope"])
def test_RetainedCustodyCannotBorrowDifferentOriginalContext(tmp_path, fault):
    """Changed original bytes or attribution cannot produce partial source facts."""

    root, source = Owned(tmp_path)
    status, imported = Run(ImportArguments(root, source), clock=lambda: datetime.fromisoformat(
        "2026-11-25T12:00:00+00:00"))
    assert status == 0, "The negative must start from actual acknowledged product custody"
    store = LocalEvidenceStore(root / "evidence")
    original = store.Get(imported["original_id"])
    receipt = store.Get(imported["receipt_id"])
    arguments = InspectArguments(root, imported)

    if fault == "pin":
        arguments[-1] = "a" * 64

    elif fault in ("raw", "receipt"):
        record = original if fault == "raw" else receipt
        (root / "evidence" / record.reference.locator).write_bytes(b"corrupt original")

    elif fault == "mixed":
        status, other = Run(ImportArguments(root, source), clock=lambda: datetime.fromisoformat(
            "2026-11-25T12:00:01+00:00"))
        assert status == 0, "Create a distinct genuine acquisition for the splice refusal"
        arguments[arguments.index("--receipt") + 1] = other["receipt_id"]

    elif fault == "receipt-body":
        body = json.loads(store.Read(receipt.reference))
        body["projection_sha256"] = "a" * 64
        alternate = store.Put(sarif.JsonBytes(body), sarif.RECEIPT_ROLE, "application/json",
                              receipt.provenance)
        arguments[arguments.index("--receipt") + 1] = alternate.evidence_id

    else:
        changes = {
            "source": {"source_id": "other"},
            "version": {"source_version": "other"},
            "provider": {"tool_version": "borrowed"},
            "execution": {"invocation_sha256": "a" * 64,
                          "execution": AdapterExecution(ExecutionState.FAILED, 7, 0.125)},
            "foreign": {"workspace_id": "foreign"},
            "scope": {"scope_reference": "scope:missing"},
        }
        provenance = replace(original.provenance, **changes.get(fault, {}))
        role = "stdout" if fault == "wrong-role" else sarif.RAW_ROLE
        alternate = store.Put(Raw(), role, sarif.RAW_MEDIA, provenance)
        body = sarif.ReceiptContent(alternate, ArtifactReadConsent(
            "operator:owned", "consent:owned"), Golden())
        alternateReceipt = store.Put(sarif.JsonBytes(body), sarif.RECEIPT_ROLE,
                                     "application/json", provenance)
        arguments[arguments.index("--original") + 1] = alternate.evidence_id
        arguments[arguments.index("--receipt") + 1] = alternateReceipt.evidence_id

    before = Files(root)
    status, refused = Run(arguments)
    assert status == 4 and "projection" not in refused, "Unverified custody must emit no assertions"
    assert Files(root) == before, "A refused original replay must not mutate stored owners"


def test_DirectAndIndexedRuleLocationsPreserveOnlyActuallyKnownFields():
    """Omitted index/URI/message text and explicit source success have separate meanings."""

    document = Document()
    run = document["runs"][0]
    run["tool"]["extensions"] = []
    run["tool"]["driver"].update({"version": "1.2.3", "semanticVersion": "1.2.3+source"})
    run["columnKind"] = "unicodeCodePoints"
    run["invocations"] = [{"executionSuccessful": True}]
    run["results"] = [
        {"ruleId": "declared-only", "message": {"text": "Literal\nsource é 😀"}},
        {"ruleIndex": 0, "message": {"id": "message-id"}, "kind": "pass", "level": "none",
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "relative.py"}}}]},
    ]
    projected = sarif.ParseSarif(Encoded(document))["runs"][0]
    first, second = projected["results"]
    assert first["locations"] is None and first["rule_index"] is None and (
        first["message_text"] == "Literal\nsource é 😀"
    ), "Keep source omissions and multiline Unicode assertions without defaulting"
    assert second["rule_id"] == "no-unused-vars" and second["declared_rule_id"] is None, (
        "A descriptor index can supply only the same-run source rule identity"
    )
    assert second["locations"][0]["start_line"] is None and second["locations"][0][
        "artifact_index"
    ] is None, "Direct URI declarations must not acquire synthetic coordinates or indices"
    assert projected["invocations"] == [{"declared_execution_successful": True}], (
        "Retain the producer's claim without constructing an executor report"
    )


def test_ForeignOriginalContextRefusesBeforeAnyRawBodyRead(tmp_path, monkeypatch):
    """Manifest/schema/context checks precede the generic evidence owner's eager blob checks."""

    root, source = Owned(tmp_path)
    status, imported = Run(ImportArguments(root, source))
    assert status == 0, "Acquire exact owned source custody before the foreign-context probe"
    store = LocalEvidenceStore(root / "evidence")
    original = store.Get(imported["original_id"])
    foreign = replace(original.provenance, workspace_id="foreign")
    changed = store.Put(Raw(), sarif.RAW_ROLE, sarif.RAW_MEDIA, foreign)
    body = sarif.ReceiptContent(changed, ArtifactReadConsent(
        "operator:owned", "consent:owned"), Golden())
    receipt = store.Put(sarif.JsonBytes(body), sarif.RECEIPT_ROLE, "application/json", foreign)

    def Denied(*arguments, **options):
        """Expose an eager original or receipt body read before owner-context refusal."""

        raise AssertionError("Foreign source metadata reached raw-body reads")

    monkeypatch.setattr(sarif.BoundedSarifStore, "Read", Denied)

    with pytest.raises(ValueError):
        sarif.LoadSavedSarif(root, changed.evidence_id, receipt.evidence_id, SHA256)


@pytest.mark.parametrize("field,value", [
    ("role", "stdout"), ("media_type", "text/plain"), ("size_bytes", 1024 * 1024 + 1),
])
def test_ProfileReaderRefusesUnrelatedOrOversizedReferencesBeforeOwnerReads(
    tmp_path, monkeypatch, field, value,
):
    """An implicit Get cannot choose a broader content budget through an untrusted reference."""

    root, source = Owned(tmp_path)
    status, imported = Run(ImportArguments(root, source))
    assert status == 0, "Acquire an actual original handle before varying the selected role"
    original = LocalEvidenceStore(root / "evidence").Get(imported["original_id"])
    reader = sarif.BoundedSarifStore(root / "evidence", sarif.RAW_ROLE, sarif.MAX_SOURCE_BYTES)

    def Denied(*arguments, **options):
        """Trip any generic blob read after failed role/media/size preflight."""

        raise AssertionError("Wrong SARIF role reached generic owner reads")

    monkeypatch.setattr(LocalEvidenceStore, "Read", Denied)

    with pytest.raises(ValueError):
        reader.Read(replace(original.reference, **{field: value}))


def test_DeclaredIndexOrCoordinatesNeverCoerceBooleansOrOverlargePositions():
    """Upper bounds and one additional hierarchical rule component remain exact source contracts."""

    document = Document()
    row = Row(document)
    row["locations"][0]["physicalLocation"]["region"]["startLine"] = 2147483647
    assert sarif.ParseSarif(Encoded(document))["runs"][0]["results"][0]["locations"][0][
        "start_line"
    ] == 2147483647, "Admit the inclusive configured coordinate ceiling"
    row["locations"][0]["physicalLocation"]["region"]["startLine"] += 1

    with pytest.raises(ValueError):
        sarif.ParseSarif(Encoded(document))

    row["locations"][0]["physicalLocation"]["region"]["startLine"] = 1
    row["ruleId"] += "/"

    with pytest.raises(ValueError):
        sarif.ParseSarif(Encoded(document))

    row["ruleId"] += "component/another"

    with pytest.raises(ValueError):
        sarif.ParseSarif(Encoded(document))
