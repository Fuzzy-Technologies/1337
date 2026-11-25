# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal bounded saved SARIF source assertions and original-byte custody, without execution."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import cast

from fuzzy1337.adapters import EvidenceReference
from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.evidence import (
    EVIDENCE_MANIFEST_MAX_BYTES,
    EvidenceRecord,
    LocalEvidenceStore,
    ParseEvidenceManifest,
    RequireEvidenceDigest,
)
from fuzzy1337.scope import LocalScopeStore
from fuzzy1337.workspace import LocalWorkspaceStore

__all__ = ()

MAX_SOURCE_BYTES = 1024 * 1024
MAX_PROJECTION_BYTES = 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024
MAX_RESULTS = 256
SOURCE_ID = "bridge.sarif-local"
SOURCE_VERSION = "sarif-2.1.0-local-v1"
RAW_ROLE = "bridge-sarif-original"
RAW_MEDIA = "application/sarif+json"
RECEIPT_ROLE = "bridge-sarif-import-receipt"
PROFILE = "bridge-sarif-local-v1"


def JsonBytes(value: object) -> bytes:
    """Encode deterministic native JSON without interpreting source values.

    Args:
        value: Finite detached source or receipt fields.

    Returns:
        Canonical UTF-8 bytes with strict finite numbers.
    """

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def UniqueObject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate original or receipt keys before any source projection.

    Args:
        pairs: Original ordered JSON object members.

    Returns:
        Exact unique-key mapping without value-derived diagnostics.
    """

    value: dict[str, object] = {}

    for key, item in pairs:
        if key in value:
            raise ValueError("SARIF JSON contains duplicate keys")

        value[key] = item

    return value


def InvalidConstant(value: str) -> None:
    """Reject nonstandard JSON numbers without exposing source text.

    Args:
        value: Decoder constant token outside finite JSON.

    Raises:
        ValueError: Such tokens are outside this profile.
    """

    raise ValueError("SARIF JSON requires finite standard numbers")


def JsonDocument(raw: bytes, maximum: int) -> dict[str, object]:
    """Decode one complete bounded UTF-8 object with finite tree/string budgets.

    Args:
        raw: Complete original bytes or profile-controlled receipt.
        maximum: Owning role-specific byte ceiling.

    Returns:
        Detached object after full JSON completion and every tree-budget check.
    """

    if type(raw) is not bytes or not 1 <= len(raw) <= maximum:
        raise ValueError("SARIF JSON exceeds its byte profile")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=UniqueObject,
                           parse_constant=InvalidConstant)

    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("SARIF requires complete bounded UTF-8 JSON") from None

    pending = [(value, 0)]
    nodes = 0

    while pending:
        item, depth = pending.pop()
        nodes += 1

        if nodes > 20000 or depth > 24:
            raise ValueError("SARIF JSON exceeds its tree profile")

        if type(item) is dict:
            pending.extend((part, depth + 1) for part in item.values())
            pending.extend((key, depth + 1) for key in item)

        elif type(item) is list:
            pending.extend((part, depth + 1) for part in item)

        elif type(item) is str:
            SourceText(item, 65536)

        elif type(item) is float and not math.isfinite(item):
            raise ValueError("SARIF JSON requires finite standard numbers")

    return Object(value)


def Object(value: object) -> dict[str, object]:
    """Require a real decoded object without permissive coercion.

    Args:
        value: Selected original JSON value.

    Returns:
        Original string-keyed object.
    """

    if type(value) is not dict:
        raise ValueError("SARIF selected fields require an object")

    return cast(dict[str, object], value)


def Array(value: object, maximum: int) -> list[object]:
    """Require a bounded original array before iteration.

    Args:
        value: Selected source collection.
        maximum: Fixed inclusive collection ceiling.

    Returns:
        Original bounded collection, retaining order and duplicate results.
    """

    if type(value) is not list or len(value) > maximum:
        raise ValueError("SARIF collection exceeds its profile")

    return cast(list[object], value)


def SourceText(value: object, maximum: int = 4096) -> str:
    """Preserve exact source text, including escaped multiline messages, within a UTF-8 cap.

    Args:
        value: Literal source string; never a path to open or a URI to fetch.
        maximum: Inclusive UTF-8 byte ceiling.

    Returns:
        Unchanged valid source text, without terminal rendering or normalization.
    """

    if type(value) is not str:
        raise ValueError("SARIF selected text requires a string")

    try:
        size = len(value.encode("utf-8"))

    except UnicodeError:
        raise ValueError("SARIF text requires valid UTF-8") from None

    if size > maximum:
        raise ValueError("SARIF text exceeds its byte profile")

    return value


def OptionalText(value: dict[str, object], key: str) -> str | None:
    """Distinguish an omitted source field from an explicitly malformed value.

    Args:
        value: Selected source object.
        key: Fixed profile-owned property name.

    Returns:
        Exact declared string, or None only when the property was absent.
    """

    return SourceText(value[key]) if key in value else None


def Integer(value: object, minimum: int = 0) -> int:
    """Require exact bounded source indices or one-based coordinates.

    Args:
        value: Source integer, excluding booleans.
        minimum: Zero for indices, one for line/column coordinates.

    Returns:
        Unchanged integer within the profile's signed 32-bit coordinate bound.
    """

    if type(value) is not int or not minimum <= value <= 2147483647:
        raise ValueError("SARIF index or coordinate is outside its profile")

    return value


def ArtifactLocation(value: object, artifacts: list[object]) -> dict[str, object]:
    """Join only an in-document artifact index while never resolving a URI or filesystem path.

    Args:
        value: Original artifactLocation object.
        artifacts: Same-run bounded artifact table.

    Returns:
        Literal URI/base-ID declarations and index, with absent data kept unknown.
    """

    location = Object(value)
    uri = OptionalText(location, "uri")
    base = OptionalText(location, "uriBaseId")
    declaredUri = uri
    declaredBase = base
    index = None

    if "index" in location:
        index = Integer(location["index"])

        if index >= len(artifacts):
            raise ValueError("SARIF artifact index is unresolved")

        artifact = Object(artifacts[index])
        indexed = Object(artifact.get("location"))
        indexedUri = OptionalText(indexed, "uri")
        indexedBase = OptionalText(indexed, "uriBaseId")

        if uri is not None and indexedUri is not None and (uri, base) != (
            indexedUri, indexedBase
        ):
            raise ValueError("SARIF artifact URI and index disagree")

        if uri is None:
            uri, base = indexedUri, indexedBase

    if uri is None:
        raise ValueError("SARIF artifact location requires a URI or resolvable index")

    return {"uri": uri, "declared_uri": declaredUri, "uri_base_id": base,
            "declared_uri_base_id": declaredBase, "artifact_index": index}


def Location(value: object, artifacts: list[object]) -> dict[str, object]:
    """Preserve explicit source coordinates without reading a source file or guessing offsets.

    Args:
        value: Same-run source location.
        artifacts: Bounded original artifact table.

    Returns:
        Literal physical location fields; missing physical facts remain None.
    """

    location = Object(value)
    result: dict[str, object] = {
        "uri": None, "declared_uri": None, "uri_base_id": None,
        "declared_uri_base_id": None, "artifact_index": None,
        "start_line": None, "start_column": None, "end_line": None, "end_column": None,
    }

    if "physicalLocation" not in location:
        return result

    physical = Object(location["physicalLocation"])

    if "artifactLocation" in physical:
        result.update(ArtifactLocation(physical["artifactLocation"], artifacts))

    if "region" in physical:
        region = Object(physical["region"])

        for source, target in (("startLine", "start_line"), ("startColumn", "start_column"),
                               ("endLine", "end_line"), ("endColumn", "end_column")):
            if source in region:
                result[target] = Integer(region[source], 1)

        startLine = cast(int | None, result["start_line"])
        endLine = cast(int | None, result["end_line"])
        startColumn = cast(int | None, result["start_column"])
        endColumn = cast(int | None, result["end_column"])

        if startLine is not None and (
            (endLine is not None and endLine < startLine) or (
                endLine in (None, startLine) and startColumn is not None
                and endColumn is not None and endColumn < startColumn
            )
        ):
            raise ValueError("SARIF source region is contradictory")

    return result


def Result(value: object, rules: list[object], artifacts: list[object], index: int
           ) -> dict[str, object]:
    """Retain one source result rather than manufacturing a canonical finding or disposition.

    Args:
        value: Original result object.
        rules: Same-driver rule descriptors.
        artifacts: Same-run artifact table.
        index: Original zero-based result ordinal, including duplicate occurrences.

    Returns:
        Exact source claims and unknowns after selected-field admission.
    """

    result = Object(value)

    if "rule" in result:
        raise ValueError("SARIF component rule references are outside this profile")

    declaredRule = OptionalText(result, "ruleId")
    ruleId = declaredRule

    if ruleId == "":
        raise ValueError("SARIF source rule ID must be nonempty")

    ruleIndex = None if "ruleIndex" not in result else Integer(result["ruleIndex"], -1)
    descriptorId = None

    if ruleIndex is not None and ruleIndex >= 0:
        if ruleIndex >= len(rules):
            raise ValueError("SARIF rule index is unresolved")

        descriptorId = SourceText(Object(rules[ruleIndex]).get("id"))

        if ruleId is not None and ruleId != descriptorId:
            prefix = descriptorId + "/"

            if not ruleId.startswith(prefix) or not ruleId[len(prefix):] or (
                "/" in ruleId[len(prefix):]
            ):
                raise ValueError("SARIF rule ID and index disagree")

        if ruleId is None:
            ruleId = descriptorId

    message = Object(result.get("message"))
    text = OptionalText(message, "text")
    markdown = OptionalText(message, "markdown")
    messageId = OptionalText(message, "id")

    if text is None and markdown is None and messageId is None:
        raise ValueError("SARIF result requires a source message")

    level = OptionalText(result, "level")
    kind = OptionalText(result, "kind")
    baseline = OptionalText(result, "baselineState")

    if level not in (None, "none", "note", "warning", "error") or kind not in (
        None, "notApplicable", "pass", "fail", "review", "open", "informational"
    ) or baseline not in (None, "new", "unchanged", "updated", "absent"):
        raise ValueError("SARIF result classification is outside its source profile")

    if kind not in (None, "fail") and level not in (None, "none"):
        raise ValueError("SARIF result kind and level disagree")

    suppressions: list[dict[str, object]] | None = None

    if "suppressions" in result:
        suppressions = []

        for item in Array(result["suppressions"], 16):
            suppression = Object(item)
            sourceKind = SourceText(suppression.get("kind"))
            status = OptionalText(suppression, "status")

            if sourceKind not in ("inSource", "external") or status not in (
                None, "accepted", "underReview", "rejected"
            ):
                raise ValueError("SARIF suppression classification is unsupported")

            suppressions.append({"kind": sourceKind, "status": status})

    locations = None if "locations" not in result else [
        Location(item, artifacts) for item in Array(result["locations"], 16)
    ]

    return {"result_index": index, "rule_id": ruleId, "declared_rule_id": declaredRule,
            "rule_index": ruleIndex, "descriptor_id": descriptorId,
            "message_text": text, "message_markdown": markdown,
            "message_id": messageId, "source_level": level, "source_kind": kind,
            "baseline_state": baseline, "suppressions": suppressions, "locations": locations}


def ParseSarif(raw: bytes) -> dict[str, object]:
    """Project only bounded inline SARIF 2.1.0 source assertions after complete original decoding.

    Args:
        raw: Exact caller-supplied original log bytes, never a path or remote locator.

    Returns:
        Ordered source runs/results, without effective defaults, risk or canonical findings.
    """

    document = JsonDocument(raw, MAX_SOURCE_BYTES)

    if document.get("version") != "2.1.0" or "inlineExternalProperties" in document:
        raise ValueError("SARIF requires the supported self-contained version 2.1.0 profile")

    runs: list[dict[str, object]] = []
    total = 0
    projectionBytes = 0

    for runIndex, item in enumerate(Array(document.get("runs"), 16)):
        run = Object(item)

        if "externalPropertyFileReferences" in run:
            raise ValueError("SARIF external property files are outside this profile")

        tool = Object(run.get("tool"))

        if "extensions" in tool and tool["extensions"] != []:
            raise ValueError("SARIF tool extensions are outside this profile")

        driver = Object(tool.get("driver"))
        name = SourceText(driver.get("name"))

        if not name:
            raise ValueError("SARIF requires a declared tool name")

        rules = Array(driver.get("rules", []), 1024)
        for rule in rules:
            if not SourceText(Object(rule).get("id")):
                raise ValueError("SARIF driver rules require nonempty IDs")

        artifacts = Array(run.get("artifacts", []), 1024)
        columnKind = OptionalText(run, "columnKind")

        if columnKind not in (None, "utf16CodeUnits", "unicodeCodePoints"):
            raise ValueError("SARIF column kind is unsupported")

        results: list[dict[str, object]] | None = None

        if run.get("results") is not None:
            results = []

            for resultIndex, entry in enumerate(Array(run["results"], MAX_RESULTS)):
                total += 1

                if total > MAX_RESULTS:
                    raise ValueError("SARIF inline results exceed the profile")

                selected = Result(entry, rules, artifacts, resultIndex)
                projectionBytes += len(JsonBytes(selected))

                if projectionBytes > MAX_PROJECTION_BYTES:
                    raise ValueError("SARIF selected facts exceed their byte profile")

                results.append(selected)

        invocations: list[dict[str, object]] | None = None

        if "invocations" in run:
            invocations = []

            for invocation in Array(run["invocations"], 16):
                declared = Object(invocation)
                success = declared.get("executionSuccessful")

                if "executionSuccessful" in declared and type(success) is not bool:
                    raise ValueError("SARIF declared execution status requires a boolean")

                invocations.append({"declared_execution_successful": success})

        runs.append({"run_index": runIndex, "tool_name": name,
            "tool_version": OptionalText(driver, "version"),
            "tool_semantic_version": OptionalText(driver, "semanticVersion"),
            "column_kind": columnKind, "invocations": invocations, "results": results})

    projection = {"sarif_version": "2.1.0", "runs": runs,
                  "inline_result_count": total, "validation_scope": "consumed-fields-only"}

    if len(JsonBytes(projection)) > MAX_PROJECTION_BYTES:
        raise ValueError("SARIF selected facts exceed their byte profile")

    return projection


class BoundedSarifStore(LocalEvidenceStore):
    """Apply fixed owning role/media/byte ceilings before implicit raw-body verification."""

    def __init__(self, root: Path, role: str, maximum: int) -> None:
        """Select one profile-owned artifact domain, independent of untrusted manifest claims.

        Args:
            root: Existing owning evidence directory.
            role: Fixed original or receipt role.
            maximum: Fixed role-specific byte ceiling.
        """

        super().__init__(root)
        self.role = role
        self.maximum = maximum

    def Read(self, reference: EvidenceReference) -> bytes:
        """Reject wrong-role or oversized artifacts before the owning reader consumes their bytes.

        Args:
            reference: Untrusted selected reference supplied by the owning manifest decoder.

        Returns:
            Hash-verified original bytes within the fixed expected artifact domain.
        """

        media = RAW_MEDIA if self.role == RAW_ROLE else "application/json"

        if type(reference) is not EvidenceReference or reference.role != self.role or (
            reference.media_type != media or reference.size_bytes > self.maximum
        ):
            raise ValueError("SARIF evidence is outside its selected role profile")

        return super().Read(reference)

    def Manifest(self, evidenceId: str) -> EvidenceRecord:
        """Preflight exact profile/manifest identity without reading its referenced raw body.

        Args:
            evidenceId: Explicit immutable original or receipt manifest identifier.

        Returns:
            Parsed original metadata for complete context checks before owning Get verification.
        """

        if type(evidenceId) is not str or not evidenceId.startswith("sha256:"):
            raise ValueError("SARIF custody requires exact manifest roots")

        RequireEvidenceDigest(evidenceId[7:])
        payload = self.ReadStoredBytes(("records", evidenceId[7:] + ".json"),
                                       EVIDENCE_MANIFEST_MAX_BYTES)
        record = ParseEvidenceManifest(payload)
        media = RAW_MEDIA if self.role == RAW_ROLE else "application/json"
        source = record.provenance

        if record.evidence_id != evidenceId or record.reference.role != self.role or (
            record.reference.media_type != media or record.reference.size_bytes > self.maximum
            or source.source_id != SOURCE_ID or source.source_version != SOURCE_VERSION
            or source.tool_version is not None or source.invocation_sha256 is not None
            or source.execution is not None
        ):
            raise ValueError("SARIF original manifest disagrees with the selected profile")

        return record


def ReceiptContent(original: EvidenceRecord, consent: ArtifactReadConsent,
                   projection: dict[str, object]) -> dict[str, object]:
    """Bind exact original custody, declared read descriptions and deterministic source projection.

    Args:
        original: Confirmed original product acquisition.
        consent: Original non-secret actor/read-record descriptions, not a new read grant.
        projection: Complete pure reparse of exactly those retained source bytes.

    Returns:
        Closed receipt content; receipt publication acknowledgement remains outcome-only.
    """

    return {"schema_version": 1, "profile": PROFILE, "original_id": original.evidence_id,
            "original_sha256": original.reference.sha256,
            "projection_sha256": hashlib.sha256(JsonBytes(projection)).hexdigest(),
            "owner_reference": consent.actor_ref, "read_consent_reference": consent.record_ref}


def LoadSavedSarif(root: Path, originalId: str, receiptId: str,
                   expectedSha256: str) -> tuple[dict[str, object], EvidenceRecord, EvidenceRecord]:
    """Verify explicit original/receipt roots and fully reparse source facts without writes or time.

    Args:
        root: Existing owning workspace, including a relocated copy.
        originalId: Independently retained original manifest identity.
        receiptId: Independently retained successful product receipt identity.
        expectedSha256: Caller-selected original-byte pin, never taken from candidate content.

    Returns:
        Complete source projection and exact owning original/receipt records after verification.
    """

    RequireEvidenceDigest(expectedSha256)
    workspace = LocalWorkspaceStore(root).Open()
    originals = BoundedSarifStore(root / "evidence", RAW_ROLE, MAX_SOURCE_BYTES)
    receipts = BoundedSarifStore(root / "evidence", RECEIPT_ROLE, MAX_RECEIPT_BYTES)
    original = originals.Manifest(originalId)
    receipt = receipts.Manifest(receiptId)
    source = original.provenance

    if original.provenance != receipt.provenance or (
        source.workspace_id != workspace.workspace_id or source.source_id != SOURCE_ID
        or source.source_version != SOURCE_VERSION or source.tool_version is not None
        or source.invocation_sha256 is not None or source.execution is not None
        or original.reference.sha256 != expectedSha256
        or not source.scope_reference.startswith("scope:")
    ):
        raise ValueError("SARIF original custody has incompatible attribution")

    scope = LocalScopeStore(root).Open(source.scope_reference[6:])

    if scope.workspace_id != workspace.workspace_id:
        raise ValueError("SARIF original scope belongs to another workspace")

    if originals.Get(originalId) != original or receipts.Get(receiptId) != receipt:
        raise ValueError("SARIF original manifests changed during owning verification")

    terminal = JsonDocument(receipts.Read(receipt.reference), MAX_RECEIPT_BYTES)
    consent = ArtifactReadConsent(cast(str, terminal.get("owner_reference")),
                                  cast(str, terminal.get("read_consent_reference")))
    projection = ParseSarif(originals.Read(original.reference))
    expected = ReceiptContent(original, consent, projection)

    if type(terminal.get("schema_version")) is not int or (
        JsonBytes(terminal) != JsonBytes(expected)
    ):
        raise ValueError("SARIF original receipt disagrees with complete source reparse")

    return projection, original, receipt
