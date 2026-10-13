# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental verified static HTML candidates without transport or browser authority."""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from types import MappingProxyType
from urllib.parse import urljoin, urlsplit

from fuzzy1337.adapters import AdapterExecution, EvidenceReference, ExecutionState
from fuzzy1337.adapters.contracts import RequireIdentifier
from fuzzy1337.evidence import (
    EvidenceError,
    EvidenceProvenance,
    EvidenceRecord,
    LocalEvidenceStore,
)
from fuzzy1337.model import (
    CanonicalModelJson,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    Observation,
    SecurityObject,
)
from fuzzy1337.requests import (
    BodyKind,
    Endpoint,
    ProjectRequests,
    RequestsFromObject,
    RequestTemplate,
)
from fuzzy1337.scope import (
    LocalScopeStore,
    NormalizeTime,
    ScopeDecision,
    ScopeDecisionReason,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore, RequireWorkspaceInteger

CAPTURED_WEB_PROFILE_VERSION = 1
MAX_BODY_BYTES = 256 * 1024
MAX_TOKEN_BYTES = 4096
MAX_MARKUP_TOKENS = 8192
MAX_ANCHORS = 1024
MAX_ATTRIBUTES = 64
MAX_HREF_BYTES = 2048
MAX_METADATA_BYTES = 256
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_START_TAG = re.compile(r"<[A-Za-z][A-Za-z0-9:-]*(?=[\t\r\n\f />])")
_END_TAG = re.compile(r"</[A-Za-z][A-Za-z0-9:-]*[\t\r\n\f ]*>\Z")
_INVALID_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")
_RAW_CLOSE = MappingProxyType({
    name: re.compile(r"</" + name + r"(?=[\t\r\n\f />])", flags=re.IGNORECASE | re.ASCII)
    for name in ("script", "style")
})
_REJECTIONS = frozenset({
    "missing-href", "invalid-url", "fragment-only", "non-http", "credentials", "query",
    "off-origin", "unsupported-path", "source-target",
    *("scope." + item.value for item in ScopeDecisionReason
      if item is not ScopeDecisionReason.ALLOWED),
})
__all__ = [
    "CAPTURED_WEB_PROFILE_VERSION", "CapturedWebLimits", "CapturedWebFrontier",
    "CapturedWebEntry", "CapturedWebProjection", "ReadCapturedWebFrontier",
    "ProjectCapturedWebFrontier",
]


def WebInteger(value: object, minimum: int, maximum: int) -> int:
    """Require exact bounded integers without bool equality or numeric coercion.

    Args:
        value: Caller count or finite profile limit.
        minimum: Inclusive lower bound.
        maximum: Inclusive upper bound.

    Returns:
        The original exact integer.

    Raises:
        ValueError: Type or range is outside the declared profile.
    """

    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("captured web integer is outside its declared bounds")

    return value


def WebText(value: object, maximum: int = MAX_METADATA_BYTES) -> str:
    """Bound string work before encoding and reject multiline or malformed metadata.

    Args:
        value: Explicit non-secret metadata or source structural text.
        maximum: Inclusive UTF-8 byte ceiling.

    Returns:
        Original bounded text, without substituting or stripping characters.

    Raises:
        ValueError: Text is empty, oversized, malformed or control-bearing.
    """

    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError("captured web text is outside its declared bounds")

    try:
        valid = len(value.encode("utf-8")) <= maximum

    except UnicodeError:
        valid = False

    if not valid or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("captured web text must be bounded valid single-line UTF-8")

    return value


def WebDigest(value: object, *, prefixed: bool = False) -> str:
    """Validate a fixed-length digest before any object lookup or nested hashing.

    Args:
        value: Canonical digest or sha256 manifest/content identity.
        prefixed: Whether sha256: is required before the hexadecimal digest.

    Returns:
        Original validated identity.

    Raises:
        ValueError: The identity is noncanonical or has an unexpected namespace.
    """

    length = 71 if prefixed else 64

    if not isinstance(value, str) or len(value) != length or (
        prefixed and not value.startswith("sha256:")
    ) or not _DIGEST.fullmatch(value[7:] if prefixed else value):
        raise ValueError("captured web requires a canonical SHA-256 identity")

    return value


def WebCapture(record: object) -> EvidenceRecord:
    """Validate bounded nested caller metadata before recomputing its owning manifest identity.

    Args:
        record: Explicit supplied immutable capture record, not transport authentication.

    Returns:
        Exact record after complete typed metadata and owning identity validation.

    Raises:
        ValueError: Shape, bounds, chronology or acquisition outcome is unsupported.
    """

    if type(record) is not EvidenceRecord or type(record.reference) is not EvidenceReference or (
        type(record.provenance) is not EvidenceProvenance
    ):
        raise ValueError("captured web requires exact typed evidence metadata")

    WebInteger(record.schema_version, 1, 1)
    reference = record.reference
    WebDigest(reference.sha256)
    WebDigest(record.evidence_id, prefixed=True)
    WebInteger(reference.size_bytes, 0, MAX_BODY_BYTES)

    if reference.locator != "blobs/sha256/" + reference.sha256 or (
        reference.role != "response-body" or reference.media_type != "text/html"
    ):
        raise ValueError("captured web requires its exact HTML body evidence profile")

    provenance = record.provenance

    for name in ("workspace_id", "scope_reference", "source_id", "source_version",
                 "started_at", "finished_at"):
        WebText(getattr(provenance, name))

    RequireIdentifier(provenance.source_id, "source_id")

    if provenance.tool_version is not None:
        WebText(provenance.tool_version)

    if provenance.invocation_sha256 is not None:
        WebDigest(provenance.invocation_sha256)

    started = datetime.fromisoformat(provenance.started_at)
    finished = datetime.fromisoformat(provenance.finished_at)

    if started.tzinfo is None or finished.tzinfo is None or started > finished:
        raise ValueError("captured web collection times must be canonical and ordered")

    execution = provenance.execution

    if execution is not None:
        if type(execution) is not AdapterExecution or (
            execution.state is not ExecutionState.SUCCEEDED
            or type(execution.exit_code) is not int or execution.exit_code != 0
            or provenance.invocation_sha256 is None
            or isinstance(execution.duration_seconds, bool)
            or not isinstance(execution.duration_seconds, (int, float))
            or execution.duration_seconds < 0
        ):
            raise ValueError("captured web refuses unsuccessful or unbound collection outcomes")

        try:
            finite = math.isfinite(execution.duration_seconds)

        except OverflowError:
            finite = False

        if not finite:
            raise ValueError("captured web collection duration must be finite")

    normalized = EvidenceProvenance(provenance.workspace_id, provenance.scope_reference,
        provenance.source_id, provenance.source_version, provenance.tool_version,
        provenance.started_at, provenance.finished_at, provenance.invocation_sha256, execution)

    if normalized != provenance or (
        EvidenceRecord(reference, normalized, record.schema_version) != record
    ):
        raise ValueError("captured web caller manifest identity differs from its metadata")

    return record


def WebSource(source: object) -> tuple[RequestTemplate, Target]:
    """Revalidate the bounded anonymous concrete source before constructing any URI identity.

    Args:
        source: Caller-declared existing source template; values and sessions are unsupported.

    Returns:
        Exact canonical source template and existing concrete URL Target.

    Raises:
        ValueError: The source is malformed, symbolic, authenticated or outside the profile.
    """

    if type(source) is not RequestTemplate or type(source.endpoint) is not Endpoint or (
        type(source.injection_points) is not tuple or source.injection_points
        or source.body_kind is not BodyKind.NONE or source.session_reference is not None
        or source.graphql_operation is not None
    ):
        raise ValueError("captured web source must be an anonymous concrete GET template")

    endpoint = source.endpoint
    WebText(endpoint.workspace_id)
    WebText(endpoint.origin, MAX_HREF_BYTES)
    WebText(endpoint.path_template, 1024)

    if endpoint.method != "GET" or (
        "{" in endpoint.path_template or "}" in endpoint.path_template
        or "%" in endpoint.path_template
    ):
        raise ValueError("captured web source must be an anonymous concrete GET template")

    rebuilt = RequestTemplate(Endpoint(endpoint.workspace_id, endpoint.origin,
                                       endpoint.path_template))

    if rebuilt != source:
        raise ValueError("captured web source fields must have canonical spelling")

    return source, Target(TargetKind.URL, endpoint.origin + endpoint.path_template)


@dataclass(frozen=True, slots=True)
class CapturedWebLimits:
    """Finite offline anchor-work and deterministic returned-candidate bounds."""

    max_anchor_work: int = MAX_ANCHORS
    max_candidates: int = 64

    def __post_init__(self) -> None:
        """Refuse bool, coercion and work/frontier sizes above the accepted profile."""

        WebInteger(self.max_anchor_work, 1, MAX_ANCHORS)
        WebInteger(self.max_candidates, 1, 256)


@dataclass(frozen=True, slots=True)
class CapturedWebEntry:
    """Retain one prepared lexical candidate and its processed source occurrences."""

    target: Target
    template: RequestTemplate
    decision: ScopeDecision
    ordinals: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class CapturedWebFrontier:
    """Hold immutable source interpretation and membership consistency, never an execution grant."""

    profile_version: int
    source: RequestTemplate
    source_target: Target
    capture: EvidenceRecord = field(repr=False)
    scope_reference: str
    scope_revision: int
    scope_sha256: str
    checked_at: str
    limits: CapturedWebLimits
    entries: tuple[CapturedWebEntry, ...]
    anchor_count: int
    processed_anchors: int
    exclusion_counts: tuple[tuple[str, int], ...]
    complete: bool
    discarded_candidates: int
    truncation_reasons: tuple[str, ...]
    frontier_digest: str


@dataclass(frozen=True, slots=True)
class CapturedWebProjection:
    """Return pure owner patches and lexical observations for explicit persistence."""

    object_patches: tuple[SecurityObject, ...]
    observations: tuple[Observation, ...]


class BoundedHtmlEvidenceStore(LocalEvidenceStore):
    """Retain owner Get/Read integrity while bounding actual artifacts before allocation."""

    def Read(self, reference: EvidenceReference) -> bytes:
        """Deny an oversized actual reference before the owning raw-byte read.

        Args:
            reference: Actual parsed manifest reference or explicit verified caller reference.

        Returns:
            Exact bounded bytes only after ordinary owner integrity checks.

        Raises:
            ValueError: Actual artifact exceeds this consumer's body budget.
            EvidenceError: Owning paths, bytes or immutable identities cannot be verified.
        """

        if type(reference) is not EvidenceReference:
            raise ValueError("captured web requires a typed actual evidence reference")

        WebInteger(reference.size_bytes, 0, MAX_BODY_BYTES)

        return super().Read(reference)


class AnchorParser(HTMLParser):
    """Interpret bounded lexical attribute tokens without building or claiming a browser DOM."""

    def __init__(self) -> None:
        """Create per-artifact parser state without acquiring or retaining source text."""

        super().__init__(convert_charrefs=True)
        self.anchors: list[str | None] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Validate framework-owned tag callbacks and retain only explicit lexical anchor hrefs.

        Args:
            tag: Framework-normalized lowercase start-tag name.
            attrs: At most one bounded token's decoded attributes.

        Raises:
            ValueError: Attributes/base semantics or total anchor count is unsupported.
        """

        if len(attrs) > MAX_ATTRIBUTES or len({name for name, _ in attrs}) != len(attrs):
            raise ValueError("captured web attributes exceed bounds or contain duplicates")

        if tag == "base":
            raise ValueError("captured web does not support base elements")

        if tag == "a":
            if len(self.anchors) == MAX_ANCHORS:
                raise ValueError("captured web anchor count exceeds the admission budget")

            self.anchors.append(dict(attrs).get("href"))


def MarkupEnd(text: str, start: int) -> int:
    """Locate one bounded complete quote-aware token before its parser can allocate attributes.

    Args:
        text: Entire already byte-bounded UTF-8-decoded artifact.
        start: Explicit opening less-than position.

    Returns:
        Exclusive end of a complete admitted token.

    Raises:
        ValueError: Token is incomplete, malformed or exceeds the inclusive byte limit.
    """

    if text.startswith("<!--", start):
        marker = text.find("-->", start + 4)

        if marker < 0:
            raise ValueError("captured web markup comment is incomplete")

        end = marker + 3

        if end - start > MAX_TOKEN_BYTES or len(text[start:end].encode("utf-8")) > MAX_TOKEN_BYTES:
            raise ValueError("captured web markup token exceeds the byte budget")

        return end

    quote: str | None = None
    used = 0

    for index in range(start, len(text)):
        character = text[index]
        codepoint = ord(character)
        used += 1 if codepoint < 128 else 2 if codepoint < 2048 else 3 if codepoint < 65536 else 4

        if used > MAX_TOKEN_BYTES:
            raise ValueError("captured web markup token exceeds the byte budget")

        if quote is not None:
            if character == quote:
                quote = None

        elif character in {"'", '"'}:
            quote = character

        elif character == ">":
            return index + 1

        elif character == "<" and index != start:
            raise ValueError("captured web markup token is malformed")

    raise ValueError("captured web markup token is incomplete")


def ParseAnchors(raw: bytes) -> tuple[str | None, ...]:
    """Admit the full static-markup artifact before applying any soft candidate work ceiling.

    Args:
        raw: Exact owner-verified body, never more than 256 KiB.

    Returns:
        Source-ordered decoded hrefs, including empty/absent anchor slots.

    Raises:
        ValueError: UTF-8, token grammar, hard bounds or source base semantics is unsupported.
    """

    if not isinstance(raw, bytes) or len(raw) > MAX_BODY_BYTES or raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("captured web body is outside its UTF-8 byte profile")

    text = raw.decode("utf-8")
    parser = AnchorParser()
    position = 0
    tokens = 0
    raw_tag: str | None = None

    while position < len(text):
        if raw_tag is not None:
            closing = _RAW_CLOSE[raw_tag].search(text, position)

            if closing is None:
                raise ValueError("captured web raw-text closing tag is incomplete")

            start = closing.start()

        else:
            start = text.find("<", position)

            if start < 0:
                break

        end = MarkupEnd(text, start)
        tokens += 1

        if tokens > MAX_MARKUP_TOKENS:
            raise ValueError("captured web markup work exceeds the admission budget")

        token = text[start:end]

        if token.startswith("<!--"):
            pass

        elif token.lower() == "<!doctype html>":
            pass

        elif token.startswith("</"):
            if not _END_TAG.fullmatch(token):
                raise ValueError("captured web closing markup is unsupported")

        elif not _START_TAG.match(token):
            raise ValueError("captured web markup declaration is unsupported")

        parser.feed(token)

        if parser.rawdata:
            raise ValueError("captured web markup token is not complete")

        raw_tag = parser.cdata_elem if parser.cdata_elem in {"script", "style"} else None
        parser.reset()
        position = end

    if raw_tag is not None:
        raise ValueError("captured web raw-text closing tag is incomplete")

    parser.close()

    return tuple(parser.anchors)


def Candidate(
    href: str | None, source: RequestTemplate, source_target: Target,
) -> tuple[Target | None, str | None]:
    """Resolve one lexical URI under exact exclusion precedence without exposing source values.

    Args:
        href: One decoded attribute or absent anchor slot.
        source: Existing validated anonymous source request.
        source_target: Exact declared document URL, not a browser navigation outcome.

    Returns:
        A canonical same-origin structural candidate or one fixed exclusion reason.

    Raises:
        ValueError: Internal typed source context is inconsistent.
    """

    if href is None or href == "":
        return None, "missing-href"

    try:
        WebText(href, MAX_HREF_BYTES)

        if any(character.isspace() for character in href) or (
            "\\" in href or _INVALID_PERCENT.search(href)
        ):
            return None, "invalid-url"

        parsed = urlsplit(href)
        parsed.port

    except ValueError:
        return None, "invalid-url"

    if href.startswith("#"):
        return None, "fragment-only"

    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        return None, "non-http"

    if parsed.username is not None or parsed.password is not None:
        return None, "credentials"

    without_fragment = href.split("#", 1)[0]

    if "?" in without_fragment:
        return None, "query"

    try:
        resolved = urljoin(source_target.value, without_fragment)
        parsed = urlsplit(resolved)

        if parsed.username is not None or parsed.password is not None:
            return None, "credentials"

        target = Target(TargetKind.URL, resolved)

    except ValueError:
        return None, "invalid-url"

    canonical = urlsplit(target.value)

    if canonical.scheme + "://" + canonical.netloc != source.endpoint.origin:
        return None, "off-origin"

    try:
        if "%" in canonical.path or "{" in canonical.path or "}" in canonical.path:
            return None, "unsupported-path"

        Endpoint(source.endpoint.workspace_id, source.endpoint.origin, canonical.path)

    except ValueError:
        return None, "unsupported-path"

    if target == source_target:
        return None, "source-target"

    return target, None


def FrontierFields(frontier: CapturedWebFrontier) -> dict[str, object]:
    """Validate every nested output field before hashing a copied immutable wrapper.

    Args:
        frontier: Complete retained source interpretation and scoped candidate output.

    Returns:
        Bounded deterministic digest fields, excluding the digest itself.

    Raises:
        ValueError: Nested typed records, identities, counters or claimed completeness disagree.
    """

    if type(frontier) is not CapturedWebFrontier:
        raise ValueError("captured web requires a typed retained frontier")

    WebInteger(frontier.profile_version, 1, 1)
    source, target = WebSource(frontier.source)
    capture = WebCapture(frontier.capture)

    if type(frontier.source_target) is not Target or (
        frontier.source_target.kind is not TargetKind.URL or frontier.source_target != target
    ):
        raise ValueError("captured web source target differs from its template")

    if type(frontier.limits) is not CapturedWebLimits:
        raise ValueError("captured web requires typed retained limits")

    limits = CapturedWebLimits(frontier.limits.max_anchor_work, frontier.limits.max_candidates)
    WebText(frontier.scope_reference)
    RequireWorkspaceInteger(frontier.scope_revision, "scope_revision")
    WebDigest(frontier.scope_sha256)
    WebText(frontier.checked_at)

    if NormalizeTime(frontier.checked_at) != frontier.checked_at or (
        capture.provenance.workspace_id != source.endpoint.workspace_id
        or capture.provenance.scope_reference != frontier.scope_reference
        or datetime.fromisoformat(capture.provenance.finished_at) >
        datetime.fromisoformat(frontier.checked_at)
    ):
        raise ValueError("captured web source, collection or scope/time binding differs")

    WebInteger(frontier.anchor_count, 0, MAX_ANCHORS)
    WebInteger(frontier.processed_anchors, 0, MAX_ANCHORS)
    WebInteger(frontier.discarded_candidates, 0, MAX_ANCHORS)

    if frontier.processed_anchors != min(frontier.anchor_count, limits.max_anchor_work) or (
        type(frontier.entries) is not tuple or len(frontier.entries) > limits.max_candidates
        or type(frontier.exclusion_counts) is not tuple
        or len(frontier.exclusion_counts) > len(_REJECTIONS)
        or type(frontier.truncation_reasons) is not tuple or type(frontier.complete) is not bool
    ):
        raise ValueError("captured web retained counts or collection shapes differ")

    exclusion_total = 0
    previous_reason = ""

    for pair in frontier.exclusion_counts:
        if type(pair) is not tuple or len(pair) != 2 or not isinstance(pair[0], str) or (
            pair[0] not in _REJECTIONS or pair[0] <= previous_reason
        ):
            raise ValueError("captured web retained exclusion counters are malformed")

        exclusion_total += WebInteger(pair[1], 1, MAX_ANCHORS)
        previous_reason = pair[0]

    entries: list[dict[str, object]] = []
    ordinals: set[int] = set()
    previous_url = ""

    for entry in frontier.entries:
        if type(entry) is not CapturedWebEntry or type(entry.target) is not Target or (
            type(entry.decision) is not ScopeDecision
            or entry.decision.reason is not ScopeDecisionReason.ALLOWED
            or type(entry.ordinals) is not tuple or not entry.ordinals
            or len(entry.ordinals) > frontier.processed_anchors
        ):
            raise ValueError("captured web retained candidate requires exact typed fields")

        template, candidate_target = WebSource(entry.template)

        if entry.target != candidate_target or entry.target.kind is not TargetKind.URL or (
            entry.target.value <= previous_url or template.endpoint.origin != source.endpoint.origin
            or template.endpoint.workspace_id != source.endpoint.workspace_id
            or entry.target == target
            or entry.decision.scope_reference != frontier.scope_reference
            or entry.decision.target_reference != entry.target.Reference()
        ):
            raise ValueError("captured web candidate identity or membership differs")

        WebText(entry.decision.scope_reference)
        WebText(entry.decision.target_reference)

        if entry.decision.rule_reference is not None:
            WebText(entry.decision.rule_reference)

        previous_ordinal = 0

        for ordinal in entry.ordinals:
            WebInteger(ordinal, 1, frontier.processed_anchors)

            if ordinal <= previous_ordinal or ordinal in ordinals:
                raise ValueError("captured web source ordinals are duplicated or unordered")

            ordinals.add(ordinal)
            previous_ordinal = ordinal

        previous_url = entry.target.value
        entries.append({"target": entry.target.ToDict(), "template": template.ToDict(),
            "decision": {"reason": entry.decision.reason.value,
                "scope_reference": entry.decision.scope_reference,
                "target_reference": entry.decision.target_reference,
                "rule_reference": entry.decision.rule_reference}, "ordinals": entry.ordinals})

    unreturned = frontier.processed_anchors - exclusion_total - len(ordinals)

    if unreturned < frontier.discarded_candidates or (
        frontier.discarded_candidates == 0 and unreturned != 0
        or frontier.discarded_candidates > 0 and len(frontier.entries) != limits.max_candidates
    ):
        raise ValueError("captured web retained anchor accounting differs")

    reasons = tuple(sorted((
        *(("anchor-work-limit",) if frontier.processed_anchors < frontier.anchor_count else ()),
        *(("candidate-limit",) if frontier.discarded_candidates else ()),
    )))

    if frontier.truncation_reasons != reasons or frontier.complete is not (not reasons):
        raise ValueError("captured web retained completeness differs from its omissions")

    return {"profile_version": frontier.profile_version, "source": source.ToDict(),
        "source_target": target.ToDict(), "capture": capture.ToDict(),
        "scope_reference": frontier.scope_reference, "scope_revision": frontier.scope_revision,
        "scope_sha256": frontier.scope_sha256, "checked_at": frontier.checked_at,
        "limits": {"max_anchor_work": limits.max_anchor_work,
                   "max_candidates": limits.max_candidates},
        "entries": entries, "anchor_count": frontier.anchor_count,
        "processed_anchors": frontier.processed_anchors,
        "exclusion_counts": frontier.exclusion_counts,
        "complete": frontier.complete, "discarded_candidates": frontier.discarded_candidates,
        "truncation_reasons": frontier.truncation_reasons}


def FrontierDigest(frontier: CapturedWebFrontier) -> str:
    """Compute a bounded consistency identity from exactly validated retained frontier fields.

    Args:
        frontier: Typed output or caller copy requiring nested revalidation.

    Returns:
        Canonical sha256 content identity, without authenticating collector or consent.

    Raises:
        ValueError: Any retained shape/binding is invalid.
    """

    return "sha256:" + hashlib.sha256(CanonicalModelJson(FrontierFields(frontier))).hexdigest()


def ReadCapturedWebFrontier(
    workspace_root: Path, source: RequestTemplate, capture: EvidenceRecord, scope_id: str,
    *, at: datetime, limits: CapturedWebLimits = CapturedWebLimits(),
) -> CapturedWebFrontier:
    """Verify one explicit HTML artifact and prepare exact current-scope lexical candidates.

    Args:
        workspace_root: Existing operator-owned physical workspace, never a discovery root.
        source: Explicit anonymous source request whose capture association is caller-attributed.
        capture: Bounded actual-store record; integrity does not prove acquisition truth.
        scope_id: Existing current persisted scope, never automatically created or expanded.
        at: Explicit aware decision time; historical collection remains historical.
        limits: Finite work/result bounds following full lexical admission.

    Returns:
        Deterministic complete or explicitly partial artifact-profile frontier, never a grant.

    Raises:
        ValueError: Inputs, source grammar, bounds or workspace/scope/time bindings are invalid.
        PermissionError: Source membership is denied under the exact current scope.
        EvidenceError: Actual manifest/blob integrity, safe paths or storage verification fails.
    """

    try:
        return ReadFrontier(workspace_root, source, capture, scope_id, at=at, limits=limits)

    except EvidenceError as error:
        raise type(error)("captured web evidence could not be verified") from None

    except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
        raise ValueError("captured web source or retained contract is invalid") from None


def ReadFrontier(
    workspace_root: Path, source: RequestTemplate, capture: EvidenceRecord, scope_id: str,
    *, at: datetime, limits: CapturedWebLimits,
) -> CapturedWebFrontier:
    """Apply owner-backed admission before constructing an ephemeral source-attributed frontier.

    Args:
        workspace_root: Existing physical owner workspace.
        source: Explicit structural source template.
        capture: Caller record that must match actual stored metadata and bytes.
        scope_id: Existing scope identifier.
        at: Explicit aware collection/membership boundary.
        limits: Typed finite profile limits.

    Returns:
        Full bounded source interpretation with no filesystem mutation.

    Raises:
        ValueError: Any typed/source/resource binding is invalid.
        PermissionError: Current source scope denies membership.
        EvidenceError: Actual owning immutable evidence verification fails.
    """

    source, source_target = WebSource(source)
    capture = WebCapture(capture)
    WebText(scope_id)
    RequireIdentifier(scope_id, "scope_id")

    if type(limits) is not CapturedWebLimits:
        raise ValueError("captured web requires typed limits")

    limits = CapturedWebLimits(limits.max_anchor_work, limits.max_candidates)

    if not isinstance(at, datetime) or at.tzinfo is None or at.utcoffset() is None:
        raise ValueError("captured web requires an explicit aware decision time")

    checked_at = at.astimezone(timezone.utc).isoformat()

    try:
        workspace = LocalWorkspaceStore(workspace_root).Open()
        scope = LocalScopeStore(workspace_root).Open(scope_id)

    except OSError:
        raise ValueError("captured web workspace or scope could not be opened") from None

    if workspace.workspace_id != source.endpoint.workspace_id or (
        scope.workspace_id != workspace.workspace_id
        or capture.provenance.workspace_id != workspace.workspace_id
        or capture.provenance.scope_reference != scope.Reference()
        or datetime.fromisoformat(capture.provenance.finished_at) > at
    ):
        raise ValueError("captured web source, collection or scope/time binding differs")

    decision = scope.Check(source_target, at=at)

    if not decision.Allowed():
        raise PermissionError("captured web source rejected by scope: " + decision.reason.value)

    store = BoundedHtmlEvidenceStore(Path(workspace_root) / "evidence")
    actual = store.Get(capture.evidence_id)

    if actual != capture:
        raise ValueError("captured web actual manifest differs from the supplied record")

    anchors = ParseAnchors(store.Read(actual.reference))
    processed = min(len(anchors), limits.max_anchor_work)
    exclusions: Counter[str] = Counter()
    entries: dict[str, CapturedWebEntry] = {}

    for ordinal in range(1, processed + 1):
        candidate_target, reason = Candidate(anchors[ordinal - 1], source, source_target)

        if reason is not None:
            exclusions[reason] += 1
            continue

        assert candidate_target is not None, "An admitted URI must have an exact target"
        membership = scope.Check(candidate_target, at=at)

        if not membership.Allowed():
            exclusions["scope." + membership.reason.value] += 1
            continue

        template = RequestTemplate(Endpoint(source.endpoint.workspace_id, source.endpoint.origin,
                                            urlsplit(candidate_target.value).path))
        previous = entries.get(candidate_target.value)
        entries[candidate_target.value] = CapturedWebEntry(candidate_target, template, membership,
            (ordinal,) if previous is None else (*previous.ordinals, ordinal))

    ordered = tuple(entries[key] for key in sorted(entries))
    discarded = max(0, len(ordered) - limits.max_candidates)
    reasons = tuple(sorted((*(('anchor-work-limit',) if processed < len(anchors) else ()),
                            *(('candidate-limit',) if discarded else ()))))
    frontier = CapturedWebFrontier(CAPTURED_WEB_PROFILE_VERSION, source, source_target, actual,
        scope.Reference(), scope.revision,
        hashlib.sha256(CanonicalModelJson(scope.ToDict())).hexdigest(),
        checked_at, limits, ordered[:limits.max_candidates], len(anchors), processed,
        tuple(sorted(exclusions.items())), not reasons, discarded, reasons, "")
    object.__setattr__(frontier, "frontier_digest", FrontierDigest(frontier))

    return frontier


def ProjectCapturedWebFrontier(
    frontier: CapturedWebFrontier, *, existing: tuple[SecurityObject, ...] = (),
) -> CapturedWebProjection:
    """Compose complete structural request patches and explicit lexical-source observations.

    Args:
        frontier: Retained verified-source output; content consistency is not actor authentication.
        existing: Every already-existing returned candidate Endpoint object, at most 256.
            Empty input is appropriate for new endpoints; this pure function cannot find omissions.

    Returns:
        Existing-owner object patches and source-attributed lexical observations, without writes.

    Raises:
        ValueError: Output integrity, existing identities/templates or owning attribute bounds fail.
    """

    try:
        return ProjectFrontier(frontier, existing)

    except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
        raise ValueError("captured web retained projection contract is invalid") from None


def ProjectFrontier(
    frontier: CapturedWebFrontier, existing: tuple[SecurityObject, ...],
) -> CapturedWebProjection:
    """Revalidate complete output and use existing request/model projection ownership.

    Args:
        frontier: Exact retained source frontier.
        existing: Explicit complete collection of relevant current Endpoint objects.

    Returns:
        Pure immutable object patches and lexical observations with original attribution.

    Raises:
        ValueError: Shapes, identities, template collections or owner bounds are invalid.
    """

    digest = FrontierDigest(frontier)
    WebDigest(frontier.frontier_digest, prefixed=True)

    if digest != frontier.frontier_digest or type(existing) is not tuple or len(existing) > 256:
        raise ValueError("captured web retained identity or existing collection differs")

    identities = {entry.template.endpoint.Identity().Reference() for entry in frontier.entries}
    current: dict[str, SecurityObject] = {}

    for item in existing:
        if type(item) is not SecurityObject or type(item.identity) is not ObjectIdentity or (
            item.identity.kind is not ObjectKind.ENDPOINT
            or item.identity.workspace_id != frontier.source.endpoint.workspace_id
            or not isinstance(item.attributes, Mapping)
        ):
            raise ValueError("captured web existing objects must be typed candidate Endpoints")

        WebText(item.identity.key, 4096)
        identity = item.identity.Reference()

        if identity not in identities or identity in current:
            raise ValueError("captured web existing object is foreign or duplicated")

        current[identity] = item

    original = frontier.capture.provenance
    provenance = ModelProvenance(original.source_id, frontier.capture.evidence_id,
        original.finished_at,
        original.scope_reference, frontier.source_target.Reference(), original.tool_version,
        (frontier.capture.reference,), original.execution)
    patches: list[SecurityObject] = []
    observations: list[Observation] = []

    for entry in frontier.entries:
        identity = entry.template.endpoint.Identity().Reference()
        previous = RequestsFromObject(current[identity]) if identity in current else ()
        templates = {template.Reference(): template for template in (*previous, entry.template)}
        patches.append(ProjectRequests(tuple(templates[key] for key in sorted(templates)),
                                       provenance=(provenance,)))
        observations.append(Observation("web.lexical-link", identity, {
            "profile_version": CAPTURED_WEB_PROFILE_VERSION, "parser_id": "web.captured-html",
            "source_request_reference": frontier.source.Reference(),
            "source_endpoint_reference": frontier.source.endpoint.Identity().Reference(),
            "source_target_reference": frontier.source_target.Reference(),
            "capture_manifest_id": frontier.capture.evidence_id,
            "source_version": original.source_version,
            "frontier_digest": frontier.frontier_digest, "scope_sha256": frontier.scope_sha256,
            "scope_revision": frontier.scope_revision, "checked_at": frontier.checked_at,
            "candidate_request_reference": entry.template.Reference(),
            "candidate_target_reference": entry.target.Reference(),
            "source_ordinals": entry.ordinals,
        }, provenance))

    return CapturedWebProjection(tuple(patches), tuple(observations))
