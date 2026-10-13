# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Hostile static source, resource, URI and copied-output admission regressions."""

from __future__ import annotations

import copy
import traceback
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from fuzzy1337.adapters import AdapterExecution, ExecutionState
from fuzzy1337.captured_web import (
    BoundedHtmlEvidenceStore,
    CapturedWebLimits,
    ProjectCapturedWebFrontier,
    ReadCapturedWebFrontier,
)
from fuzzy1337.evidence import (
    EvidenceIntegrityError,
    EvidenceNotFoundError,
    EvidenceRecord,
    LocalEvidenceStore,
)
from fuzzy1337.requests import BodyKind, Endpoint, RequestTemplate, SessionReference
from fuzzy1337.scope import LocalScopeStore, ScopeDecisionReason, Target, TargetKind
from tests.contract.captured_web_fixture import Fixture, WorkspaceBytes


def Copy(value, **changes):
    """Create deliberately malformed frozen-wrapper copies without changing their original owners.

    Args:
        value: Existing immutable producer output to copy.
        changes: Explicit hostile replacement fields.

    Returns:
        Independent malformed copy for public-boundary refusal tests.
    """

    copied = copy.copy(value)

    for name, replacement in changes.items():
        object.__setattr__(copied, name, replacement)

    return copied


def Read(fixture, **changes):
    """Invoke the public consumer with explicit real-owner fixture context and selected overrides.

    Args:
        fixture: Independently produced synthetic workspace/source/evidence.
        changes: Public argument overrides for failure or boundary cases.

    Returns:
        Actual captured-source frontier rather than a mocked expected interpretation.
    """

    arguments = {"workspace_root": fixture.root, "source": fixture.source,
        "capture": fixture.capture, "scope_id": fixture.scope.scope_id, "at": fixture.at}
    arguments.update(changes)

    return ReadCapturedWebFrontier(**arguments)


@pytest.mark.parametrize("field", ["max_anchor_work", "max_candidates"])
@pytest.mark.parametrize("value", [True, False, 0, -1, 1.0, "1", None, 2048, 10**400],
                         ids=["bool-true", "bool-false", "zero", "negative", "float",
                              "text", "null", "oversize", "huge-int"])
def test_LimitsRejectCoercionAndOutOfRangeCounts(field, value):
    """Numeric equality and enormous Python integers cannot weaken finite work/result admission."""

    with pytest.raises(ValueError):
        CapturedWebLimits(**{field: value})


@pytest.mark.parametrize("tag", ["title", "textarea", "xmp", "iframe", "noembed",
                                "noframes", "plaintext", "template", "noscript"])
def test_TokenLocalAttributesHavePatchIndependentLexicalOrdinals(tmp_path, tag):
    """Nonbrowser context names cannot activate runtime-dependent raw/RCDATA suppression."""

    raw = (f'<{tag}><a href="/alpha">lexical</a></{tag}>'
           '<a href="/ports">ordinary</a>').encode()
    fixture = Fixture.Create(tmp_path / "workspace", raw=raw)
    frontier = Read(fixture)
    assert frontier.anchor_count == 2, "A stdlib patch version silently changed lexical ordinals"
    assert [entry.ordinals for entry in frontier.entries] == [(1,), (2,)], (
        "The profile acquired DOM visibility or parser-context semantics"
    )


@pytest.mark.parametrize("tag", ["script", "style"])
def test_OnlyDeclaredRawTextSuppressesFakeLinksAndBaseTokens(tmp_path, tag):
    """Comment/raw-text strings do not become markup or change relative resolution."""

    raw = (f'<{tag}>literal = \'<a href="/zeta"><base href="/elsewhere">\';</{tag}>'
           '<!-- <a href="/zeta"><base href="/elsewhere"> -->'
           '<A HREF="/alpha">real</A>').encode()
    fixture = Fixture.Create(tmp_path / "workspace", raw=raw)
    frontier = Read(fixture)
    assert frontier.anchor_count == 1 and frontier.entries[0].ordinals == (1,), (
        "A raw-text/comment string became a source tag"
    )


def test_EntityDecodingOccursOnceBeforeUnsafeUriChecks(tmp_path):
    """Encoded delimiters, controls and credentials cannot bypass the fixed URI profile."""

    raw = b'''<a href="/al&#112;ha"></a><a href="/search&#63;selection=synthetic"></a>
<a href="&#x23;part"></a><a href="http://user&#58;synthetic&#64;127.0.0.1:19091/x"></a>
<a href="/with&#9;tab"></a><a href="/al&amp;#112;ha"></a>'''
    fixture = Fixture.Create(tmp_path / "workspace", raw=raw)
    frontier = Read(fixture)
    assert frontier.entries[0].template.endpoint.path_template == "/alpha", (
        "One character-reference decode lost the declared path"
    )
    assert dict(frontier.exclusion_counts) == {"query": 1, "fragment-only": 1,
        "credentials": 1, "invalid-url": 1, "unsupported-path": 1}, (
        "Entities were decoded recursively or unsafe delimiters escaped admission"
    )


@pytest.mark.parametrize("raw", [
    b'<a href="/alpha"><base href="/elsewhere">',
    b'<a href="/alpha"><BASE>',
    b'<a HREF="/alpha" href="/ports">',
    b'<div class="first" CLASS="second"><a href="/alpha">',
    b'<a href="/alpha"', b'<a href="/alpha>', b'<!-- incomplete',
    b'<!ENTITY private "synthetic">', b'<?private marker?>',
    b'<!DOCTYPE html SYSTEM "synthetic">', b'</a junk>', b'< 5',
    b'<script>unterminated', b'<style>unterminated', b'<script></script junk>',
    b'\xef\xbb\xbf<a href="/alpha">', b'\xff',
], ids=["late-base", "empty-base", "duplicate-href", "duplicate-other", "unclosed-tag",
        "unclosed-quote", "unclosed-comment", "entity-declaration", "processing-instruction",
        "external-doctype", "end-attributes", "invalid-less-than", "unclosed-script",
        "unclosed-style", "invalid-raw-close", "bom", "invalid-utf8"])
def test_FullSourceAdmissionRefusesBeforeSoftWorkCanHideAmbiguity(tmp_path, raw):
    """A one-anchor work ceiling cannot hide unsupported base, duplicate or malformed suffixes."""

    fixture = Fixture.Create(tmp_path / "workspace", raw=raw)

    with pytest.raises(ValueError):
        Read(fixture, limits=CapturedWebLimits(1, 1))


@pytest.mark.parametrize("body_kind", [BodyKind.TEXT, "none", None])
def test_SourceRequiresExactAnonymousBodyEnum(tmp_path, body_kind):
    """Equal strings and unsupported body kinds cannot masquerade as a concrete no-body source."""

    fixture = Fixture.Create(tmp_path / "workspace")

    with pytest.raises(ValueError):
        Read(fixture, source=Copy(fixture.source, body_kind=body_kind))


@pytest.mark.parametrize("field,value", [
    ("endpoint", None), ("injection_points", []),
    ("session_reference", SessionReference("web-fixture", "synthetic")),
    ("graphql_operation", "Synthetic"),
], ids=["missing-endpoint", "mutable-points", "session", "graphql"])
def test_SourceNestedCopiesRefuseLiteralOrUnresolvedRuntimeContext(tmp_path, field, value):
    """Source interpretation never resolves credentials, session references or symbolic values."""

    fixture = Fixture.Create(tmp_path / "workspace")

    with pytest.raises(ValueError):
        Read(fixture, source=Copy(fixture.source, **{field: value}))


@pytest.mark.parametrize("field,value", [
    ("method", "POST"), ("method", "get"), ("path_template", "/users/{user_id}"),
    ("path_template", "/percent%41"), ("origin", "http://127.0.0.1:private-source/"),
    ("workspace_id", "other-workspace"),
], ids=["mutation-method", "noncanonical-method", "variable", "escape", "invalid-authority",
        "foreign-workspace"])
def test_ExplicitSourceEndpointBindingIsRevalidated(tmp_path, field, value):
    """Caller surgery on existing structural objects cannot broaden the declared source profile."""

    fixture = Fixture.Create(tmp_path / "workspace")
    source = Copy(fixture.source, endpoint=Copy(fixture.source.endpoint, **{field: value}))

    with pytest.raises(ValueError):
        Read(fixture, source=source)


@pytest.mark.parametrize("at", [None, "2026-10-13T12:00:00+00:00", datetime(2026, 10, 13),
                              datetime(2026, 10, 12, tzinfo=timezone.utc)],
                         ids=["missing", "text", "naive", "future-capture"])
def test_ExplicitAwareTimeMustNotPrecedeCollection(tmp_path, at):
    """Historical artifacts are admissible only with truthful collection/decision chronology."""

    fixture = Fixture.Create(tmp_path / "workspace")

    with pytest.raises(ValueError):
        Read(fixture, at=at)


@pytest.mark.parametrize("field,value", [
    ("workspace_id", "foreign"), ("scope_reference", "scope:other"),
    ("source_id", "invalid source"), ("source_version", "x" * 257),
    ("tool_version", "x" * 257), ("started_at", "synthetic-private-source-value"),
    ("finished_at", "2026-10-12T11:59:59.000000+00:00"),
    ("invocation_sha256", "x" * 64),
], ids=["foreign-workspace", "foreign-scope", "invalid-source-id", "source-version-size",
        "tool-version-size", "invalid-time", "reversed-time", "invalid-invocation"])
def test_CompleteSourceProvenanceAndManifestIdentityAreRequired(tmp_path, field, value):
    """Copied collection metadata requires its exact owning manifest binding."""

    fixture = Fixture.Create(tmp_path / "workspace")
    capture = Copy(fixture.capture, provenance=Copy(fixture.capture.provenance, **{field: value}))

    with pytest.raises(ValueError):
        Read(fixture, capture=capture)


@pytest.mark.parametrize("state", [ExecutionState.FAILED, ExecutionState.TIMED_OUT,
                                  ExecutionState.CANCELLED, "succeeded"])
def test_FailedOrEqualStringExecutionsNeverBecomeSuccessfulSourceFacts(tmp_path, state):
    """Capture interpretation preserves terminal outcome rather than upgrading available bytes."""

    fixture = Fixture.Create(tmp_path / "workspace")
    execution = Copy(AdapterExecution(ExecutionState.SUCCEEDED, 0, 1), state=state)
    provenance = Copy(fixture.capture.provenance, execution=execution, invocation_sha256="a" * 64)

    with pytest.raises(ValueError):
        Read(fixture, capture=Copy(fixture.capture, provenance=provenance))


def test_MetadataBudgetRefusesBeforeOwningManifestSerialization(tmp_path, monkeypatch):
    """An oversized direct caller field cannot trigger a full canonical provenance copy."""

    fixture = Fixture.Create(tmp_path / "workspace")
    provenance = Copy(fixture.capture.provenance, source_version="x" * (1024 * 1024))
    capture = Copy(fixture.capture, provenance=provenance)

    def RefuseSerialization(*args, **kwargs):
        """Tripwire full owning serialization after explicit malformed caller construction."""

        raise AssertionError("oversized caller metadata reached owning serialization")

    monkeypatch.setattr(EvidenceRecord, "Serialize", RefuseSerialization)

    with pytest.raises(ValueError):
        Read(fixture, capture=capture)


def test_ActualParsedArtifactBudgetPrecedesAllocatingOwnerRead(tmp_path, monkeypatch):
    """A valid oversized stored manifest is refused by the facade before raw allocation."""

    fixture = Fixture.Create(tmp_path / "workspace", raw=b"x" * (262144 + 1))

    def RefuseOwnerRead(*args, **kwargs):
        """Fail if an oversized actual parsed reference reaches the allocating raw reader."""

        raise AssertionError("oversized actual HTML reached owner Read")

    monkeypatch.setattr(LocalEvidenceStore, "Read", RefuseOwnerRead)

    with pytest.raises(ValueError):
        BoundedHtmlEvidenceStore(fixture.root / "evidence").Get(fixture.capture.evidence_id)

    forged = Copy(fixture.capture, reference=replace(fixture.capture.reference, size_bytes=1))

    with pytest.raises(ValueError):
        Read(fixture, capture=forged)


@pytest.mark.parametrize("raw,allowed", [
    (b"x" * 262144, True), (b"x" * 262145, False),
    (b"<div title='" + b"x" * (4096 - 14) + b"'>", True),
    (b"<div title='" + b"x" * (4096 - 13) + b"'>", False),
    (b"<a>" * 1024, True), (b"<a>" * 1025, False),
    (b"<br>" * 8192, True), (b"<br>" * 8193, False),
    (("<div " + " ".join(f"a{index}=x" for index in range(64)) + ">").encode(), True),
    (("<div " + " ".join(f"a{index}=x" for index in range(65)) + ">").encode(), False),
], ids=["body-exact", "body-plus-one", "token-exact", "token-plus-one", "anchors-exact",
        "anchors-plus-one", "tokens-exact", "tokens-plus-one", "attrs-exact", "attrs-plus-one"])
def test_InclusiveHardSourceBudgetsAreIndependentlyMeasured(tmp_path, raw, allowed):
    """Every first-over-limit source refuses without silent source truncation."""

    fixture = Fixture.Create(tmp_path / "workspace", raw=raw)

    if allowed:
        frontier = Read(fixture)
        assert frontier.complete, "Hard-bound admission unexpectedly became a partial scan"

    else:
        with pytest.raises(ValueError):
            Read(fixture)


@pytest.mark.parametrize("corruption", ["missing-blob", "corrupt-blob", "missing-manifest",
                                      "corrupt-manifest"])
def test_OwningEvidenceFailuresKeepTheirCategoryAndSanitizeTracebacks(tmp_path, corruption):
    """Corrupt stored bytes cannot become link observations or expose diagnostic source values."""

    fixture = Fixture.Create(tmp_path / "workspace")
    blob = fixture.root / "evidence" / fixture.capture.reference.locator
    manifest = fixture.root / "evidence" / "records" / (fixture.capture.evidence_id[7:] + ".json")
    target = blob if corruption.endswith("blob") else manifest

    if corruption.startswith("missing"):
        target.unlink()

    else:
        target.write_bytes(b"synthetic-private-source-value")

    expected = (EvidenceNotFoundError if corruption.startswith("missing")
                else EvidenceIntegrityError)

    with pytest.raises(expected) as raised:
        Read(fixture)

    rendered = "".join(traceback.format_exception(raised.value))
    assert "synthetic-private-source-value" not in rendered, "Exception cause leaked raw bytes"


@pytest.mark.parametrize("field,value", [
    ("profile_version", True), ("source", None), ("capture", None), ("limits", None),
    ("scope_revision", True), ("scope_sha256", "private"), ("checked_at", "private"),
    ("entries", [None]), ("anchor_count", True), ("processed_anchors", -1),
    ("exclusion_counts", (({}, 1),)), ("complete", 1), ("discarded_candidates", True),
    ("truncation_reasons", []), ("frontier_digest", "sha256:" + "0" * 64),
], ids=["bool-profile", "source", "capture", "limits", "bool-revision", "scope-digest",
        "time", "mutable-entries", "bool-anchor-count", "negative-work", "nested-counter",
        "bool-complete", "bool-discarded", "mutable-reasons", "digest"])
def test_PublicProjectionRefusesMalformedCopiedFrontierFields(tmp_path, field, value):
    """Pure consumers validate nested shapes before any digest/reference computation."""

    fixture = Fixture.Create(tmp_path / "workspace")
    frontier = Read(fixture)

    with pytest.raises(ValueError):
        ProjectCapturedWebFrontier(Copy(frontier, **{field: value}))


@pytest.mark.parametrize("change", ["string-decision", "wrong-target", "duplicate-ordinal",
                                   "null-template", "mutable-ordinals", "missing-decision",
                                   "string-target-kind"])
def test_EqualEnumStringsAndNestedEntryCopiesCannotBypassIntegrity(tmp_path, change):
    """Every candidate remains an exact typed scope/template/occurrence binding after copying."""

    fixture = Fixture.Create(tmp_path / "workspace")
    frontier = Read(fixture)
    entry = frontier.entries[0]

    if change == "string-decision":
        changed = Copy(entry, decision=Copy(entry.decision, reason="allowed"))

    elif change == "wrong-target":
        changed = Copy(entry, target=Target(TargetKind.URL, "http://127.0.0.1:19091/ports"))

    elif change == "duplicate-ordinal":
        changed = Copy(entry, ordinals=(2, 2))

    elif change == "null-template":
        changed = Copy(entry, template=None)

    elif change == "mutable-ordinals":
        changed = Copy(entry, ordinals=[2, 3, 16])

    elif change == "missing-decision":
        changed = Copy(entry, decision=None)

    else:
        changed = Copy(entry, target=Copy(entry.target, kind="url"))

    with pytest.raises(ValueError):
        ProjectCapturedWebFrontier(Copy(frontier, entries=(changed, *frontier.entries[1:])))


def test_ChangedCurrentScopeDeniesSourceAndPreparationNeverWrites(tmp_path):
    """Capture attribution cannot replace the freshly opened source scope or mutate its rules."""

    fixture = Fixture.Create(tmp_path / "workspace")
    before = WorkspaceBytes(fixture.root)
    Read(fixture)
    assert WorkspaceBytes(fixture.root) == before, "Offline source interpretation wrote owner state"
    denied = replace(fixture.scope, deny=(*fixture.scope.deny, Target(TargetKind.URL,
                     fixture.source.endpoint.origin + fixture.source.endpoint.path_template)))
    LocalScopeStore(fixture.root).Save(denied)

    with pytest.raises(PermissionError, match=ScopeDecisionReason.DENIED.value):
        Read(fixture)


@pytest.mark.parametrize("href,reason", [
    ("http://127.0.0.1:80/alpha", None), ("//127.0.0.1:80/alpha", None),
    ("/alpha#synthetic-fragment", None), ("http://127.0.0.1:81/alpha", "off-origin"),
    ("https://127.0.0.1/alpha", "off-origin"), ("/docs/index", "source-target"),
    ("/alpha?#synthetic", "query"), ("/not-registered", "scope.unregistered"),
    ("/alpha%3Fselection", "unsupported-path"), ("/alpha%23part", "unsupported-path"),
    ("/alpha%0Acontrol", "unsupported-path"), ("/bad%xx", "invalid-url"),
    ("http://127.0.0.1:invalid/alpha", "invalid-url"),
    ("http://%75ser@127.0.0.1/alpha", "credentials"),
    ("data:text/plain,synthetic", "non-http"),
], ids=["default-port", "network-default-port", "fragment-removed", "different-port",
        "different-scheme", "source-target", "empty-query", "unregistered",
        "escaped-query", "escaped-fragment", "escaped-control", "bad-percent",
        "bad-port", "escaped-userinfo", "data-scheme"])
def test_ExactCanonicalOriginsDelimitersAndScopeDecisionsAreIndependent(tmp_path, href, reason):
    """Default ports normalize while every actual path remains an independently checked target."""

    fixture = Fixture.Create(tmp_path / "workspace", raw=f'<a href="{href}">'.encode())
    source = RequestTemplate(Endpoint("web-fixture", "http://127.0.0.1:80", "/docs/index"))
    declarations = (Target(TargetKind.URL, "http://127.0.0.1/docs/index"),
                    Target(TargetKind.URL, "http://127.0.0.1/alpha"))
    LocalScopeStore(fixture.root).Save(replace(fixture.scope, targets=declarations,
                                               allow=declarations, deny=()))
    frontier = Read(fixture, source=source)

    if reason is None:
        assert frontier.entries[0].target == declarations[1], "Default-port origin changed"
        assert not frontier.exclusion_counts, "A supported exact candidate was excluded"

    else:
        assert not frontier.entries and dict(frontier.exclusion_counts) == {reason: 1}, (
            "URI normalization broadened scope or changed exclusion precedence"
        )


@pytest.mark.parametrize("length,reason", [(2048, "unsupported-path"), (2049, "invalid-url")])
def test_DecodedHrefByteBudgetPrecedesStructuralPathAdmission(tmp_path, length, reason):
    """The exact href boundary is independent from the smaller existing Endpoint path bound."""

    raw = ('<a href="/' + "x" * (length - 1) + '">').encode()
    fixture = Fixture.Create(tmp_path / "workspace", raw=raw)
    frontier = Read(fixture)
    assert dict(frontier.exclusion_counts) == {reason: 1}, "Decoded href budget priority changed"


def test_ExplicitSucceededCollectionRetainsOutcomeWithoutInventingTransportProof(tmp_path):
    """An exact supplied SDK outcome remains attribution without becoming an acquisition grant."""

    fixture = Fixture.Create(tmp_path / "workspace")
    evidence = LocalEvidenceStore(fixture.root / "evidence")
    provenance = replace(fixture.capture.provenance, tool_version=None,
        invocation_sha256="a" * 64, execution=AdapterExecution(ExecutionState.SUCCEEDED, 0, 1.5))
    record = evidence.Put(evidence.Read(fixture.capture.reference), "response-body", "text/html",
                          provenance)
    frontier = Read(fixture, capture=record)
    projection = ProjectCapturedWebFrontier(frontier)
    assert all(item.provenance.execution == provenance.execution
               for item in projection.observations), (
        "Exact acquisition outcome was lost or replaced with a parser execution"
    )
    assert all(item.provenance.provider_version is None for item in projection.observations), (
        "An absent collector version was fabricated"
    )


@pytest.mark.parametrize("duration", [True, -1, None, float("nan"), float("inf"), 10**400],
                         ids=["bool", "negative", "null", "nan", "infinite", "huge-int"])
def test_CopiedCollectionDurationsRefuseBeforeNumericOverflow(tmp_path, duration):
    """Malformed caller execution metadata cannot bypass finite validation or raise overflow."""

    fixture = Fixture.Create(tmp_path / "workspace")
    execution = Copy(AdapterExecution(ExecutionState.SUCCEEDED, 0, 1), duration_seconds=duration)
    provenance = Copy(fixture.capture.provenance, invocation_sha256="a" * 64, execution=execution)

    with pytest.raises(ValueError):
        Read(fixture, capture=Copy(fixture.capture, provenance=provenance))


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("reference", None), ("provenance", None),
    ("evidence_id", "sha256:" + "0" * 64),
], ids=["bool-schema", "reference", "provenance", "manifest-identity"])
def test_CopiedCaptureShapesRefuseWithoutUnstructuredAttributeErrors(tmp_path, field, value):
    """Caller copies require exact nested owner records before lookup or content hashing."""

    fixture = Fixture.Create(tmp_path / "workspace")

    with pytest.raises(ValueError):
        Read(fixture, capture=Copy(fixture.capture, **{field: value}))


def test_RawTextBudgetUsesWholeArtifactWhileUnicodeTokenBudgetUsesExactUtf8(tmp_path):
    """Large admitted raw text is ignored; multibyte attribute tokens keep exact byte ceilings."""

    raw = b"<script>" + b"x" * 200000 + b'</script><a href="/alpha">'
    fixture = Fixture.Create(tmp_path / "raw-workspace", raw=raw)
    frontier = Read(fixture)
    assert frontier.anchor_count == 1, "Raw-text contents consumed markup/anchor work"
    exact = b"<div title='" + bytes.fromhex("cea9") * 2041 + b"'>"
    assert len(exact) == 4096, "Independent Unicode fixture did not hit the exact token boundary"
    unicode_fixture = Fixture.Create(tmp_path / "unicode-workspace", raw=exact)
    assert Read(unicode_fixture).complete, "Exact multibyte token admission was lost"

    with pytest.raises(ValueError):
        Read(Fixture.Create(tmp_path / "over-workspace", raw=exact[:-2] + b"x'>"))


@pytest.mark.parametrize("role,media_type", [
    ("stdout", "application/json"), ("response-body", "application/json"),
    ("response-body", "text/html; charset=utf-8"),
], ids=["native-status-only", "different-source-format", "charset-extension"])
def test_OtherEvidenceFormatsCannotBeReinterpretedAsCapturedHtml(tmp_path, role, media_type):
    """Native status JSON and undeclared encodings never silently become response-body sources."""

    fixture = Fixture.Create(tmp_path / "workspace")
    record = LocalEvidenceStore(fixture.root / "evidence").Put(
        b'{"schema_version":1,"status":200}', role, media_type, fixture.capture.provenance)

    with pytest.raises(ValueError):
        Read(fixture, capture=record)
