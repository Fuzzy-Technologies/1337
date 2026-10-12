# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Offline structural request identities, location constraints and invalid-input boundaries."""

from dataclasses import FrozenInstanceError, replace

import pytest

from fuzzy1337.model import ModelProvenance, ObjectIdentity, ObjectKind, SecurityObject
from fuzzy1337.requests import (
    MAX_INJECTION_POINTS,
    MAX_REQUEST_BYTES,
    BindingSource,
    BodyKind,
    Endpoint,
    InjectionLocation,
    InjectionPoint,
    ProjectRequests,
    RequestsFromObject,
    RequestTemplate,
    SessionReference,
    ValueBinding,
)


def Template() -> RequestTemplate:
    """Build one synthetic structural template with path and repeated-query slots."""

    return RequestTemplate(Endpoint("demo", "https://example.test", "/users/{user_id}"), (
        InjectionPoint(InjectionLocation.PATH, "user_id", ValueBinding("user-id")),
        InjectionPoint(InjectionLocation.QUERY, "filter", ValueBinding("filter"), 1),
    ))


def Attribution() -> tuple[ModelProvenance, ...]:
    """Attribute offline structural metadata without inventing execution or scope consent."""

    return (ModelProvenance(
        "synthetic-request", "fixture", "2026-10-11T10:00:00Z", "scope:demo", "target:demo",
    ),)


@pytest.mark.parametrize("origin,canonical", [
    ("HTTPS://EXAMPLE.TEST:443/", "https://example.test"),
    ("http://[2001:db8::1]:8080", "http://[2001:db8::1]:8080"),
    ("https://xn--bcher-kva.example.", "https://xn--bcher-kva.example"),
])
def test_EndpointReusesWorkspaceBoundSOMIdentity(origin, canonical):
    """Offline authority aliases converge while methods, paths and workspaces remain distinct."""

    endpoint = Endpoint("demo", origin, "/api/{item_id}", "post")
    canonical_endpoint = Endpoint("demo", canonical, "/api/{item_id}", "POST")
    assert endpoint == canonical_endpoint and endpoint.origin == canonical, "Origin alias drift"
    assert endpoint.Identity().kind is ObjectKind.ENDPOINT, "A second object family was introduced"
    assert Endpoint.FromDict(endpoint.ToDict()) == endpoint, "Endpoint round trip changed identity"
    assert endpoint.Identity() != replace(endpoint, workspace_id="other").Identity(), (
        "Endpoint identity lost workspace ownership"
    )
    assert endpoint.Identity() != replace(endpoint, method="GET").Identity(), "Method identity lost"
    assert endpoint.Identity() != replace(endpoint, path_template="/").Identity(), "Route lost"
    assert endpoint.PathVariables() == ("item_id",), "Declared path variable was not recovered"


@pytest.mark.parametrize("field,value", [
    ("workspace_id", "Bad Workspace"), ("origin", "https://user:password@example.test"),
    ("origin", "https://example.test/path"), ("origin", "https://example.test?token=test"),
    ("origin", "https://example.test?"), ("origin", "https://example.test#fragment"),
    ("origin", "file:///tmp/target"), ("origin", "https://example.test\n"),
    ("origin", 7), ("path_template", "users"), ("path_template", "/a//b"),
    ("path_template", "/../admin"), ("path_template", "/a/./b"),
    ("path_template", "/users/%2fadmin"), ("path_template", "/?token=test"),
    ("path_template", "/{a}/{a}"), ("path_template", "/prefix{a}"),
    ("path_template", "/" + "a" * 1024), ("path_template", "/a" * 65),
    ("path_template", None), ("method", "GET\r\nX-Extra: test"), ("method", "x" * 33),
], ids=(
    "invalid-workspace", "userinfo", "origin-path", "origin-query", "empty-query",
    "fragment", "non-http-scheme", "newline", "non-text-origin", "relative-path",
    "double-slash", "parent-segment", "dot-segment", "encoded-separator", "inline-query",
    "duplicate-path-variable", "partial-path-variable", "oversized-path", "too-many-segments",
    "non-text-path", "method-header-injection", "oversized-method",
))
def test_EndpointRejectsCapturedOrAmbiguousAddressing(field, value):
    """Captured credentials/query strings and ambiguous path encodings cannot become templates."""

    with pytest.raises(ValueError):
        replace(Template().endpoint, **{field: value})


def test_RootAndTrailingSlashPathsAreExplicit():
    """Root and a trailing slash are valid distinct routes, without implicit path-prefix grants."""

    root = Endpoint("demo", "http://127.0.0.1", "/")
    route = replace(root, path_template="/api/")
    assert root.PathVariables() == () and root.Identity() != route.Identity(), "Root route drift"
    assert RequestTemplate(root).Reference() != RequestTemplate(route).Reference(), (
        "Route collision"
    )


@pytest.mark.parametrize("binding", [
    ("Bad Name", BindingSource.INPUT), ("a" * 65, BindingSource.INPUT),
    ("value", "input"), (5, BindingSource.INPUT),
])
def test_ValueBindingHasNamesAndTypedSourcesOnly(binding):
    """Symbolic names cannot be replaced with arbitrary captured value text or coercion."""

    with pytest.raises(ValueError):
        ValueBinding(*binding)


@pytest.mark.parametrize("field,value", [
    ("workspace_id", "Bad"), ("session_id", "a" * 65), ("session_id", "session cookie"),
])
def test_SessionIdentifiersCannotContainCapturedMaterial(field, value):
    """A session reference describes ownership without materializing an authenticated session."""

    with pytest.raises(ValueError):
        replace(SessionReference("demo", "operator"), **{field: value})


def test_SessionIdentityAndImmutability():
    """Session references are credential-independent and immutable across serialization."""

    session = SessionReference("demo", "operator")
    assert SessionReference.FromDict(session.ToDict()) == session, "Session roundtrip changed"
    assert session.Reference().startswith("session:"), "Wrong session namespace"
    assert session.Reference() != replace(session, workspace_id="other").Reference(), (
        "Session identity omitted workspace ownership"
    )

    with pytest.raises(FrozenInstanceError):
        session.session_id = "changed"


@pytest.mark.parametrize("location,selector,body_kind", [
    (InjectionLocation.QUERY, "filter", BodyKind.NONE),
    (InjectionLocation.BODY, "username", BodyKind.FORM),
    (InjectionLocation.BODY, "", BodyKind.TEXT),
    (InjectionLocation.JSON, "/items/0/a~1b/~0key", BodyKind.JSON),
    (InjectionLocation.JSON, "", BodyKind.JSON),
    (InjectionLocation.COOKIE, "sid", BodyKind.NONE),
    (InjectionLocation.HEADER, "X-User-Id", BodyKind.NONE),
    (InjectionLocation.PATH, "user_id", BodyKind.NONE),
    (InjectionLocation.GRAPHQL, "/variables/id", BodyKind.GRAPHQL),
    (InjectionLocation.MULTIPART, "upload", BodyKind.MULTIPART),
])
def test_AllTypedLocationsRoundTripWithoutValues(location, selector, body_kind):
    """Eight typed locations and whole-body/root pointers have coherent reversible contracts."""

    point = InjectionPoint(location, selector, ValueBinding("input"))
    template = RequestTemplate(Template().endpoint, (point,), body_kind)
    assert RequestTemplate.FromJson(template.ToJson()) == template, "Typed template roundtrip drift"
    assert InjectionPoint.FromDict(point.ToDict()) == point, "Injection coordinate drift"
    assert ValueBinding.FromDict(point.binding.ToDict()) == point.binding, "Input binding drift"
    assert point.Reference(template.Reference()).startswith("injection:"), "Wrong input namespace"
    assert point.Reference(template.Reference()) != point.Reference(Template().Reference()), (
        "Injection identity omitted its request owner"
    )


@pytest.mark.parametrize("location,selector,occurrence", [
    ("query", "name", 0), (InjectionLocation.QUERY, "with space", 0),
    (InjectionLocation.QUERY, "a" * 65, 0), (InjectionLocation.QUERY, 2, 0),
    (InjectionLocation.QUERY, "name", True), (InjectionLocation.QUERY, "name", -1),
    (InjectionLocation.QUERY, "name", 1024), (InjectionLocation.JSON, "not-pointer", 0),
    (InjectionLocation.JSON, "/invalid~2", 0), (InjectionLocation.JSON, "/a\n", 0),
    (InjectionLocation.JSON, "/" + "a" * 256, 0),
    (InjectionLocation.JSON, "/a", 1), (InjectionLocation.PATH, "user_id", 1),
    (InjectionLocation.BODY, "", 1), (InjectionLocation.GRAPHQL, "/query", 0),
    (InjectionLocation.GRAPHQL, "/variables/", 0),
], ids=(
    "untyped-location", "selector-space", "oversized-name", "non-text-selector",
    "boolean-occurrence", "negative-occurrence", "oversized-occurrence", "non-pointer",
    "invalid-pointer-escape", "pointer-newline", "oversized-pointer", "json-occurrence",
    "path-occurrence", "text-occurrence", "graphql-query-selector", "empty-graphql-variable",
))
def test_InvalidInjectionCoordinatesFailClosed(location, selector, occurrence):
    """Invalid names, pointer escapes and duplicate-field semantics are never silently coerced."""

    with pytest.raises(ValueError):
        InjectionPoint(location, selector, ValueBinding("input"), occurrence)


def test_InjectionRequiresBindingAndRequestOwner():
    """An injection point always names a typed binding and is bound to a valid template digest."""

    with pytest.raises(ValueError):
        InjectionPoint(InjectionLocation.QUERY, "name", "literal-value")

    point = Template().injection_points[0]

    for reference in ("request:forged", "object:" + "a" * 64, None):
        with pytest.raises(ValueError):
            point.Reference(reference)


def test_CanonicalPointOrderAndRepeatedFieldIdentity():
    """Sorting removes producer order while distinct repeated-field occurrences remain distinct."""

    template = Template()
    reordered = replace(template, injection_points=tuple(reversed(template.injection_points)))
    assert reordered == template and reordered.ToJson() == template.ToJson(), "Producer order drift"
    point = InjectionPoint(InjectionLocation.HEADER, "X-Test", ValueBinding("one"))
    same_coordinate = replace(point, selector="x-TEST", binding=ValueBinding("two"))

    with pytest.raises(ValueError, match="unique"):
        RequestTemplate(template.endpoint, (point, same_coordinate))

    different_occurrence = replace(point, occurrence=1)
    repeated = RequestTemplate(template.endpoint, (point, different_occurrence))
    assert len(repeated.injection_points) == 2, (
        "Different repeated-field occurrences were incorrectly collapsed"
    )


@pytest.mark.parametrize("point,body_kind", [
    (InjectionPoint(InjectionLocation.BODY, "form", ValueBinding("form")), BodyKind.NONE),
    (InjectionPoint(InjectionLocation.BODY, "", ValueBinding("body")), BodyKind.FORM),
    (InjectionPoint(InjectionLocation.JSON, "/id", ValueBinding("id")), BodyKind.FORM),
    (InjectionPoint(InjectionLocation.GRAPHQL, "/variables/id", ValueBinding("id")), BodyKind.JSON),
    (InjectionPoint(InjectionLocation.MULTIPART, "file", ValueBinding("file")), BodyKind.TEXT),
    (InjectionPoint(InjectionLocation.PATH, "unknown", ValueBinding("unknown")), BodyKind.NONE),
])
def test_EncodingAndDeclaredPathOwnershipAreMandatory(point, body_kind):
    """A well-formed coordinate still fails when its encoding or declared route does not match."""

    with pytest.raises(ValueError):
        RequestTemplate(Template().endpoint, (point,), body_kind)


def test_SessionBindingRequiresSameWorkspaceReference():
    """A named session input is useful only with an unresolved same-workspace session reference."""

    endpoint = Template().endpoint
    point = InjectionPoint(
        InjectionLocation.COOKIE, "sid", ValueBinding("cookie", BindingSource.SESSION),
    )

    with pytest.raises(ValueError, match="require a session"):
        RequestTemplate(endpoint, (point,))

    for session in (SessionReference("other", "operator"), "cookie-value"):
        with pytest.raises(ValueError):
            RequestTemplate(endpoint, (point,), session_reference=session)

    template = RequestTemplate(
        endpoint, (point,), session_reference=SessionReference("demo", "user"),
    )
    assert RequestTemplate.FromJson(template.ToJson()) == template, "Session-bound template drift"
    assert "cookie-value" not in template.ToJson(), "A symbolic reference became a cookie value"


def test_GraphqlOperationIsOptionalTypedStructure():
    """Operation names do not store GraphQL documents and cannot decorate other encodings."""

    template = RequestTemplate(Template().endpoint, body_kind=BodyKind.GRAPHQL)
    named = replace(template, graphql_operation="FindUser")
    assert RequestTemplate.FromDict(named.ToDict()) == named, "GraphQL operation name was changed"

    for value in ("query { secret }", "1bad", "a" * 65, 5):
        with pytest.raises(ValueError):
            replace(template, graphql_operation=value)

    with pytest.raises(ValueError):
        replace(Template(), graphql_operation="FindUser")


@pytest.mark.parametrize("field,value", [
    ("endpoint", "https://example.test"), ("body_kind", "none"),
    ("injection_points", "captured body"), ("injection_points", ("invalid",)),
    ("injection_points", Template().injection_points * (MAX_INJECTION_POINTS + 1)),
], ids=(
    "untyped-endpoint", "untyped-encoding", "untyped-point-list", "untyped-point",
    "too-many-points",
))
def test_TemplateRequiresBoundedTypedInputs(field, value):
    """Direct constructors reject untyped fields before digest creation."""

    with pytest.raises(ValueError):
        replace(Template(), **{field: value})


def test_TemplateSizeBoundAppliesBeforeStorage():
    """Large individually valid pointers cannot exceed the template's aggregate byte budget."""

    points = tuple(
        InjectionPoint(InjectionLocation.JSON, f"/{index}/" + "x" * 240, ValueBinding("a" * 64))
        for index in range(MAX_INJECTION_POINTS)
    )
    assert RequestTemplate(Template().endpoint, points, BodyKind.JSON).ToJson(), (
        "Valid bounded aggregate template was unexpectedly rejected"
    )
    larger_points = tuple(
        replace(point, selector=f"/{index}/" + "\u0080" * 240)
        for index, point in enumerate(points)
    )

    with pytest.raises(ValueError, match="size bound"):
        RequestTemplate(Template().endpoint, larger_points, BodyKind.JSON)


def test_ModelProjectionGroupsTemplatesAndRejectsForeignObjects():
    """The projection reuses one Endpoint and handles multiple template shapes without new state."""

    first = Template()
    second = replace(first, injection_points=())
    projected = ProjectRequests((first, second), provenance=Attribution())
    expected = tuple(sorted((first, second), key=RequestTemplate.Reference))
    assert RequestsFromObject(projected) == expected, "Projection did not preserve both templates"
    empty = SecurityObject(first.endpoint.Identity(), provenance=Attribution())
    assert RequestsFromObject(empty) == (), "Absent projection did not remain empty"
    assert RequestsFromObject(replace(empty, attributes={"request_templates": []})) == (), (
        "Explicit empty request collection could not be reopened"
    )

    for templates in ((), "invalid", (first, "invalid"), (first, first), (
        first, replace(first, endpoint=replace(first.endpoint, workspace_id="other")),
    )):
        with pytest.raises(ValueError):
            ProjectRequests(templates, provenance=Attribution())

    asset = SecurityObject(
        ObjectIdentity("demo", ObjectKind.ASSET, "asset"), provenance=Attribution(),
    )

    for value in ("invalid", asset):
        with pytest.raises(ValueError):
            RequestsFromObject(value)


def test_ProjectionConsumerRejectsMalformedForeignOrDuplicateTemplates():
    """Real model attribute consumers revalidate structure, membership and collection order."""

    first = Template()
    second = replace(first, injection_points=())
    records = (first.ToDict(), second.ToDict())
    ordered = sorted(records, key=lambda record: record["request_reference"])
    foreign = replace(first, endpoint=replace(first.endpoint, workspace_id="other"))

    invalid_records = (
        {}, [first.ToDict(), first.ToDict()], list(reversed(ordered)), [foreign.ToDict()],
    )

    for records in invalid_records:
        with pytest.raises(ValueError):
            RequestsFromObject(SecurityObject(
                first.endpoint.Identity(), {"request_templates": records}, Attribution(),
            ))


@pytest.mark.parametrize("value", [
    5, "[", "null", "[]", " " * (MAX_REQUEST_BYTES + 1),
    '{"schema_version":1,"schema_version":1}', '{"field":NaN}',
    '{"field":Infinity}', '\ud800', "[" * 2000,
], ids=(
    "non-text", "malformed-json", "null", "array", "oversized-json", "duplicate-key",
    "nan", "infinity", "invalid-utf8", "excessive-nesting",
))
def test_JsonRejectsAmbiguousOversizedAndInvalidText(value):
    """Strict bounded JSON rejects duplicate keys, constants, malformed UTF-8 and deep nesting."""

    with pytest.raises(ValueError):
        RequestTemplate.FromJson(value)
