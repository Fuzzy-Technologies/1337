# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise strict selection, bounded decoding, finite corpora and mutation replay failures."""

from __future__ import annotations

import json
from dataclasses import replace
from traceback import format_exception

import pytest

from fuzzy1337.requests import (
    BindingSource,
    BodyKind,
    Endpoint,
    InjectionLocation,
    InjectionPoint,
    RequestTemplate,
    SessionReference,
    ValueBinding,
)
from fuzzy1337.structured_mutations import (
    GenerateJsonMutations,
    JsonMutationLimits,
    JsonMutationProfile,
    JsonMutationSelection,
    ReplayJsonMutation,
)


def Template(selector=""):
    """Declare one explicitly owned synthetic JSON input without permission or credentials."""

    return RequestTemplate(Endpoint("mutation-unit", "http://127.0.0.1:19001", "/owned", "POST"),
        (InjectionPoint(InjectionLocation.JSON, selector, ValueBinding("payload")),), BodyKind.JSON)


def Generate(body=b'{"value":1}', *, selections=None, **options):
    """Run the public mutation interface with a fixed synthetic seed and declared body input."""

    return GenerateJsonMutations(Template(), body,
        (JsonMutationSelection("/value"),) if selections is None else selections,
        seed=options.pop("seed", 17), **options)


@pytest.mark.parametrize("source,expected", [
    ("text", ["", "1337", "'\"\\", "\x00"]),
    (0, [-1, 2147483647, -2147483648]),
    (1.5, [0.0, -1.5]),
    (False, [True]),
])
def test_HandwrittenScalarBoundaryCorporaPreserveTypesAndSkipUnchangedValues(source, expected):
    """Known expected scalars independently detect missing boundaries or no-op candidates."""

    actual = [json.loads(item.body)["value"]
              for item in Generate(json.dumps({"value": source}).encode())]
    assert sorted(actual, key=repr) == sorted(expected, key=repr), "Scalar corpus differs"
    assert all(type(value) is type(source) for value in actual), "Scalar type changed"


@pytest.mark.parametrize("source", [None, False, 5, 1.5, "text"])
def test_TypeChangeProfileIntentionallyChangesJsonTypes(source):
    """Every selected replacement differs in JSON type, with int/float treated as numbers."""

    candidates = Generate(json.dumps({"value": source}).encode(),
                          profile=JsonMutationProfile.TYPE_CHANGE)
    expected = [None, False, 0, "1337", [], {}]
    expected = [value for value in expected if type(value) is not type(source)
                and not (type(source) is float and type(value) is int)]
    actual = [json.loads(item.body)["value"] for item in candidates]
    assert sorted(actual, key=repr) == sorted(expected, key=repr), "Type-change corpus differs"


@pytest.mark.parametrize("body", [
    b"", b"{", b'{"value":NaN}', b'{"value":Infinity}', b'{"value":-Infinity}',
    b'{"value":1e999}', b'{"value":1,"value":2}', b'{"value":"\\ud800"}',
    b'{"\\ud800":1}', b'{"value":"\xff"}', b'{"value":1} trailing',
    b"[" * 1500 + b"0" + b"]" * 1500,
    "{\"value\":1}", bytearray(b'{"value":1}'), None,
])
def test_MalformedAmbiguousAndNonUtf8SourcesFailClosed(body):
    """Strict decoder errors cannot produce apparently valid mutation outputs."""

    with pytest.raises(ValueError, match="bounded JSON mutation"):
        Generate(body)


@pytest.mark.parametrize("pointer", ["not/a/pointer", "/bad~2", "/\n", "/" + "x" * 256, None])
def test_InvalidPointerGrammarFailsBeforeBodyAccess(pointer):
    """Existing request pointer validation remains the sole coordinate grammar."""

    with pytest.raises(ValueError):
        JsonMutationSelection(pointer)

    with pytest.raises(ValueError):
        JsonMutationSelection("/value", pointer if pointer is not None else 1)


@pytest.mark.parametrize("pointer", ["/missing", "/value/0", "/array/01", "/array/-1",
                                       "/array/-", "/array/1", "/array/9"])
def test_UnresolvedAndNoncanonicalArraySelectorsFailClosed(pointer):
    """Missing fields, scalar descent, append syntax and padded indexes are never guessed."""

    with pytest.raises(ValueError):
        Generate(b'{"value":1,"array":[2]}', selections=(JsonMutationSelection(pointer),))


@pytest.mark.parametrize("body", [b'{"value":null}', b'{"value":[]}', b'{"value":{}}'])
def test_UnsupportedTypePreservingSelectionsAreExplicitRefusals(body):
    """Null has no alternate value; container shape mutation belongs to another profile."""

    with pytest.raises(ValueError):
        Generate(body)


@pytest.mark.parametrize("selections", [(), [], ("/value",),
    (JsonMutationSelection("/value"), JsonMutationSelection("/value")),
    (JsonMutationSelection("/value"), JsonMutationSelection("/value", "")),
    tuple(JsonMutationSelection(f"/{index}") for index in range(65)),
])
def test_SelectionsMustBeAnExplicitBoundedUniqueTuple(selections):
    """No caller order, duplicate or count ambiguity is silently normalized."""

    with pytest.raises(ValueError):
        Generate(selections=selections)


@pytest.mark.parametrize("field,ceiling", [
    ("max_depth", 16), ("max_nodes", 4096), ("max_body_bytes", 65536),
    ("max_decoded_bytes", 131072), ("max_mutations", 64), ("max_output_bytes", 1048576),
])
@pytest.mark.parametrize("invalid", ["boolean", "zero", "negative", "above", "float"])
def test_BudgetConfigurationCannotRelaxHardCeilings(field, ceiling, invalid):
    """Every independent limit rejects misleading booleans and invalid numeric spellings."""

    values = {"boolean": True, "zero": 0, "negative": -1, "above": ceiling + 1, "float": 1.0}

    with pytest.raises(ValueError):
        JsonMutationLimits(**{field: values[invalid]})


@pytest.mark.parametrize("options", [
    {"seed": True}, {"seed": -1}, {"seed": 2**64}, {"seed": "17"},
    {"profile": "scalar-boundaries-v1"}, {"limits": {}},
])
def test_ConfigurationTypesAndSeedBoundsAreStrict(options):
    """String aliases and untyped limits do not weaken versioned configuration validation."""

    with pytest.raises(ValueError):
        Generate(**options)


@pytest.mark.parametrize("limits", [
    JsonMutationLimits(max_body_bytes=10), JsonMutationLimits(max_nodes=2),
    JsonMutationLimits(max_mutations=3), JsonMutationLimits(max_output_bytes=30),
    JsonMutationLimits(max_decoded_bytes=10),
])
def test_RealByteNodeCountAndAggregateOutputBudgetsFailWithoutPartialResults(limits):
    """Actual source and complete corpus sizes, rather than caller estimates, decide limits."""

    with pytest.raises(ValueError):
        Generate(limits=limits)


def test_ExactlyBoundedDepthAndNodesAreAcceptedBeforeOneExtraLevelIsRejected():
    """Depth counts the root at zero and object keys as nodes at their member level."""

    body = b'{"outer":{"value":true}}'
    selection = (JsonMutationSelection("/outer/value"),)
    result = Generate(body, selections=selection,
                      limits=JsonMutationLimits(max_depth=2, max_nodes=5))
    assert result[0].body == b'{"outer":{"value":false}}', "Exact bounds were not honored"

    with pytest.raises(ValueError):
        Generate(body, selections=selection, limits=JsonMutationLimits(max_depth=1))


@pytest.mark.parametrize("body,selection", [
    (b'{"value":true}', JsonMutationSelection("/value", "")),
    (b'{"value":"not-json"}', JsonMutationSelection("/value", "")),
    (b'{"value":"{\\"a\\":1,\\"a\\":2}"}', JsonMutationSelection("/value", "/a")),
    (b'{"value":"{\\"a\\":true}"}', JsonMutationSelection("/value", "/missing")),
])
def test_ExplicitStringDecodingDoesNotAcceptInvalidInnerData(body, selection):
    """Opt-in decoding retains strict parsing and exact pointer resolution at the inner layer."""

    with pytest.raises(ValueError):
        Generate(body, selections=(selection,))


def test_DecodedDepthNodesAndBytesAggregateAcrossDistinctSelectedStrings():
    """Multiple small decoded documents cannot individually evade the aggregate budget."""

    body = b'{"a":"{\\"x\\":true}","b":"{\\"y\\":false}"}'
    selections = (JsonMutationSelection("/a", "/x"), JsonMutationSelection("/b", "/y"))
    assert len(Generate(body, selections=selections)) == 2, "Explicit nested selections failed"

    for limits in [JsonMutationLimits(max_depth=2), JsonMutationLimits(max_nodes=10),
                   JsonMutationLimits(max_decoded_bytes=len(body) + 20)]:
        with pytest.raises(ValueError):
            Generate(body, selections=selections, limits=limits)


def test_ReusingOneExplicitDecodedDocumentCountsItOnce():
    """Two independent scalar selections share one bounded decode, never recursive guessing."""

    body = b'{"value":"{\\"a\\":true,\\"b\\":false}"}'
    selections = (JsonMutationSelection("/value", "/a"), JsonMutationSelection("/value", "/b"))
    result = Generate(body, selections=selections,
                      limits=JsonMutationLimits(max_nodes=8, max_decoded_bytes=len(body) + 22))
    assert len(result) == 2, "The same string was charged or decoded twice"


def test_NondeclaredCoordinatesSessionsAndNonJsonTemplatesCannotBecomeInputs():
    """Template structure is reused without resolving credentials or adding symbolic inputs."""

    endpoint = Template().endpoint
    session = SessionReference(endpoint.workspace_id, "owned")
    templates = [None, RequestTemplate(endpoint), Template("/other"),
        replace(Template(), session_reference=session),
        RequestTemplate(endpoint, (InjectionPoint(InjectionLocation.JSON, "",
            ValueBinding("payload", BindingSource.SESSION)),), BodyKind.JSON, session)]

    for template in templates:
        with pytest.raises(ValueError):
            GenerateJsonMutations(template, b'{"value":1}', (JsonMutationSelection("/value"),),
                                  seed=17)


def test_DeclaredArrayCoordinateOwnsItsExplicitConcreteElement():
    """An importer array coordinate permits explicit element selection, without a wildcard."""

    result = GenerateJsonMutations(Template("/flags"), b'{"flags":[true,false]}',
                                  (JsonMutationSelection("/flags/0"),), seed=0)
    assert result[0].body == b'{"flags":[false,false]}', "Array member replacement changed siblings"


@pytest.mark.parametrize("change", ["body", "template", "seed", "variant", "candidate", "type"])
def test_ReplayRejectsEveryChangedSourceAttributionOrCandidate(change):
    """Recomputation verifies full candidate equality rather than trusting recorded digests."""

    template, body = Template(), b'{"value":1}'
    mutation = Generate(body)[0]
    reference = mutation.Reference()

    if change == "body":
        body += b" "

    elif change == "template":
        template = replace(template, endpoint=replace(template.endpoint, workspace_id="other"))

    elif change == "seed":
        mutation = replace(mutation, seed=18)

    elif change == "variant":
        mutation = replace(mutation, variant="invented")

    elif change == "candidate":
        mutation = replace(mutation, body=b'{"value":999}')

    else:
        mutation = None

    with pytest.raises(ValueError):
        ReplayJsonMutation(template, body, mutation, expected_reference=reference)


@pytest.mark.parametrize("reference", [None, "bad", "json-mutation:" + "0" * 64])
def test_ReplayRequiresAnIndependentlyRetainedExactReference(reference):
    """Missing or different expected references cannot turn recomputation into integrity proof."""

    mutation = Generate()[0]

    with pytest.raises(ValueError):
        ReplayJsonMutation(Template(), b'{"value":1}', mutation, expected_reference=reference)


@pytest.mark.parametrize("index", [False, True, 0.0, 1.0, -1, 1, "synthetic-private-index", None])
def test_ReplayRejectsNonIntegerAndOutOfRangeIndexesDespiteDataclassEquality(index):
    """Python's False/zero/float equality cannot replace exact canonical candidate attribution."""

    mutation = Generate(b'{"value":true}')[0]
    altered = replace(mutation, selection_index=index)

    with pytest.raises(ValueError, match="replay candidate metadata") as caught:
        ReplayJsonMutation(Template(), b'{"value":true}', altered,
                           expected_reference=mutation.Reference())

    assert "synthetic-private-index" not in "".join(format_exception(caught.value)), (
        "Malformed candidate field leaked into diagnostics"
    )


@pytest.mark.parametrize("field,value", [
    ("body", bytearray(b'{"value":false}')), ("variant", {"synthetic-private-variant"}),
])
def test_ReplayRejectsMutableBodiesAndMalformedCandidateMetadata(field, value):
    """Bytes equality and serialization errors cannot silently validate forged candidate fields."""

    mutation = Generate(b'{"value":true}')[0]
    altered = replace(mutation, **{field: value})

    with pytest.raises(ValueError, match="replay candidate metadata") as caught:
        ReplayJsonMutation(Template(), b'{"value":true}', altered,
                           expected_reference=mutation.Reference())

    assert "synthetic-private-variant" not in "".join(format_exception(caught.value)), (
        "Malformed candidate metadata leaked into diagnostics"
    )


def test_EncodedOutputMustAlsoFitTheAggregateDecodedBudget():
    """A slightly larger replacement cannot pass a budget that only fits the original input."""

    body = b'{"value":"true"}'

    with pytest.raises(ValueError):
        Generate(body, selections=(JsonMutationSelection("/value", ""),),
                 limits=JsonMutationLimits(max_decoded_bytes=len(body) + 4))


def test_ParserDiagnosticsAndRepresentationDoNotExposeSourceValues():
    """Duplicate-key parser detail is suppressed at the public boundary and body repr is hidden."""

    marker = "synthetic-private-input"
    body = ('{"' + marker + '":1,"' + marker + '":2}').encode()

    with pytest.raises(ValueError) as caught:
        Generate(body)

    diagnostic = "".join(format_exception(caught.value))
    assert marker not in diagnostic, "Duplicate-key detail leaked source material"
    candidate = Generate(json.dumps({"value": marker}).encode())[0]
    assert marker not in repr(candidate) and "body=" not in repr(candidate), "Body repr leaked"
    assert marker not in json.dumps(candidate.Metadata()), "Metadata leaked a source value"
