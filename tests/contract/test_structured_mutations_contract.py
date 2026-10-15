# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify exact mutation bodies and provenance against handwritten JSON consumer contracts."""

from __future__ import annotations

import hashlib
import json
import socket
from dataclasses import FrozenInstanceError

import pytest
from jsonschema import Draft202012Validator, ValidationError

from fuzzy1337.requests import (
    BodyKind,
    Endpoint,
    InjectionLocation,
    InjectionPoint,
    RequestTemplate,
    ValueBinding,
)
from fuzzy1337.structured_mutations import (
    GenerateJsonMutations,
    JsonMutationLimits,
    JsonMutationProfile,
    JsonMutationSelection,
    ReplayJsonMutation,
)


def Template():
    """Construct a synthetic caller-owned JSON input using the original request contract."""

    endpoint = Endpoint("mutation-contract", "http://127.0.0.1:19001", "/owned", "POST")

    return RequestTemplate(endpoint,
        (InjectionPoint(InjectionLocation.JSON, "", ValueBinding("body")),), BodyKind.JSON)


def test_IndependentJsonOracleChecksEscapedPointersArraysAndUnchangedSiblings():
    """Each candidate changes exactly one predeclared coordinate in the original document."""

    body = b'{"a/b~c":{"values":[true,false]},"keep":{"nested":"same"}}'
    selections = (JsonMutationSelection("/a~1b~0c/values/0"),
                  JsonMutationSelection("/a~1b~0c/values/1"))
    results = GenerateJsonMutations(Template(), body, selections, seed=0)
    assert [json.loads(result.body) for result in results] == [
        {"a/b~c": {"values": [False, False]}, "keep": {"nested": "same"}},
        {"a/b~c": {"values": [True, True]}, "keep": {"nested": "same"}},
    ], "JSON consumer observed a mutation outside the selected coordinate"
    assert body == b'{"a/b~c":{"values":[true,false]},"keep":{"nested":"same"}}', (
        "Mutation changed caller-owned source bytes"
    )


def test_SeededOrderAndEveryMetadataIdentityCanBeRecomputedWithoutProducerHelpers():
    """Canonical JSON plus hashlib verify the complete externally visible provenance payload."""

    template = Template()
    body = b'{"value":1}'
    selection = JsonMutationSelection("/value")
    candidates = GenerateJsonMutations(template, body, (selection,), seed=17)
    assert [(item.variant, json.loads(item.body)) for item in candidates] == [
        ("int32-max", {"value": 2147483647}), ("zero", {"value": 0}),
        ("int32-min", {"value": -2147483648}), ("negative", {"value": -1}),
    ], "Versioned seed/corpus ordering drifted"
    expected_configuration = {
        "seed": 17, "profile": "scalar-boundaries-v1",
        "selections": [{"pointer": "/value", "decoded_pointer": None}],
        "limits": {"max_depth": 16, "max_nodes": 4096, "max_body_bytes": 65536,
                   "max_decoded_bytes": 131072, "max_mutations": 64, "max_output_bytes": 1048576},
    }

    for candidate in candidates:
        metadata = candidate.Metadata()
        assert metadata["schema_version"] == 1, "Metadata version is missing"
        assert metadata["configuration"] == expected_configuration, "Complete configuration lost"
        assert metadata["source_body_digest"] == "sha256:" + hashlib.sha256(body).hexdigest(), (
            "Source attribution did not retain exact input bytes"
        )
        assert metadata["body_digest"] == "sha256:" + hashlib.sha256(candidate.body).hexdigest(), (
            "Candidate digest does not bind actual bytes"
        )
        assert metadata["template_reference"] == template.Reference(), "Template ownership lost"
        assert metadata["selection"] == {"pointer": "/value", "decoded_pointer": None}, (
            "Mutation path differs from the selected coordinate"
        )
        assert metadata["selection_index"] == 0, "Selection ordering is not explicit"
        assert metadata["encoding_chain"] == ["json-utf8"], "Unselected decoder was introduced"
        identity = {key: value for key, value in metadata.items() if key != "mutation_reference"}
        encoded = json.dumps({"namespace": "json-mutation", "identity": identity},
                             ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        assert metadata["mutation_reference"] == "json-mutation:" + hashlib.sha256(
            encoded
        ).hexdigest(), "Provenance reference cannot be independently recomputed"
        assert ReplayJsonMutation(template, body, candidate,
            expected_reference=candidate.Reference()) == candidate, "Replay drifted"

    assert GenerateJsonMutations(template, body, (selection,), seed=17) == candidates, (
        "Identical complete input did not reproduce byte-identical candidates"
    )
    changed = GenerateJsonMutations(template, body, (selection,), seed=18)
    assert changed != candidates and changed[0].Metadata() != candidates[0].Metadata(), (
        "Changed seed did not change candidate attribution"
    )


def test_ExplicitJsonStringDecodingChangesOnlyTheSelectedInnerScalar():
    """A handwritten two-stage JSON consumer verifies re-encoding and preserved outer structure."""

    source = b'{"packed":"{\\"a/b\\":[true,false]}","unselected":"{\\"x\\":true}"}'
    selected = JsonMutationSelection("/packed", "/a~1b/0")
    candidate = GenerateJsonMutations(Template(), source, (selected,), seed=0)[0]
    outer = json.loads(candidate.body)
    assert json.loads(outer["packed"]) == {"a/b": [False, False]}, "Inner semantic mutation failed"
    assert outer["unselected"] == '{"x":true}', "Another JSON-looking string was decoded"
    assert candidate.Metadata()["encoding_chain"] == ["json-utf8", "json-string"], (
        "Explicit decoder provenance was lost"
    )
    assert candidate.Metadata()["selection"] == {"pointer": "/packed", "decoded_pointer": "/a~1b/0"}
    raw_candidates = GenerateJsonMutations(Template(), source,
                                          (JsonMutationSelection("/packed"),), seed=0)
    assert {json.loads(item.body)["packed"] for item in raw_candidates} == {
        "", "1337", "'\"\\", "\x00",
    }, "JSON-looking strings were implicitly decoded"


def test_RootSelectionsAndDecodedRootSelectionsRemainUnambiguous():
    """Root scalar documents are legitimate; None never aliases the decoded empty pointer."""

    root = GenerateJsonMutations(Template(), b"true", (JsonMutationSelection(""),), seed=0)
    nested = GenerateJsonMutations(Template(), b'"true"',
                                  (JsonMutationSelection("", ""),), seed=0)
    assert root[0].body == b"false" and nested[0].body == b'"false"', "Root encoding was lost"
    assert root[0].Metadata()["selection"] != nested[0].Metadata()["selection"], (
        "Raw and decoded root identities collided"
    )


def test_TypePreservationIsExplicitlyWeakerThanIndependentSchemaValidity():
    """The API does not imply that preserving a scalar type preserves original constraints."""

    validator = Draft202012Validator({"type": "object", "properties": {
        "value": {"type": "integer", "minimum": 1},
    }})
    candidates = GenerateJsonMutations(Template(), b'{"value":1}',
                                      (JsonMutationSelection("/value"),), seed=17)
    zero = next(item for item in candidates if item.variant == "zero")

    with pytest.raises(ValidationError):
        validator.validate(json.loads(zero.body))

    deliberate = GenerateJsonMutations(Template(), b'{"value":1}',
        (JsonMutationSelection("/value"),), seed=17, profile=JsonMutationProfile.TYPE_CHANGE)
    assert any(isinstance(json.loads(item.body)["value"], dict) for item in deliberate), (
        "Type-change profile did not retain its deliberate structural distinction"
    )


def test_GenerationUsesNoNetworkAndCandidatesAreImmutable(monkeypatch):
    """Real interface execution does not create sockets or resolve any destination."""

    def Forbidden(*args, **kwargs):
        """Fail if an offline transformer attempts any transport activity."""

        raise AssertionError("offline mutation attempted transport")

    monkeypatch.setattr(socket, "socket", Forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", Forbidden)
    candidate = GenerateJsonMutations(Template(), b'{"value":true}',
        (JsonMutationSelection("/value"),), seed=2**64 - 1,
        limits=JsonMutationLimits(max_mutations=1))[0]

    with pytest.raises(FrozenInstanceError):
        candidate.body = b"changed"

    assert candidate.body == b'{"value":false}', "Offline candidate does not match its oracle"
