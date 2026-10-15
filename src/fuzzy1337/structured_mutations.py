# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Prepare bounded JSON body mutations without transmission, schema proof or model authority."""

from __future__ import annotations

import hashlib
import json
import math
import re
from copy import deepcopy
from dataclasses import dataclass, field
from enum import StrEnum
from typing import cast

from fuzzy1337.model import CanonicalModelJson
from fuzzy1337.requests import (
    BindingSource,
    BodyKind,
    InjectionLocation,
    RequestDigest,
    RequestTemplate,
    RequirePointer,
)
from fuzzy1337.workspace import RejectWorkspaceConstant, UniqueWorkspaceObject

__all__ = [
    "JsonMutation", "JsonMutationLimits", "JsonMutationProfile", "JsonMutationSelection",
    "GenerateJsonMutations", "ReplayJsonMutation",
]


class JsonMutationProfile(StrEnum):
    """Select a fixed scalar corpus; type preservation never asserts schema validity."""

    SCALAR_BOUNDARIES = "scalar-boundaries-v1"
    TYPE_CHANGE = "type-change-v1"


@dataclass(frozen=True, slots=True)
class JsonMutationLimits:
    """Bound complete decoding and all output, with ceilings independent of caller choices."""

    max_depth: int = 16
    max_nodes: int = 4096
    max_body_bytes: int = 64 * 1024
    max_decoded_bytes: int = 128 * 1024
    max_mutations: int = 64
    max_output_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        """Reject booleans, nonpositive budgets and values above the profile's hard ceilings."""

        ceilings = (16, 4096, 64 * 1024, 128 * 1024, 64, 1024 * 1024)

        for value, ceiling in zip(self.ToDict().values(), ceilings, strict=True):
            if type(value) is not int or not 0 < value <= ceiling:
                raise ValueError("JSON mutation budget is outside its hard bound")

    def ToDict(self) -> dict[str, int]:
        """Expose every actual resource bound for replayable configuration attribution.

        Returns:
            Exact named integer budgets, in the validation ceiling order.
        """

        return {
            "max_depth": self.max_depth, "max_nodes": self.max_nodes,
            "max_body_bytes": self.max_body_bytes, "max_decoded_bytes": self.max_decoded_bytes,
            "max_mutations": self.max_mutations, "max_output_bytes": self.max_output_bytes,
        }


@dataclass(frozen=True, slots=True)
class JsonMutationSelection:
    """Address one scalar, optionally inside one explicitly selected JSON string."""

    pointer: str
    decoded_pointer: str | None = None

    def __post_init__(self) -> None:
        """Reuse the structural request pointer grammar, including its bounded root selector."""

        RequirePointer(self.pointer)

        if self.decoded_pointer is not None:
            RequirePointer(self.decoded_pointer)

        CanonicalModelJson(self.ToDict())

    def ToDict(self) -> dict[str, object]:
        """Expose exact structural paths without interpreting their contents.

        Returns:
            Outer and optional inner pointers; None and an inner root remain distinct.
        """

        return {"pointer": self.pointer, "decoded_pointer": self.decoded_pointer}


@dataclass(frozen=True, slots=True)
class JsonMutation:
    """Hold an ephemeral candidate and replay configuration, never an executable request."""

    template_reference: str
    source_body_digest: str
    selections: tuple[JsonMutationSelection, ...]
    seed: int
    profile: JsonMutationProfile
    limits: JsonMutationLimits
    selection_index: int
    variant: str
    body: bytes = field(repr=False)

    def Reference(self) -> str:
        """Compute the full mutation digest for an independent subsequent replay anchor.

        Returns:
            Domain-separated SHA-256 reference binding complete metadata and output bytes.
        """

        return cast(str, self.Metadata()["mutation_reference"])

    def Metadata(self) -> dict[str, object]:
        """Bind exact bytes and complete configuration without exposing concrete source values.

        Returns:
            Reference metadata. Structural selectors must themselves be non-secret.
            Caller attribution does not prove a body originated from a template or schema.
        """

        selection = self.selections[self.selection_index]
        configuration = {
            "seed": self.seed, "profile": self.profile.value, "limits": self.limits.ToDict(),
            "selections": [item.ToDict() for item in self.selections],
        }
        metadata = {
            "schema_version": 1, "template_reference": self.template_reference,
            "source_body_digest": self.source_body_digest, "configuration": configuration,
            "configuration_reference": RequestDigest("json-mutation-config", configuration),
            "selection_index": self.selection_index, "selection": selection.ToDict(),
            "encoding_chain": ["json-utf8"] + (
                ["json-string"] if selection.decoded_pointer is not None else []
            ),
            "variant": self.variant, "body_digest": BodyDigest(self.body),
        }

        return {**metadata, "mutation_reference": RequestDigest("json-mutation", metadata)}


def BodyDigest(value: bytes) -> str:
    """Bind the exact original or generated byte sequence without normalization.

    Args:
        value: Byte-bounded original or generated body.

    Returns:
        Algorithm-prefixed lowercase SHA-256 digest.
    """

    return "sha256:" + hashlib.sha256(value).hexdigest()


def InspectTree(value: object, limits: JsonMutationLimits, *, depth: int = 0) -> int:
    """Count nodes including keys and reject invalid Unicode, nonfinite values and deep trees.

    Args:
        value: Strict decoded JSON tree or one generated candidate.
        limits: Current hard-bounded node and depth budgets.
        depth: Initial depth, including an explicitly selected outer decoder path.

    Returns:
        Number of decoded value and object-key nodes.

    Raises:
        ValueError: A node, depth, numeric or Unicode boundary is violated.
    """

    pending = [(value, depth)]
    nodes = 0

    while pending:
        current, level = pending.pop()
        nodes += 1

        if nodes > limits.max_nodes or level > limits.max_depth:
            raise ValueError("JSON mutation tree exceeds its node or depth budget")

        if isinstance(current, dict):
            pending.extend((item, level + 1) for pair in current.items() for item in pair)

        elif isinstance(current, list):
            pending.extend((item, level + 1) for item in current)

        elif isinstance(current, str):
            current.encode("utf-8")

        elif isinstance(current, float) and not math.isfinite(current):
            raise ValueError("JSON mutation tree contains a nonfinite number")

    return nodes


def DecodeBody(value: bytes, limits: JsonMutationLimits, *, depth: int = 0) -> tuple[object, int]:
    """Strictly decode one UTF-8 body using existing duplicate-key guards.

    Args:
        value: Actual bytes, checked before decoding without BOM or replacement decoding.
        limits: Current byte, node and depth budgets.
        depth: Root depth within the complete explicitly selected decoding chain.

    Returns:
        Decoded tree and its inspected node count.

    Raises:
        ValueError: Bytes, strict JSON, Unicode or inspected resource bounds are invalid.
    """

    if type(value) is not bytes or len(value) > limits.max_body_bytes:
        raise ValueError("JSON mutation body exceeds its byte budget")

    decoded = json.loads(value.decode("utf-8"), object_pairs_hook=UniqueWorkspaceObject,
                         parse_constant=RejectWorkspaceConstant)

    return decoded, InspectTree(decoded, limits, depth=depth)


def PointerTokens(pointer: str) -> tuple[str, ...]:
    """Decode validated RFC 6901 tokens without URI, wildcard or automatic string decoding.

    Args:
        pointer: Selection pointer already checked by the structural request contract.

    Returns:
        Exact unescaped tokens, or an empty tuple for the root.
    """

    return tuple(token.replace("~1", "/").replace("~0", "~")
                 for token in pointer[1:].split("/")) if pointer else ()


def Child(value: object, token: str) -> object:
    """Resolve one exact existing object key or canonical nonnegative array index.

    Args:
        value: Decoded parent node.
        token: One unescaped pointer component.

    Returns:
        Existing child value without copying, decoding or coercion.

    Raises:
        ValueError: The parent, object key or canonical in-range index does not resolve.
    """

    if isinstance(value, dict) and token in value:
        return cast(object, value[token])

    if isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", token):
        index = int(token)

        if index < len(value):
            return cast(object, value[index])

    raise ValueError("JSON mutation selector does not resolve")


def Resolve(value: object, tokens: tuple[str, ...]) -> object:
    """Follow an explicit bounded token path in an already decoded tree.

    Args:
        value: Root of the selected decoded document.
        tokens: Validated unescaped path components.

    Returns:
        Existing selected node, or the root for an empty path.

    Raises:
        ValueError: Any path component fails exact resolution.
    """

    for token in tokens:
        value = Child(value, token)

    return value


def Replace(value: object, tokens: tuple[str, ...], replacement: object) -> object:
    """Replace one proven existing coordinate in a private tree copy, including its root.

    Args:
        value: Privately copied tree whose selected coordinate was already resolved.
        tokens: Exact validated selected path.
        replacement: Finite profile-generated JSON value or re-encoded JSON string.

    Returns:
        Mutated private tree, or the replacement itself for a root selection.

    Raises:
        ValueError: The existing parent does not resolve to an object or array.
    """

    if not tokens:
        return replacement

    parent = Resolve(value, tokens[:-1])

    if isinstance(parent, dict):
        parent[tokens[-1]] = replacement

    elif isinstance(parent, list):
        parent[int(tokens[-1])] = replacement

    else:
        raise ValueError("JSON mutation parent is not a container")

    return value


def Variants(value: object, profile: JsonMutationProfile) -> list[tuple[str, object]]:
    """Select finite distinct scalar replacements, with no execution or schema assertion.

    Args:
        value: Existing selected JSON scalar, never an automatically decoded string.
        profile: Explicit validated versioned corpus choice.

    Returns:
        Variant names and bounded values, omitting no-op or same-type candidates as configured.

    Raises:
        ValueError: A container or type-preserving null has no supported candidate.
    """

    if isinstance(value, (dict, list)):
        raise ValueError("JSON mutation selection must address a scalar")

    if profile is JsonMutationProfile.TYPE_CHANGE:
        candidates: list[tuple[str, object]] = [
            ("null", None), ("boolean", False), ("integer", 0), ("string", "1337"),
            ("array", []), ("object", {}),
        ]

    elif isinstance(value, str):
        candidates = [("empty", ""), ("marker", "1337"), ("delimiters", "'\"\\"), ("nul", "\x00")]

    elif isinstance(value, bool):
        candidates = [("boolean-inverse", not value)]

    elif isinstance(value, int):
        candidates = [("zero", 0), ("negative", -1), ("int32-max", 2147483647),
                      ("int32-min", -2147483648)]

    elif isinstance(value, float):
        candidates = [("zero", 0.0), ("negative", -1.5), ("fraction", 1.5)]

    else:
        raise ValueError("null has no distinct type-preserving mutation")

    if profile is JsonMutationProfile.TYPE_CHANGE:
        return [(name, item) for name, item in candidates if type(item) is not type(value)
                and not (type(value) is float and type(item) is int)]

    return [(name, item) for name, item in candidates if item != value]


def EncodeBody(value: object, maximum: int) -> bytes:
    """Encode canonical JSON incrementally and stop before collecting an oversized result.

    Args:
        value: Inspected finite tree with only original or bounded synthetic values.
        maximum: Remaining encoded-byte allowance for this output.

    Returns:
        Canonical UTF-8 JSON bytes without a trailing newline.

    Raises:
        ValueError: Incremental encoding exceeds the remaining byte budget.
    """

    chunks: list[bytes] = []
    size = 0
    encoder = json.JSONEncoder(ensure_ascii=False, allow_nan=False, sort_keys=True,
                               separators=(",", ":"))

    for chunk in encoder.iterencode(value):
        encoded = chunk.encode("utf-8")
        size += len(encoded)

        if size > maximum:
            raise ValueError("JSON mutation output exceeds its byte budget")

        chunks.append(encoded)

    return b"".join(chunks)


def GenerateJsonMutations(
    template: RequestTemplate, body: bytes, selections: tuple[JsonMutationSelection, ...], *,
    seed: int, profile: JsonMutationProfile = JsonMutationProfile.SCALAR_BOUNDARIES,
    limits: JsonMutationLimits = JsonMutationLimits(),
) -> tuple[JsonMutation, ...]:
    """Prepare one-coordinate candidates from caller-attributed synthetic bytes, with no I/O.

    Args:
        template: Existing anonymous JSON template; a template never grants permission.
        body: Exact UTF-8 JSON bytes. Association with the template is caller attribution.
        selections: One to 64 distinct explicit pointers beneath declared JSON inputs.
            A decoded_pointer opts into exactly one JSON-string layer at that outer pointer.
        seed: Unsigned 64-bit seed determining each finite corpus's SHA-256 ordering.
        profile: Versioned type-preserving boundaries or deliberate JSON type changes.
        limits: Positive bounded budgets; decoded nodes/bytes aggregate across selected strings.

    Returns:
        Immutable ephemeral candidates, each changing one value in the original body.
        Type preservation does not validate an original schema or establish a vulnerability.

    Raises:
        ValueError: Any input, selector, decoding or budget is invalid. No partial output escapes.
            Diagnostics exclude source values. Inputs and external state remain unchanged.
    """

    try:
        return PrepareMutations(template, body, selections, seed, profile, limits)

    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise ValueError("input is outside the bounded JSON mutation profile") from None


def PrepareMutations(
    template: RequestTemplate, body: bytes, selections: tuple[JsonMutationSelection, ...],
    seed: int, profile: JsonMutationProfile, limits: JsonMutationLimits,
) -> tuple[JsonMutation, ...]:
    """Validate complete input and reserve the finite count before rendering any output.

    Args:
        template: Existing anonymous JSON template, without execution authority.
        body: Exact caller-attributed synthetic JSON bytes.
        selections: Explicit distinct selections with optional one-layer string decoding.
        seed: Unsigned 64-bit corpus ordering seed.
        profile: Versioned finite scalar replacement corpus.
        limits: Positive bounded input, decoding and complete-output budgets.

    Returns:
        Complete immutable candidate corpus, with independent original-tree replacements.

    Raises:
        ValueError: Any input or output falls outside the declared bounded profile.
    """

    if not isinstance(template, RequestTemplate) or template.body_kind is not BodyKind.JSON or (
        template.session_reference is not None
        or any(point.binding.source is not BindingSource.INPUT
               for point in template.injection_points)
    ):
        raise ValueError("JSON mutation requires an anonymous JSON template")

    if type(seed) is not int or not 0 <= seed < 2**64 or (
        not isinstance(profile, JsonMutationProfile) or not isinstance(limits, JsonMutationLimits)
    ):
        raise ValueError("JSON mutation seed, profile or limits are invalid")

    if type(selections) is not tuple or not 1 <= len(selections) <= limits.max_mutations or (
        any(not isinstance(item, JsonMutationSelection) for item in selections)
        or len(set(selections)) != len(selections)
    ):
        raise ValueError("JSON mutation selections must be bounded and unique")

    raw_pointers = {item.pointer for item in selections if item.decoded_pointer is None}
    decoded_pointers = {item.pointer for item in selections if item.decoded_pointer is not None}

    if raw_pointers & decoded_pointers:
        raise ValueError("JSON mutation selections cannot mix raw and decoded input versions")

    if type(body) is not bytes or len(body) > limits.max_decoded_bytes:
        raise ValueError("JSON mutation source exceeds its decoded byte budget")

    tree, nodes = DecodeBody(body, limits)
    decoded_bytes = len(body)
    decoded: dict[str, object] = {}
    decoded_sizes: dict[str, int] = {}
    plans: list[list[tuple[str, object]]] = []
    count = 0
    coordinates = [PointerTokens(point.selector) for point in template.injection_points
                   if point.location is InjectionLocation.JSON]

    for selection in selections:
        tokens = PointerTokens(selection.pointer)

        if not any(tokens[:len(parent)] == parent for parent in coordinates):
            raise ValueError("JSON mutation selector is outside declared inputs")

        selected = Resolve(tree, tokens)

        if selection.decoded_pointer is not None:
            if not isinstance(selected, str):
                raise ValueError("JSON string decoding requires a string")

            if selection.pointer not in decoded:
                inner_bytes = selected.encode("utf-8")
                decoded_bytes += len(inner_bytes)

                if decoded_bytes > limits.max_decoded_bytes:
                    raise ValueError("JSON mutation decoding exceeds its aggregate byte budget")

                inner, inner_nodes = DecodeBody(inner_bytes, limits, depth=len(tokens) + 1)
                decoded[selection.pointer] = inner
                decoded_sizes[selection.pointer] = len(inner_bytes)
                nodes += inner_nodes

                if nodes > limits.max_nodes:
                    raise ValueError("JSON mutation decoding exceeds its aggregate node budget")

            selected = Resolve(decoded[selection.pointer], PointerTokens(selection.decoded_pointer))

        candidates = Variants(selected, profile)
        candidates.sort(key=lambda item: hashlib.sha256(CanonicalModelJson(
            [seed, profile.value, selection.ToDict(), item[0]],
        )).digest())
        count += len(candidates)

        if count > limits.max_mutations:
            raise ValueError("JSON mutation count exceeds its budget")

        plans.append(candidates)

    result: list[JsonMutation] = []
    output_bytes = 0

    for index, candidates in enumerate(plans):
        selection = selections[index]
        tokens = PointerTokens(selection.pointer)

        for variant, replacement in candidates:
            mutated = deepcopy(tree)
            candidate_decoded_bytes = decoded_bytes - len(body)

            if selection.decoded_pointer is not None:
                inner = Replace(deepcopy(decoded[selection.pointer]),
                                PointerTokens(selection.decoded_pointer), replacement)
                InspectTree(inner, limits, depth=len(tokens) + 1)
                encoded_inner = EncodeBody(inner, limits.max_body_bytes)
                candidate_decoded_bytes += len(encoded_inner) - decoded_sizes[selection.pointer]
                replacement = encoded_inner.decode("utf-8")

            mutated = Replace(mutated, tokens, replacement)
            InspectTree(mutated, limits)
            encoded = EncodeBody(mutated, min(limits.max_body_bytes,
                                             limits.max_output_bytes - output_bytes))

            if candidate_decoded_bytes + len(encoded) > limits.max_decoded_bytes:
                raise ValueError("JSON mutation output exceeds its decoded byte budget")

            output_bytes += len(encoded)
            result.append(JsonMutation(template.Reference(), BodyDigest(body), selections, seed,
                                       profile, limits, index, variant, encoded))

    return tuple(result)


def ReplayJsonMutation(
    template: RequestTemplate, body: bytes, mutation: JsonMutation, *, expected_reference: str,
) -> JsonMutation:
    """Recompute a candidate and reject changed input, configuration, attribution or output bytes.

    Args:
        template: Original structural template, including its original workspace ownership.
        body: Exact original source bytes; even whitespace changes invalidate replay.
        mutation: Previously prepared in-memory candidate; it grants no execution permission.
        expected_reference: Independently retained original mutation reference. Recomputing it
            from an altered candidate cannot establish integrity against the original record.

    Returns:
        The independently regenerated candidate with identical metadata and body.

    Raises:
        ValueError: The source, template or candidate differs from the deterministic replay.
    """

    if not isinstance(mutation, JsonMutation) or not isinstance(template, RequestTemplate) or (
        type(body) is not bytes or len(body) > 64 * 1024
        or not isinstance(expected_reference, str)
        or re.fullmatch(r"json-mutation:[0-9a-f]{64}", expected_reference) is None
        or template.Reference() != mutation.template_reference
        or BodyDigest(body) != mutation.source_body_digest
    ):
        raise ValueError("JSON mutation replay source does not match")

    candidates = GenerateJsonMutations(template, body, mutation.selections, seed=mutation.seed,
                                      profile=mutation.profile, limits=mutation.limits)

    try:
        if type(mutation.selection_index) is not int or not (
            0 <= mutation.selection_index < len(mutation.selections)
        ) or type(mutation.body) is not bytes or len(mutation.body) > mutation.limits.max_body_bytes:
            raise ValueError("JSON mutation replay candidate fields are invalid")

        if mutation.Reference() != expected_reference:
            raise ValueError("JSON mutation replay candidate reference does not match")

    except (ValueError, TypeError, IndexError, AttributeError, RecursionError):
        raise ValueError("JSON mutation replay candidate metadata is invalid") from None

    for candidate in candidates:
        if candidate == mutation and candidate.Reference() == expected_reference:
            return candidate

    raise ValueError("JSON mutation replay candidate does not match")
