# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal bounded YAML event decoding without constructors, aliases or implicit resolvers."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass

_TAG_PREFIX = "tag:yaml.org,2002:"
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z")
_AMBIGUOUS_NUMBER = re.compile(
    r"[+-]?(?:\.(?:inf|nan)|[0-9]+(?:_[0-9]+)+|[0-9]+(?::[0-9]+)+"
    r"|0[xob][0-9a-f_]+|(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)\Z",
    re.IGNORECASE,
)


def YamlScalar(value: str, tag: str | None, style: str | None) -> object:
    """Convert the declared JSON-compatible scalar profile, never PyYAML implicit types.

    Args:
        value: Decoded scalar text from a bounded parser event.
        tag: Explicit tag URI, or None for an untagged scalar.
        style: Quote/block style, or None for a plain scalar.

    Returns:
        A string, null, boolean or finite JSON number.

    Raises:
        ValueError: A tag or numeric spelling cannot be represented by this profile.
    """

    if tag == _TAG_PREFIX + "str" or (tag is None and style is not None):
        value.encode("utf-8")

        return value

    if tag not in {None, *(_TAG_PREFIX + kind for kind in ("null", "bool", "int", "float"))}:
        raise ValueError("API YAML scalar tag is outside the JSON-compatible profile")

    if value in {"null", ""} and tag in {None, _TAG_PREFIX + "null"}:
        return None

    if value in {"true", "false"} and tag in {None, _TAG_PREFIX + "bool"}:
        return value == "true"

    if _NUMBER.fullmatch(value) and tag in {None, _TAG_PREFIX + "int", _TAG_PREFIX + "float"}:
        number = json.loads(value)

        if (isinstance(number, float) and not math.isfinite(number)) or (
            tag == _TAG_PREFIX + "int" and not isinstance(number, int)
        ):
            raise ValueError("API YAML numeric type or finite value is invalid")

        return float(number) if tag == _TAG_PREFIX + "float" else number

    if tag is not None or _AMBIGUOUS_NUMBER.fullmatch(value):
        raise ValueError("API YAML scalar spelling is outside the JSON-compatible profile")

    value.encode("utf-8")

    return value


@dataclass(slots=True)
class YamlCollection:
    """Own one bounded collection and the next exact string key while consuming events."""

    value: dict[str, object] | list[object]
    key: str | None = None

    def Add(self, value: object) -> None:
        """Append one already validated child, rejecting duplicate and non-JSON mapping keys.

        Args:
            value: A scalar or a bounded child collection, without an alias or constructor.
        """

        if isinstance(self.value, list):
            self.value.append(value)

        elif self.key is None:
            if not isinstance(value, str) or value == "<<" or value in self.value:
                raise ValueError("API YAML keys must be unique strings without merge semantics")

            self.key = value

        else:
            self.value[self.key] = value
            self.key = None


def DecodeOpenApiYaml(value: str, *, maximum_nodes: int, maximum_depth: int) -> object:
    """Decode one pre-byte-bounded document using the optional event parser only.

    Args:
        value: Supplied UTF-8-compatible text, never a path, stream or URL.
        maximum_nodes: Inclusive count of scalar and collection nodes, including keys.
        maximum_depth: Inclusive child nesting, with the root collection at depth zero.

    Returns:
        The JSON-compatible tree for the existing API validator.

    Raises:
        ValueError: The optional dependency, syntax, representation or resource bounds fail.
    """

    try:
        import yaml  # type: ignore[import-untyped]

    except ImportError:
        raise ValueError("API YAML input requires the 1337[openapi-yaml] extra") from None

    pending: list[YamlCollection] = []
    root: object = None
    count = 0
    documents = 0

    try:
        for event in yaml.parse(value, Loader=yaml.BaseLoader):
            if isinstance(event, yaml.events.DocumentStartEvent):
                documents += 1

                if documents != 1 or event.version not in {None, (1, 2)} or event.tags:
                    raise ValueError("API YAML requires one document without custom directives")

            elif isinstance(event, yaml.events.AliasEvent):
                raise ValueError("API YAML aliases and anchors are unsupported")

            elif isinstance(event, (yaml.events.ScalarEvent, yaml.events.CollectionStartEvent)):
                count += 1

                if count > maximum_nodes or len(pending) > maximum_depth:
                    raise ValueError("API YAML nodes/nesting exceeds its bound")

                if event.anchor is not None:
                    raise ValueError("API YAML aliases and anchors are unsupported")

                child: object

                if isinstance(event, yaml.events.ScalarEvent):
                    child = YamlScalar(event.value, event.tag, event.style)

                else:
                    mapping = isinstance(event, yaml.events.MappingStartEvent)
                    expected_tag = _TAG_PREFIX + ("map" if mapping else "seq")

                    if event.tag not in {None, expected_tag}:
                        raise ValueError("API YAML collection tag is outside the JSON profile")

                    child = {} if mapping else []

                if pending:
                    pending[-1].Add(child)

                else:
                    root = child

                if isinstance(child, (dict, list)):
                    pending.append(YamlCollection(child))

            elif isinstance(event, yaml.events.CollectionEndEvent):
                pending.pop()

        if documents != 1:
            raise ValueError("API YAML requires exactly one document")

        return root

    except (yaml.YAMLError, ValueError, UnicodeError, RecursionError, OverflowError):
        raise ValueError("API YAML syntax, representation or resource bound is invalid") from None
