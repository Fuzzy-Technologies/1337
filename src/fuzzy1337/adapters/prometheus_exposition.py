# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Conservative bounded legacy Prometheus exposition detection without retaining values."""

from __future__ import annotations

import re

MAX_PROMETHEUS_BODY_BYTES = 256 * 1024
MAX_PROMETHEUS_LINE_BYTES = 16 * 1024
_NAME = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_:]*")
_LABEL = re.compile(r'[a-zA-Z_][a-zA-Z0-9_]*')
_VALUE = r"(?:[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?|(?i:NaN)|[+-]?Inf)"
_SAMPLE_END = re.compile(r"[ \t]+" + _VALUE + r"(?:[ \t]+[+-]?[0-9]+)?[ \t]*")
_TYPES = frozenset({"counter", "gauge", "histogram", "summary", "untyped"})


def EscapedText(value: str, *, quote: bool = False) -> bool:
    """Validate only the legacy backslash escapes without interpreting label values.

    Args:
        value: Transient HELP or label text from one already bounded line.
        quote: Permit the escaped quote used by label strings in addition to HELP escapes.

    Returns:
        Whether every escape and control character belongs to the supported legacy grammar.
    """

    index = 0

    while index < len(value):
        character = value[index]

        if character in "\r\n" or ord(character) < 32 and character != "\t":
            return False

        if character == "\\":
            index += 1

            if index == len(value) or value[index] not in ("\\\"n" if quote else "\\n"):
                return False

        index += 1

    return True


def Sample(line: str) -> tuple[str, frozenset[str]] | None:
    """Validate a complete sample with unique legacy labels and lexical numeric tokens.

    Args:
        line: One bounded transient sample line with optional surrounding blanks removed.

    Returns:
        Sample name and label-name set, or None for unsupported syntax; values are discarded.
    """

    match = _NAME.match(line)

    if match is None:
        return None

    name = match[0]
    index = match.end()
    label_start = index
    labels: set[str] = set()

    while label_start < len(line) and line[label_start] in " \t":
        label_start += 1

    if label_start < len(line) and line[label_start] == "{":
        index = label_start + 1

        while True:
            while index < len(line) and line[index] in " \t":
                index += 1

            if index < len(line) and line[index] == "}":
                index += 1
                break

            label = _LABEL.match(line, index)

            if label is None or label[0] in labels:
                return None

            labels.add(label[0])
            index = label.end()

            while index < len(line) and line[index] in " \t":
                index += 1

            if not line.startswith("=", index):
                return None

            index += 1

            while index < len(line) and line[index] in " \t":
                index += 1

            if not line.startswith('"', index):
                return None

            index += 1
            start = index

            while index < len(line) and line[index] != '"':
                index += 2 if line[index] == "\\" else 1

            if index >= len(line) or not EscapedText(line[start:index], quote=True):
                return None

            index += 1

            while index < len(line) and line[index] in " \t":
                index += 1

            if index < len(line) and line[index] == ",":
                index += 1
                continue

            if index < len(line) and line[index] == "}":
                index += 1
                break

            return None

    if _SAMPLE_END.fullmatch(line[index:]) is None:
        return None

    return name, frozenset(labels)


def SupportedExposition(body: bytes) -> bool:
    """Require a complete supported document and one associated HELP/TYPE/sample family.

    Args:
        body: Transient complete decoded HTTP body, limited to 256 KiB and strict UTF-8.

    Returns:
        Whether all lines have supported syntax and a declared family establishes the predicate.
    """

    if type(body) is not bytes or not 1 <= len(body) <= MAX_PROMETHEUS_BODY_BYTES or (
        not body.endswith(b"\n")
    ):
        return False

    try:
        text = body.decode("utf-8", errors="strict")

    except UnicodeError:
        return False

    help_names: set[str] = set()
    types: dict[str, str] = {}
    sampled: set[str] = set()
    matched = False

    for raw_line in text.split("\n")[:-1]:
        if len(raw_line.encode("utf-8")) > MAX_PROMETHEUS_LINE_BYTES:
            return False

        if any(ord(character) < 32 and character != "\t" for character in raw_line):
            return False

        line = raw_line.strip(" \t")

        if not line:
            continue

        if line.startswith("#"):
            parts = re.split(r"[ \t]+", line[1:].lstrip(" \t"), maxsplit=2)

            if not parts:
                continue

            if parts[0] in {"EOF", "UNIT"}:
                return False

            if parts[0] not in {"HELP", "TYPE"}:
                continue

            if len(parts) != 3 or _NAME.fullmatch(parts[1]) is None:
                return False

            directive, name, value = parts

            if name in sampled:
                return False

            if directive == "HELP":
                if name in help_names or not EscapedText(value):
                    return False

                help_names.add(name)

            else:
                if name in types or value not in _TYPES:
                    return False

                suffixes = ("_bucket", "_sum", "_count") if value == "histogram" else (
                    ("_sum", "_count") if value == "summary" else ()
                )

                if any(name + suffix in sampled for suffix in suffixes):
                    return False

                types[name] = value

            continue

        sample = Sample(line)

        if sample is None:
            return False

        name, labels = sample
        family = name

        if name not in types:
            for suffix in ("_bucket", "_sum", "_count"):
                if name.endswith(suffix) and name[:-len(suffix)] in types:
                    candidate = name[:-len(suffix)]
                    kind = types[candidate]

                    if kind == "histogram" or kind == "summary" and suffix != "_bucket":
                        family = candidate
                        break

        sample_type = types.get(family)

        if sample_type == "histogram" and (name == family or (
            name.endswith("_bucket") and "le" not in labels
        )) or sample_type == "summary" and name == family and "quantile" not in labels:
            return False

        sampled.update((name, family))

        if family in help_names and sample_type is not None:
            matched = True

    return matched
