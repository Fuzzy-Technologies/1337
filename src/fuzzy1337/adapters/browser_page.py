# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Separate closed offline-browser record grammar over an independently verified native body."""

from __future__ import annotations

import re

from fuzzy1337.adapters.page_capture import (
    CHROMIUM_VERSION,
    ERROR_EXITS,
    PAGE_BROWSER_PROFILE,
    PLAYWRIGHT_VERSION,
    CanonicalRecord,
    FlatJson,
    Integer,
    KnownBody,
    KnownSyntheticHtmlBody,
    PageCaptureRecordError,
    ParseRecord,
)

MAX_DOM_BYTES = 262144
MAX_DOM_ELEMENTS = 8192
MAX_BLOCKED_REQUESTS = 64
RENDER_SECONDS = 6.0
BROWSER_ERROR_EXITS = {"renderer-unavailable": 78, "renderer-version": 78,
    "renderer-policy": 1, "renderer-timeout": 124, "renderer": 1}
_RENDER_FIELDS = frozenset({"renderer_profile", "playwright_version", "chromium_version",
    "input_body_sha256", "dom_sha256", "dom_size_bytes", "element_count", "anchor_count",
    "form_count", "input_count", "blocked_request_count"})
_FAILURE_FIELDS = frozenset({"schema_version", "renderer_profile", "error"})


def ParseBrowserRecord(raw: bytes, url: str, expected_body: KnownSyntheticHtmlBody,
                       max_body_bytes: int) -> dict[str, object]:
    """Validate original canonical browser bytes before separating complete native custody.

    Args:
        raw: Exact bounded canonical browser-worker stdout, with no stderr interpretation.
        url: Exact approved native acquisition destination; the browser never navigates it.
        expected_body: Explicit unchanged closed catalog body selection.
        max_body_bytes: Exact selected native acquisition body quota.

    Returns:
        Complete original flat success or fixed failure record. A renderer failure carries
        either no source body or the entire independently validated native success group.

    Raises:
        PageCaptureRecordError: Original encoding, fields, source, metrics or pins differ.
    """

    try:
        expected = KnownBody(expected_body)
        record = FlatJson(raw)
        Integer(record.get("schema_version"), 1, 1)

        if record.get("renderer_profile") != PAGE_BROWSER_PROFILE:
            raise ValueError("browser profile differs")

        error = record.get("error")

        if "error" in record:
            if type(error) is not str or error not in {**ERROR_EXITS, **BROWSER_ERROR_EXITS}:
                raise ValueError("unknown browser failure")

            if set(record) == _FAILURE_FIELDS:
                return record

            if error not in BROWSER_ERROR_EXITS or record.get("input_body_sha256") != (
                expected.sha256
            ):
                raise ValueError("browser failure has no complete verified source binding")

            native = {key: value for key, value in record.items()
                      if key not in {"renderer_profile", "error", "input_body_sha256"}}
            admitted = ParseRecord(CanonicalRecord(native), url, expected, max_body_bytes)

            if "error" in admitted:
                raise ValueError("browser failure source group is not a verified body")

            return record

        if not _RENDER_FIELDS.issubset(record):
            raise ValueError("incomplete browser metrics")

        native = {key: value for key, value in record.items() if key not in _RENDER_FIELDS}
        admitted = ParseRecord(CanonicalRecord(native), url, expected, max_body_bytes)

        if "error" in admitted or record["input_body_sha256"] != expected.sha256 or (
            record["playwright_version"] != PLAYWRIGHT_VERSION
            or record["chromium_version"] != CHROMIUM_VERSION
            or type(record["dom_sha256"]) is not str
            or re.fullmatch(r"[a-f0-9]{64}", record["dom_sha256"]) is None
        ):
            raise ValueError("browser engine or original input binding differs")

        Integer(record["dom_size_bytes"], 1, MAX_DOM_BYTES)
        elements = Integer(record["element_count"], 1, MAX_DOM_ELEMENTS)

        for name in ("anchor_count", "form_count", "input_count"):
            Integer(record[name], 0, elements)

        Integer(record["blocked_request_count"], 0, MAX_BLOCKED_REQUESTS)

        return record

    except (ValueError, TypeError, AttributeError, OverflowError, KeyError, RecursionError):
        raise PageCaptureRecordError("browser page record violated its closed offline grammar") \
            from None
