# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure original-header field absence; source custody and authority stay with the workflow."""

from __future__ import annotations

import re

NATIVE_RESPONSE_PROVIDER_ID = "native.response-passive"
NATIVE_RESPONSE_CAPABILITY = "http.owned-response-header-check"
NATIVE_RESPONSE_CHECK_ID = "native.response-header-xcto-absent"
NATIVE_RESPONSE_PROFILE = "owned-response-header-absence.v1"
NATIVE_RESPONSE_VERSION = "1"
NATIVE_RESPONSE_ASSESSMENT_KIND = "native.response-header-assessment"
NATIVE_RESPONSE_SUMMARY = "Captured response omitted X-Content-Type-Options"
MAX_HEADER_BYTES = 16384
MAX_HEADER_FIELDS = 64
MAX_HEADER_LINE_BYTES = 4096
MAX_ASSESSMENT_BYTES = 16384
_FIELD_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


class NativeResponseHeaderError(ValueError):
    """Original source or interpretation is unadmitted, without raw diagnostic material."""


def HeaderFieldAbsent(raw_headers: bytes) -> bool:
    """Inspect complete original header names without interpreting or searching a body.

    Calling this pure function establishes neither original source custody nor permission.
    The owning workflow must first verify both original receipt replayers and authority.

    Args:
        raw_headers: Complete verified version-one header section including final CRLFCRLF.

    Returns:
        Whether the complete x-content-type-options field name is absent.

    Raises:
        NativeResponseHeaderError: Complete bounded header grammar cannot be established.
    """

    if type(raw_headers) is not bytes or not 1 <= len(raw_headers) <= MAX_HEADER_BYTES or (
        raw_headers.find(b"\r\n\r\n") != len(raw_headers) - 4
    ):
        raise NativeResponseHeaderError("original response header section is unadmitted")

    lines = raw_headers[:-4].split(b"\r\n")

    if not 2 <= len(lines) <= MAX_HEADER_FIELDS + 1 or (
        lines[0] != b"HTTP/1.1 200 OK"
        or any(len(line) + 2 > MAX_HEADER_LINE_BYTES for line in lines)
    ):
        raise NativeResponseHeaderError("original response header section is unadmitted")

    names: set[bytes] = set()

    for line in lines[1:]:
        name, separator, value = line.partition(b":")

        if not separator or _FIELD_NAME.fullmatch(name) is None or name.lower() in names or any(
            byte != 9 and not 32 <= byte <= 126 for byte in value
        ):
            raise NativeResponseHeaderError("original response header section is unadmitted")

        names.add(name.lower())

    return b"x-content-type-options" not in names
