# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Decode bounded saved RFC 5424 version-one originals into source-only canonical records."""

from __future__ import annotations

import calendar
import hashlib
import json
import re
from datetime import UTC, datetime

__all__ = ["ParseSavedSyslog"]

SYSLOG_PROFILE = "saved-rfc5424-v1"
SYSLOG_PARSER = "syslog-rfc5424"
SYSLOG_PARSER_VERSION = "1"
MAX_SYSLOG_SOURCE_BYTES = 1024 * 1024
MAX_SYSLOG_RECORDS = 256
MAX_SYSLOG_RECORD_BYTES = 16 * 1024
MAX_SYSLOG_ELEMENTS = 32
MAX_SYSLOG_PARAMETERS = 64
MAX_SYSLOG_VALUE_BYTES = 4096
MAX_SYSLOG_DOCUMENT_BYTES = 4 * 1024 * 1024
_TIMESTAMP = re.compile(
    rb"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
    rb"(\.[0-9]{1,6})?(Z|[+-][0-9]{2}:[0-9]{2})"
)


class SyslogDecodeError(ValueError):
    """Retain only a fixed parser category and original numeric record coordinates."""

    def __init__(self, code: str, recordIndex: int = 0, byteOffset: int = 0) -> None:
        """Preserve bounded diagnostic facts without source values or message text.

        Args:
            code: Implementation-owned profile refusal category.
            recordIndex: One-based record ordinal, or zero before framing.
            byteOffset: Zero-based frame start in the complete original.
        """

        super().__init__(code)
        self.code = code
        self.recordIndex = recordIndex
        self.byteOffset = byteOffset


def SyslogLimits() -> dict[str, int]:
    """Return the independent fixed limits of this saved-source profile.

    Returns:
        Detached ceilings, never transport limits or modifications of another parser.
    """

    return {"source_bytes": MAX_SYSLOG_SOURCE_BYTES, "records": MAX_SYSLOG_RECORDS,
        "record_bytes": MAX_SYSLOG_RECORD_BYTES, "sd_elements": MAX_SYSLOG_ELEMENTS,
        "sd_parameters_per_record": MAX_SYSLOG_PARAMETERS,
        "parameter_bytes": MAX_SYSLOG_VALUE_BYTES,
        "document_bytes": MAX_SYSLOG_DOCUMENT_BYTES}


def SyslogJson(value: object) -> bytes:
    """Render profile-controlled JSON without retaining arbitrary message bytes.

    Args:
        value: Bounded JSON-compatible parser or receipt metadata.

    Returns:
        Canonical UTF-8 JSON, including exact source strings without normalization.
    """

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def RequireSyslogDigest(value: object) -> str:
    """Require an independent exact lowercase SHA-256 byte pin.

    Args:
        value: Caller-retained source checksum, not a manifest identity.

    Returns:
        Unchanged admitted digest.
    """

    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("Syslog source requires a lowercase SHA-256 pin")

    return value


def RequireSyslogFraming(value: object) -> str:
    """Keep single-message bytes distinct from an explicitly selected line export.

    Args:
        value: Exactly single or lines; there is no auto-detection.

    Returns:
        Unchanged selected saved-file framing.
    """

    if type(value) is not str or value not in {"single", "lines"}:
        raise ValueError("Syslog framing must be explicitly single or lines")

    return value


def HeaderValue(value: bytes, maximum: int) -> str | None:
    """Decode one bounded printable ASCII header field while preserving NIL as unknown.

    Args:
        value: Complete original field token.
        maximum: RFC field-specific maximum byte length.

    Returns:
        Exact case-sensitive source string, or None for the original NIL token.
    """

    if not 1 <= len(value) <= maximum or any(item < 33 or item > 126 for item in value):
        raise SyslogDecodeError("header")

    return None if value == b"-" else value.decode("ascii")


def TimestampValue(value: bytes) -> dict[str, object]:
    """Keep known source UTC separate from local-offset knowledge and clock accuracy.

    Args:
        value: Original timestamp token, including a possible NIL marker.

    Returns:
        Original spelling, declared local-offset knowledge and precision-preserving source UTC.
        Z and negative zero keep UTC known without declaring a local numeric offset.
    """

    if value == b"-":
        return {"timestamp": None, "timestamp_offset": None, "offset_known": None,
                "timestamp_utc": None, "utc_status": "unknown"}

    match = _TIMESTAMP.fullmatch(value)

    if match is None:
        raise SyslogDecodeError("timestamp")

    year, month, day, hour, minute, second = (int(match[index]) for index in range(1, 7))

    if not 1 <= month <= 12 or not 1 <= day <= calendar.monthrange(year, month)[1] or (
        hour > 23 or minute > 59 or second > 59
    ):
        raise SyslogDecodeError("timestamp")

    offset = match[8].decode("ascii")

    if offset != "Z" and (int(offset[1:3]) > 23 or int(offset[4:6]) > 59):
        raise SyslogDecodeError("timestamp")

    original = value.decode("ascii")
    result: dict[str, object] = {"timestamp": original, "timestamp_offset": offset,
        "offset_known": offset not in {"Z", "-00:00"}, "timestamp_utc": None,
        "utc_status": "unrepresentable"}

    if offset in {"Z", "-00:00", "+00:00"}:
        result["timestamp_utc"] = original[:-len(offset)] + "Z"
        result["utc_status"] = "available"

        return result

    try:
        instant = datetime.fromisoformat(original.replace("Z", "+00:00")).astimezone(UTC)

    except (ValueError, OverflowError):
        return result

    fraction = match[7].decode("ascii") if match[7] else ""
    result["timestamp_utc"] = (
        f"{instant.year:04d}-{instant.month:02d}-{instant.day:02d}T"
        f"{instant.hour:02d}:{instant.minute:02d}:{instant.second:02d}{fraction}Z"
    )
    result["utc_status"] = "available"

    return result


def ReadSdName(frame: bytes, position: int, terminators: bytes) -> tuple[str, int]:
    """Read the RFC SD-NAME grammar, including a permitted opening bracket.

    Args:
        frame: One complete bounded record.
        position: First name byte within that record.
        terminators: Grammar-specific end markers for this name coordinate.

    Returns:
        Exact ASCII name and first unconsumed delimiter index.
    """

    start = position

    while position < len(frame) and frame[position] not in terminators:
        token = frame[position]

        if token < 33 or token > 126 or token in (34, 61, 93):
            raise SyslogDecodeError("structured-data")

        position += 1

        if position - start > 32:
            raise SyslogDecodeError("structured-data")

    if position == start:
        raise SyslogDecodeError("structured-data")

    return frame[start:position].decode("ascii"), position


def ReadSdValue(frame: bytes, position: int) -> tuple[str, int, int, int]:
    """Decode exact RFC escapes and preserve an unknown backslash sequence unchanged.

    Args:
        frame: Complete bounded record with an opening parameter quote at position.
        position: Original opening quote coordinate.

    Returns:
        Valid UTF-8 value, next cursor, raw value offset and raw escaped byte length.
    """

    if position >= len(frame) or frame[position] != 34:
        raise SyslogDecodeError("structured-data")

    start = position + 1
    position = start
    decoded = bytearray()

    while position < len(frame):
        token = frame[position]

        if position - start > MAX_SYSLOG_VALUE_BYTES:
            raise SyslogDecodeError("parameter-limit")

        if token == 34:
            if position - start > MAX_SYSLOG_VALUE_BYTES:
                raise SyslogDecodeError("parameter-limit")

            try:
                return decoded.decode("utf-8"), position + 1, start, position - start

            except UnicodeError as error:
                raise SyslogDecodeError("parameter-utf8") from error

        if token == 93:
            raise SyslogDecodeError("structured-data")

        if token == 92 and position + 1 < len(frame) and frame[position + 1] in (34, 92, 93):
            decoded.append(frame[position + 1])
            position += 2

        else:
            decoded.append(token)
            position += 1

    raise SyslogDecodeError("structured-data")


def ReadStructuredData(frame: bytes, position: int, base: int
                       ) -> tuple[list[dict[str, object]] | None, int]:
    """Preserve SD order and repeated parameters while refusing duplicate SD identifiers.

    Args:
        frame: Complete bounded RFC record.
        position: First structured-data byte.
        base: Frame start in the complete original for global byte coordinates.

    Returns:
        Ordered elements or NIL, plus the first byte after structured data.
    """

    if frame[position:position + 1] == b"-":
        return None, position + 1

    elements: list[dict[str, object]] = []
    identifiers: set[str] = set()
    parameterCount = 0

    while position < len(frame) and frame[position] == 91:
        start = position
        identifier, position = ReadSdName(frame, position + 1, b" ]")

        if identifier in identifiers or len(elements) >= MAX_SYSLOG_ELEMENTS:
            raise SyslogDecodeError("structured-data")

        if "@" in identifier and re.fullmatch(r"[^@]+@[0-9]+(?:\.[0-9]+)*", identifier) is None:
            raise SyslogDecodeError("structured-data")

        identifiers.add(identifier)
        parameters: list[dict[str, object]] = []

        while position < len(frame) and frame[position] == 32:
            nameStart = position + 1
            name, position = ReadSdName(frame, nameStart, b"=")

            if position >= len(frame) or frame[position] != 61:
                raise SyslogDecodeError("structured-data")

            value, position, valueStart, valueLength = ReadSdValue(frame, position + 1)
            parameterCount += 1

            if parameterCount > MAX_SYSLOG_PARAMETERS:
                raise SyslogDecodeError("parameter-limit")

            parameters.append({"name": name, "value": value,
                "byte_offset": base + nameStart, "byte_length": position - nameStart,
                "value_byte_offset": base + valueStart, "value_byte_length": valueLength})

        if position >= len(frame) or frame[position] != 93:
            raise SyslogDecodeError("structured-data")

        position += 1
        elements.append({"sd_id": identifier, "parameters": parameters,
                         "byte_offset": base + start, "byte_length": position - start})

    if not elements:
        raise SyslogDecodeError("structured-data")

    return elements, position


def ParseSyslogRecord(frame: bytes, base: int, ordinal: int, lineNumber: int,
                      terminator: str | None) -> dict[str, object]:
    """Decode one complete record without message interpretation or entity inference.

    Args:
        frame: Exact message bytes excluding only explicitly selected line framing.
        base: Original zero-based record offset.
        ordinal: One-based source-order record index.
        lineNumber: One-based physical header line.
        terminator: Explicit LF/CRLF delimiter, or None.

    Returns:
        Source fields, structured data and original byte coordinates; message bytes stay raw.
    """

    if not frame or len(frame) > MAX_SYSLOG_RECORD_BYTES:
        raise SyslogDecodeError("record-limit")

    fields = frame.split(b" ", 6)

    if len(fields) != 7:
        raise SyslogDecodeError("header")

    priorityMatch = re.fullmatch(rb"<(0|[1-9][0-9]{0,2})>1", fields[0])

    if priorityMatch is None or int(priorityMatch[1]) > 191:
        raise SyslogDecodeError("priority-version")

    priority = int(priorityMatch[1])
    result: dict[str, object] = {"record_index": ordinal, "line_number": lineNumber,
        "byte_offset": base, "byte_length": len(frame), "terminator": terminator,
        "priority": priority, "facility_code": priority // 8, "severity_code": priority % 8,
        "version": 1}
    result.update(TimestampValue(fields[1]))
    coordinates: dict[str, object] = {
        "priority": {"byte_offset": base + 1, "byte_length": len(priorityMatch[1])},
        "version": {"byte_offset": base + len(fields[0]) - 1, "byte_length": 1},
    }
    cursor = len(fields[0]) + 1

    for name, token, maximum in zip(
        ("timestamp", "hostname", "app_name", "procid", "msgid"), fields[1:6],
        (32, 255, 48, 128, 32), strict=True,
    ):
        decoded = HeaderValue(token, maximum)
        coordinates[name] = {"byte_offset": base + cursor, "byte_length": len(token)}

        if name != "timestamp":
            result[name] = decoded

        cursor += len(token) + 1

    result["header_coordinates"] = coordinates
    elements, position = ReadStructuredData(frame, cursor, base)
    result["structured_data"] = elements
    result["structured_data_coordinates"] = {
        "byte_offset": base + cursor, "byte_length": position - cursor,
    }
    message: dict[str, object] | None = None

    if position < len(frame):
        if frame[position] != 32:
            raise SyslogDecodeError("structured-data")

        messageOffset = position + 1
        payload = frame[messageOffset:]
        marked = payload.startswith(b"\xef\xbb\xbf")

        if marked:
            try:
                payload[3:].decode("utf-8")

            except UnicodeError as error:
                raise SyslogDecodeError("message-utf8") from error

        message = {"byte_offset": base + messageOffset, "byte_length": len(payload),
            "content_byte_offset": base + messageOffset + (3 if marked else 0),
            "content_byte_length": len(payload) - (3 if marked else 0),
            "encoding": "utf-8-bom" if marked else "unmarked-octets",
            "sha256": hashlib.sha256(payload).hexdigest()}

    result["message"] = message

    return result


def ParseSavedSyslog(payload: bytes, *, expectedSha256: str, framing: str = "single") -> bytes:
    """Parse an explicit saved original into canonical source-only JSON without custody or I/O.

    Args:
        payload: Complete caller-supplied original bytes, never a path or network source.
        expectedSha256: Independent exact original byte checksum.
        framing: Single message bytes or explicit LF/CRLF one-message-per-line saved export.

    Returns:
        Immutable canonical JSON containing source fields, NILs and original byte coordinates.
        Message content is never included; SD values remain exact source declarations.

    Raises:
        ValueError: Original pin, framing, RFC consumed grammar or finite profile is refused.
    """

    RequireSyslogDigest(expectedSha256)
    RequireSyslogFraming(framing)

    if type(payload) is not bytes or not 1 <= len(payload) <= MAX_SYSLOG_SOURCE_BYTES:
        raise SyslogDecodeError("source-limit")

    if hashlib.sha256(payload).hexdigest() != expectedSha256:
        raise SyslogDecodeError("source-digest")

    records: list[dict[str, object]] = []
    position = 0
    lineNumber = 1

    while position < len(payload):
        if len(records) >= MAX_SYSLOG_RECORDS:
            raise SyslogDecodeError("record-limit", len(records) + 1, position)

        terminator = None
        end = len(payload)
        following = end

        if framing == "lines":
            newline = payload.find(b"\n", position)

            if newline >= 0:
                end = newline
                following = newline + 1
                terminator = "LF"

                if end > position and payload[end - 1] == 13:
                    end -= 1
                    terminator = "CRLF"

        try:
            record = ParseSyslogRecord(payload[position:end], position,
                                       len(records) + 1, lineNumber, terminator)

        except SyslogDecodeError as error:
            raise SyslogDecodeError(error.code, len(records) + 1, position) from error

        records.append(record)
        position = following
        lineNumber += 1

    document = SyslogJson({"schema_version": 1, "profile": SYSLOG_PROFILE,
        "parser_id": SYSLOG_PARSER, "parser_version": SYSLOG_PARSER_VERSION,
        "source_sha256": expectedSha256, "source_bytes": len(payload), "framing": framing,
        "limits": SyslogLimits(), "records": records})

    if len(document) > MAX_SYSLOG_DOCUMENT_BYTES:
        raise SyslogDecodeError("document-limit")

    return document
