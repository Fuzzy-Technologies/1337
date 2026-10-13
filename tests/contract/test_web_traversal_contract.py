# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Closed paired traversal catalog record grammar across owning parser and JSON Schema."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

from fuzzy1337.adapters.page_capture import (
    CanonicalRecord,
    KnownSyntheticHtmlBody,
    PageCaptureRecordError,
    ParseRecord,
)
from fuzzy1337.page_capture_worker import ParseHeaders
from tests.contract.page_capture_fixture import Body as OriginalBody
from tests.contract.web_traversal_fixture import PATHS, Body

SCHEMA = json.loads((Path(__file__).parents[2] / "contracts" /
                     "page-capture-record.schema.json").read_bytes())


def Record(path):
    """Build an independent actual-body record with handwritten concrete URL/header metadata."""

    body = Body(path)

    return {"schema_version": 1, "fixture_id": "owned-traversal-" + path[1:] + ".v1",
        "url": "http://127.0.0.1:32123" + path, "address": "127.0.0.1", "port": 32123,
        "scheme": "http", "status": 200, "http_version": "HTTP/1.1",
        "content_type": "text/html", "declared_charset": "utf-8", "content_length": len(body),
        "header_size_bytes": 77, "header_count": 2,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_base64": base64.b64encode(body).decode("ascii")}


@pytest.mark.parametrize("path", PATHS)
def test_ClosedPairedCatalogRecordsPassParserAndSchema(path):
    """New exact reviewed records retain the unchanged flat field/version grammar."""

    record = Record(path)
    jsonschema.validate(record, SCHEMA)
    selected = KnownSyntheticHtmlBody(record["fixture_id"])
    assert ParseRecord(CanonicalRecord(record), record["url"], selected, 16384) == record, (
        "Owning parser and additive record schema disagree on exact reviewed body"
    )


@pytest.mark.parametrize("field,value", [
    ("fixture_id", "arbitrary.v1"), ("fixture_id", "owned-traversal-alpha.v1"),
    ("content_length", 221), ("content_length", True),
    ("body_sha256", "0" * 64), ("body_base64", "YQ=="), ("schema_version", True),
])
def test_UnknownOrMixedCatalogFieldsNeverBecomeApprovedRecords(field, value):
    """Body ID, hash, size and canonical base64 shape must remain one exact selected tuple."""

    record = copy.deepcopy(Record("/index"))
    record[field] = value

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(record, SCHEMA)

    with pytest.raises(PageCaptureRecordError):
        ParseRecord(CanonicalRecord(record), record["url"],
                    KnownSyntheticHtmlBody("owned-traversal-index.v1"), 16384)


@pytest.mark.parametrize("path", ("/original", *PATHS))
@pytest.mark.parametrize("charset", (False, True))
def test_MinimalWireHeaderAdmissionFollowsExactCatalogBodySize(path, charset):
    """The real worker, parser and schema agree at exact two/three-digit body header floors."""

    body = OriginalBody() if path == "/original" else Body(path)
    record = Record("/index" if path == "/original" else path)
    record.update({"fixture_id": "owned-loopback-html.v1" if path == "/original"
        else record["fixture_id"], "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_base64": base64.b64encode(body).decode("ascii")})
    media = "text/html;charset=utf-8" if charset else "text/html"
    header = ("HTTP/1.0 200 \r\ncontent-length:" + str(len(body)) + "\r\ncontent-type:" + media +
              "\r\n\r\n").encode("ascii")
    record.update(ParseHeaders(header, len(body), 16384))
    selected = KnownSyntheticHtmlBody(record["fixture_id"])
    jsonschema.validate(record, SCHEMA)
    assert ParseRecord(CanonicalRecord(record), record["url"], selected, 16384) == record, (
        "Worker-admitted minimal header was refused by the owning record consumer"
    )
    record["header_size_bytes"] -= 1

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(record, SCHEMA)

    with pytest.raises(PageCaptureRecordError):
        ParseRecord(CanonicalRecord(record), record["url"], selected, 16384)
