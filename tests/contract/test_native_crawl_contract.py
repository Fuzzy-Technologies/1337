# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Validate proposed crawl schema examples without implementing or launching a provider."""

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlsplit

import jsonschema
import pytest

from fuzzy1337.adapters import AdapterInvocation, AdapterRequest, ImpactLevel, SerializeContract
from fuzzy1337.requests import Endpoint, RequestTemplate
from fuzzy1337.scope import Target, TargetKind

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "contracts/native-crawl-record.schema.json").read_text())
EXAMPLES = json.loads((
    ROOT / "tests/contract/fixtures/native-crawl.records.v1.json"
).read_text())


def InputSchema():
    """Select the documented private input definition without a second schema authority."""

    return {"$schema": SCHEMA["$schema"], "$defs": SCHEMA["$defs"], "$ref": "#/$defs/input"}


@pytest.mark.parametrize("name", ("html", "non-html", "client-error", "refused"))
def test_DescriptiveRecordBranchesValidateAgainstTheProposedClosedSchema(name):
    """Schema examples describe shapes only and cannot stand in for actual scanner evidence."""

    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    jsonschema.Draft202012Validator(SCHEMA).validate(EXAMPLES["records"][name])
    jsonschema.Draft202012Validator(InputSchema()).validate(EXAMPLES["input"])


@pytest.mark.parametrize("case", (
    "new-version", "extra-root", "body", "header-values", "untyped-counter",
    "extra-counter", "unknown-outcome", "redirect-success", "html-as-non-html",
    "terminal-frontier", "too-many-entries", "duplicate-ordinal", "foreign-host",
    "refusal-body-digest", "empty-body-digest", "unknown-refusal",
))
def test_ClosedSchemaRejectsUnadmittedRecordShapes(case):
    """Unsafe fields, unsupported branch combinations and finite-bound overflow refuse."""

    record = deepcopy(EXAMPLES["records"]["html"])

    if case == "new-version":
        record["schema_version"] = 2

    elif case == "extra-root":
        record["diagnostic"] = "not permitted"

    elif case == "body":
        record["response"]["body"] = "not retained"

    elif case == "header-values":
        record["response"]["headers"] = {}

    elif case == "untyped-counter":
        record["frontier"]["exclusion_counts"]["query"] = True

    elif case == "extra-counter":
        record["frontier"]["exclusion_counts"]["raw-href"] = 0

    elif case == "unknown-outcome":
        record["outcome"] = "clean"

    elif case == "redirect-success":
        record["response"]["status"] = 302

    elif case == "html-as-non-html":
        record["outcome"] = "non-html"

    elif case == "terminal-frontier":
        record = deepcopy(EXAMPLES["records"]["client-error"])
        record["frontier"]["anchor_count"] = 1

    elif case == "too-many-entries":
        record["frontier"]["entries"] *= 16

    elif case == "duplicate-ordinal":
        record["frontier"]["entries"][0]["ordinals"] = [1, 1]

    elif case == "foreign-host":
        record["frontier"]["entries"][0]["url"] = "http://example.test/leaf"

    elif case == "refusal-body-digest":
        record = deepcopy(EXAMPLES["records"]["refused"])
        record["body_sha256"] = "0" * 64

    elif case == "empty-body-digest":
        record = deepcopy(EXAMPLES["records"]["non-html"])
        record["response"]["body_sha256"] = "0" * 64

    else:
        record = deepcopy(EXAMPLES["records"]["refused"])
        record["error"] = "echo-peer-response"

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(SCHEMA).validate(record)


@pytest.mark.parametrize("field,value", (
    ("selected_urls", []),
    ("selected_urls", ["http://127.0.0.1/index"] * 2),
    ("source_url", "http://127.0.0.1/index?token=private"),
    ("source_url", "http://localhost/index"),
    ("source_url", "http://127.0.0.1:80/index"),
    ("max_body_bytes", 65537),
    ("request_timeout_ms", 5001),
    ("caller_file", "request.json"),
))
def test_PrivateInputSchemaRejectsUnsafeOrUnboundedShapes(field, value):
    """A schema input cannot introduce caller files, DNS, query data or widened ceilings."""

    document = deepcopy(EXAMPLES["input"])
    document[field] = value

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(InputSchema()).validate(document)


def test_ExampleInputAndOutputBindExistingImmutableInvocationAndRequestOwners():
    """Existing contracts can represent the fixed argument without any worker or target access."""

    document = EXAMPLES["input"]
    raw = SerializeContract(document).encode("ascii")
    source = urlsplit(document["source_url"])
    request = RequestTemplate(Endpoint(document["workspace_id"],
        source.scheme + "://" + source.netloc, source.path))
    selected = tuple(document["selected_urls"])
    target = Target(TargetKind.URL, document["source_url"])
    invocation = AdapterInvocation("native.crawl", AdapterRequest(
        "http.owned-loopback-crawl", target.Reference(), ImpactLevel.SAFE, document),
        ("python", "-I", "-m", "fuzzy1337.native_crawl_worker", raw.decode("ascii")), 4, "1")
    record = EXAMPLES["records"]["html"]
    assert len(raw) <= 24576 and selected == tuple(sorted(set(selected))), (
        "The example must fit one bounded immutable argument with an exact sorted selection."
    )
    assert record["input_sha256"] == hashlib.sha256(raw).hexdigest(), (
        "The example output must bind the exact complete immutable input."
    )
    assert record["selected_urls_sha256"] == hashlib.sha256(
        SerializeContract(selected).encode("ascii")).hexdigest(), (
        "The admitted-set digest must use the canonical complete selection."
    )
    assert record["source"]["request_reference"] == request.Reference(), (
        "The worker cannot invent a source request identity."
    )
    assert record["source"]["endpoint_reference"] == request.endpoint.Identity().Reference(), (
        "The proposed source uses existing structural Endpoint identity."
    )
    assert invocation.request.parameters["selected_urls"] == selected, (
        "Existing AdapterRequest must recursively freeze the input set."
    )
    assert invocation.argv[-1].encode("ascii") == raw, (
        "The fixed worker argument must match the exact frozen invocation metadata."
    )
