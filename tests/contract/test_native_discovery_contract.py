# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Versioned native discovery descriptor, safe record and producer-consumer contracts."""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from fuzzy1337.adapters import ImpactLevel
from fuzzy1337.adapters.native_http import NativeHttpAdapter, ParseRecord
from fuzzy1337.discovery import (
    DISCOVERY_VERSION,
    NATIVE_HTTP_CAPABILITY,
    NATIVE_HTTP_PROVIDER_ID,
    DiscoveryLimits,
    NativeDiscoveryProvider,
)

ROOT = Path(__file__).resolve().parents[2]


def test_PublicProducerContractRemainsTypedAndNonexecuting():
    """Quick Scan can bind the fixed producer API without importing CLI or starting a probe."""

    descriptor = NativeHttpAdapter(lambda _: b"").Descriptor
    assert (
        descriptor.adapter_id == NATIVE_HTTP_PROVIDER_ID == "native.http"
    ), 'Public Producer Contract Remains Typed And Nonexecuting boundary invariant failed'
    assert (
        descriptor.capabilities == (NATIVE_HTTP_CAPABILITY,)
    ), 'Public Producer Contract Remains Typed And Nonexecuting boundary invariant failed'
    assert (
        descriptor.version == DISCOVERY_VERSION == "1"
    ), 'Public Producer Contract Remains Typed And Nonexecuting boundary invariant failed'
    assert (
        descriptor.maximum_impact is ImpactLevel.SAFE and not descriptor.required_privileges
    ), 'Public Producer Contract Remains Typed And Nonexecuting boundary invariant failed'
    signature = inspect.signature(NativeDiscoveryProvider)
    assert tuple(signature.parameters) == (
        "workspace_root", "targets", "scope_id", "policy", "limits", "clock",
    ), 'Public Producer Contract Remains Typed And Nonexecuting boundary invariant failed'
    assert (
        inspect.iscoroutinefunction(NativeDiscoveryProvider.Run)
    ), 'Public Producer Contract Remains Typed And Nonexecuting boundary invariant failed'
    assert (
        DiscoveryLimits().max_endpoints == 8
    ), 'Public Producer Contract Remains Typed And Nonexecuting boundary invariant failed'


@pytest.mark.parametrize("status", [200, 302, 404, 500, 599])
def test_StatusRecordSchemaAndParserAgree(status):
    """Valid observed status output satisfies its versioned wire grammar and binding parser."""

    schema = json.loads((ROOT / "contracts/native-http-record.schema.json").read_text())
    record = {"schema_version": 1, "url": "http://127.0.0.1/", "address": "127.0.0.1",
              "port": 80, "scheme": "http", "status": status}
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(record)
    assert (
        ParseRecord(json.dumps(record).encode(), record["url"]) == record
    ), 'Status Record Schema And Parser Agree boundary invariant failed'


@pytest.mark.parametrize("name", ["timeout", "connection", "protocol", "tls", "input"])
def test_FailureRecordHasNoUntrustedText(name):
    """Only fixed failure categories cross the worker wire boundary."""

    schema = json.loads((ROOT / "contracts/native-http-record.schema.json").read_text())
    record = {"schema_version": 1, "error": name}
    Draft202012Validator(schema).validate(record)
    assert (
        ParseRecord(json.dumps(record).encode(), "http://127.0.0.1/") == record
    ), 'Failure Record Has No Untrusted Text boundary invariant failed'
    assert (
        not Draft202012Validator(schema).is_valid({**record, "body": "secret"})
    ), 'Failure Record Has No Untrusted Text boundary invariant failed'
