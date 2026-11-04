# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise exact remote-CWE declarations and canonical limits before resource admission."""

from __future__ import annotations

import math
from dataclasses import replace

import pytest

from fuzzy1337 import intelligence_cwe_remote as remote
from fuzzy1337.intelligence_cwe_notice import CweNoticeBundle


def Request():
    """Return one immutable finite remote declaration with no supplied body or callback."""

    return remote.CweHttpsRequest(remote.CweHttpsSource("5.0", "a" * 64), ("CWE-79",))


@pytest.mark.parametrize("field,value", [
    ("catalog_version", None), ("catalog_version", 5.0), ("catalog_version", "latest"),
    ("expected_sha256", None), ("expected_sha256", "A" * 64), ("expected_sha256", "a" * 63),
    ("notice_profile", None), ("notice_profile", "unknown"),
])
def test_SourceRejectsUnknownCatalogPinOrNotice(field, value):
    """No source class accepts caller URLs, alternate notices or guessed current releases."""

    with pytest.raises(ValueError):
        replace(Request().source, **{field: value})


@pytest.mark.parametrize("field,value", [
    ("source", {}), ("requested_ids", []), ("requested_ids", ()),
    ("requested_ids", ("CVE-2024-3094",)), ("requested_ids", ("CWE-9", "CWE-1")),
    ("requested_ids", ("CWE-1",) * 65), ("max_bytes", True), ("max_bytes", 0),
    ("max_bytes", 4194305), ("timeout_seconds", True), ("timeout_seconds", "15"),
    ("timeout_seconds", 0), ("timeout_seconds", 0.049), ("timeout_seconds", 60.001),
    ("timeout_seconds", math.inf), ("timeout_seconds", -math.inf),
    ("timeout_seconds", math.nan),
    pytest.param("timeout_seconds", 10**10000, id="huge-integer-timeout"),
])
def test_RequestRejectsAliasesNonfiniteAndHugeLimitsBeforeDelegation(field, value):
    """The remote owner rejects huge integers before math conversion or any resource call."""

    with pytest.raises(ValueError):
        replace(Request(), **{field: value})


@pytest.mark.parametrize("timeout", [0.05, 15, 15.0, 60])
def test_EquivalentAdmittedTimeoutsHaveCanonicalFloatIdentity(timeout):
    """Only the new family canonicalizes accepted timeout spellings, including both bounds."""

    request = replace(Request(), timeout_seconds=timeout)
    assert type(request.timeout_seconds) is float, "New request retained noncanonical timeout"
    assert request.timeout_seconds == float(timeout), "Effective time changed"


@pytest.mark.parametrize("version", ["5.0", "4.21"])
def test_SourceLocatorAndFullNoticeAreFixedAndDetached(version):
    """A finite version selects one query-free path and retains complete original notice facts."""

    source = remote.CweHttpsSource(version, "a" * 64)
    value = source.ToDict()
    assert source.SourceUrl == f"https://cwe.mitre.org/data/xml/cwec_v{version}.xml.zip", (
        "Remote source acquired an uncontrolled locator"
    )
    assert value["notice_bundle"] == CweNoticeBundle(), "Source lost complete notice"
    assert remote.DecodeSource(value) == source, "Fixed source cannot reopen"
    value["notice_bundle"]["text"] = "changed"
    assert source.ToDict()["notice_bundle"] == CweNoticeBundle(), "Caller mutated source notice"


@pytest.mark.parametrize("value", [None, [], {}, {"catalog_version": "5.0"}])
def test_SourceDecoderRejectsIncompleteDeclarations(value):
    """A label or missing source cannot substitute for the complete fixed source identity."""

    with pytest.raises(ValueError):
        remote.DecodeSource(value)


@pytest.mark.parametrize("mutation", ["extra", "source-size", "notice-size", "notice-text"])
def test_SourceDecoderBoundsSubdocumentsBeforeReconstruction(mutation):
    """Source and notice allocations retain separate finite serialized ceilings."""

    document = Request().source.ToDict()

    if mutation == "extra":
        document["unexpected"] = True

    elif mutation == "source-size":
        document["unexpected"] = "x" * (remote.MAX_SOURCE_BYTES + 1)

    elif mutation == "notice-size":
        document["notice_bundle"]["text"] = "x" * (remote.MAX_NOTICE_BYTES + 1)

    else:
        document["notice_bundle"]["text"] = "not the captured complete notice"

    with pytest.raises(ValueError):
        remote.DecodeSource(document)


@pytest.mark.parametrize("which", ["notice", "source"])
def test_ProducerSourceBoundsApplyBeforeWorkspaceOrReceiver(monkeypatch, which):
    """Even producer-side metadata changes cannot bypass the frozen subdocument profile."""

    monkeypatch.setattr(remote, "MAX_NOTICE_BYTES" if which == "notice" else "MAX_SOURCE_BYTES", 1)

    with pytest.raises(ValueError):
        remote.CweHttpsSource("5.0", "a" * 64)


def test_InvalidPublicRequestAndScopeDoNoResourceWork(tmp_path, monkeypatch):
    """Typed request and scope admission happen before opening any workspace or process."""

    def Forbidden(*args, **kwargs):
        """Turn a premature resource operation into a directly observable test failure."""

        raise AssertionError("Invalid remote admission reached a resource")

    monkeypatch.setattr(remote.LocalWorkspaceStore, "Open", Forbidden)
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", Forbidden)

    with pytest.raises(ValueError):
        remote.AcquireHttpsCweSelection(tmp_path, {}, scope_reference="scope:owned")

    with pytest.raises(ValueError):
        remote.AcquireHttpsCweSelection(tmp_path, Request(), scope_reference="")
