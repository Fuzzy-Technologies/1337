# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify immutable EPSS HTTPS source grammar and finite request admission."""

from dataclasses import replace

import pytest

from fuzzy1337.intelligence_epss_remote import DecodeHttpsSource, EpssHttpsRequest, EpssHttpsSource


def Source():
    """Declare one exact immutable archive pin without contacting any remote service."""

    return EpssHttpsSource("a" * 40, "2026-11-02", "model", "b" * 64)


@pytest.mark.parametrize("field,value", [("commit", "main"), ("commit", "A" * 40),
    ("commit", "a" * 39), ("commit", "a" * 41), ("commit", "../" + "a" * 37),
    ("commit", "a" * 40 + "?query"), ("commit", "a" * 40 + "#fragment"),
    ("commit", "https://evil.invalid"), ("commit", 1),
    ("score_date", "2026-02-30"), ("score_date", "2026-1-02"),
    ("score_date", "2026-11-02/../03"), ("score_date", None),
    ("model_version", ""), ("model_version", " model"), ("model_version", "x" * 257),
    ("expected_sha256", None), ("expected_sha256", "B" * 64), ("expected_sha256", "b" * 63)])
def test_SourceRejectsAliasesTraversalAndMissingMandatoryPin(field, value):
    """No caller-controlled component can admit an alternate host/path, alias or absent pin."""

    with pytest.raises(ValueError):
        replace(Source(), **{field: value})


@pytest.mark.parametrize("field,value", [("source", None), ("requested_ids", []),
    ("requested_ids", ()), ("requested_ids", ("cve-1900-0001",)),
    ("requested_ids", ("CVE-1900-0002", "CVE-1900-0001")),
    ("requested_ids", ("CVE-1900-0001",) * 2),
    ("requested_ids", tuple(f"CVE-1900-{i:04}" for i in range(65))),
    ("max_bytes", True), ("max_bytes", 0), ("max_bytes", 4194305),
    ("timeout_seconds", True), ("timeout_seconds", "15"), ("timeout_seconds", 0.049),
    ("timeout_seconds", 60.001), ("timeout_seconds", float("nan")),
    ("timeout_seconds", float("inf"))])
def test_RequestRejectsMutableNoncanonicalOrUnboundedSelections(field, value):
    """All admission occurs before the isolated receiver or any source bytes are consumed."""

    request = EpssHttpsRequest(Source(), ("CVE-1900-0001",))

    with pytest.raises(ValueError):
        replace(request, **{field: value})


@pytest.mark.parametrize("timeout,maximum", [(0.05, 1), (60, 4194304)])
def test_ExactFiniteRequestBoundariesAreAccepted(timeout, maximum):
    """Both declared timeout boundaries and the exact four MiB compressed cap remain usable."""

    request = EpssHttpsRequest(Source(), ("CVE-1900-0001",), maximum, timeout)
    assert request.max_bytes == maximum and request.timeout_seconds == timeout


def test_OnlyGeneratedImmutableLocatorAndPrimaryAttributionArePresented():
    """Fixed source links remain detached without an invented data license or authenticity."""

    source = Source()
    assert source.source_url == ("https://raw.githubusercontent.com/empiricalsec/epss_scores/"
        + "a" * 40 + "/2026/epss_scores-2026-11-02.csv.gz")
    document = source.ToDict()
    assert DecodeHttpsSource(document) == source
    assert document["data_license"] == "not-established"
    assert document["publisher_authentication"] == "not-assessed"
    document["terms_urls"].append("https://evil.invalid")
    assert source.ToDict()["terms_urls"] == ["https://www.first.org/about/policies/terms"]


@pytest.mark.parametrize("field,value", [("source_url", "https://evil.invalid/source"),
    ("publisher", "someone"), ("attribution_url", "https://evil.invalid"),
    ("data_url", "https://evil.invalid"), ("terms_urls", []),
    ("data_license", "Apache-2.0"), ("publisher_authentication", "verified"),
    ("extra", True)])
def test_DecodedSourceRequiresExactFixedAttributionAndGeneratedLocator(field, value):
    """Rehashed source metadata cannot change admission or imply stronger source guarantees."""

    document = Source().ToDict()
    document[field] = value

    with pytest.raises(ValueError):
        DecodeHttpsSource(document)
