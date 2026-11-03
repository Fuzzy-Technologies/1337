# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify exact single-CVE HTTPS admission and preserved primary data notices."""

import hashlib
from dataclasses import replace

import pytest

from fuzzy1337.intelligence_cve_remote import (
    CVE_COPYRIGHT_NOTICE,
    CVE_NOTICE_BLOB,
    CVE_NOTICE_SOURCE,
    CVE_TERMS_NOTICE,
    CveHttpsRequest,
    CveHttpsSource,
    DecodeHttpsSource,
)


def Source():
    """Declare one immutable selected record pin without making a network request."""

    return CveHttpsSource("a" * 40, "CVE-1900-0001", "b" * 64)


@pytest.mark.parametrize("field,value", [("commit", "main"), ("commit", "A" * 40),
    ("commit", "a" * 39), ("commit", "a" * 41), ("commit", "../" + "a" * 37),
    ("commit", "a" * 40 + "?query"), ("commit", "a" * 40 + "#fragment"),
    ("commit", "https://evil.invalid"), ("commit", 1),
    ("identifier", "cve-1900-0001"), ("identifier", "CWE-79"),
    ("identifier", "CVE-1900-001"), ("identifier", "CVE-1900-" + "1" * 20),
    ("identifier", "CVE-1900-0001/../0002"), ("identifier", "CVE-1900-0001?query"),
    ("identifier", "CVE-1900-%30001"), ("identifier", ("CVE-1900-0001",)),
    ("identifier", None), ("expected_sha256", None), ("expected_sha256", "B" * 64),
    ("expected_sha256", "b" * 63), ("expected_sha256", "b" * 65)])
def test_SourceRefusesAliasesNoncanonicalIdsAndMissingMandatoryPin(field, value):
    """No source component can admit alternate locators, implicit selection or unpinned bytes."""

    with pytest.raises(ValueError):
        replace(Source(), **{field: value})


@pytest.mark.parametrize("serial,bucket", [("0001", "0xxx"), ("3094", "3xxx"),
    ("10000", "10xxx"), ("1" * 19, "1" * 16 + "xxx")])
def test_GeneratedResourceRetainsExactLexicalSerialAndYear(serial, bucket):
    """Path derivation preserves original canonical digits without integer coercion or aliases."""

    source = replace(Source(), identifier="CVE-2024-" + serial)
    expected = ("https://raw.githubusercontent.com/CVEProject/cvelistV5/" + "a" * 40
                + f"/cves/2024/{bucket}/CVE-2024-{serial}.json")
    assert source.SourceUrl == expected, "CVE locator changed the exact immutable path recipe"


@pytest.mark.parametrize("field,value", [("source", None), ("source", {}),
    ("max_bytes", True), ("max_bytes", 0), ("max_bytes", 1048577),
    ("timeout_seconds", True), ("timeout_seconds", "15"), ("timeout_seconds", 0.049),
    ("timeout_seconds", 60.001), ("timeout_seconds", float("nan")),
    ("timeout_seconds", float("inf"))])
def test_RequestRefusesUntypedOrUnboundedReceiveLimits(field, value):
    """Finite profile admission runs before a workspace or receiver is entered."""

    with pytest.raises(ValueError):
        replace(CveHttpsRequest(Source()), **{field: value})


@pytest.mark.parametrize("timeout,maximum", [(0.05, 1), (60, 1048576)])
def test_ExactFiniteRequestLimitsAreAccepted(timeout, maximum):
    """Both timeout boundaries and the exact one MiB source ceiling remain usable."""

    request = CveHttpsRequest(Source(), maximum, timeout)
    assert request.max_bytes == maximum and request.timeout_seconds == timeout, (
        "Accepted request changed its explicit source-byte or timeout limits"
    )


def test_FullPrimaryLicenseAndDisclaimerTextRetainsPinnedOfficialBlobIdentity():
    """Bundled text is the entire reviewed license/disclaimer source, not a URL-only notice."""

    original = ("---\ntitle: Terms of Use\nlayout: page\n---\n" + CVE_TERMS_NOTICE).encode("utf-8")
    framed = b"blob " + str(len(original)).encode("ascii") + b"\0" + original
    digest = hashlib.sha1(framed).hexdigest()
    assert digest == CVE_NOTICE_BLOB == "9a1df8348853e654ed926d884047b6b9875b2f8d", (
        "Bundled CVE notice no longer reproduces the reviewed official terms Git blob"
    )
    assert CVE_NOTICE_SOURCE == ("https://github.com/CVEProject/cveproject.github.io/blob/"
        "edf6d280a1a3a63af267a0f2ee043b6ed402196a/docs/terms.md"), (
        "Data notice lost its independently pinned primary-source provenance"
    )
    assert CVE_COPYRIGHT_NOTICE == "Copyright © 1999–2026, The MITRE Corporation.", (
        "Observed copyright designation was synthesized or changed"
    )


def test_SourcePresentationIsDetachedAndDoesNotInventSchemaDataLicensing():
    """Fixed data attribution stays separate from schema CC0 and legal/authenticity verdicts."""

    source = Source()
    document = source.ToDict()
    assert DecodeHttpsSource(document) == source, "Exact source declaration failed to round-trip"
    assert document["legal_rights"] == document["publisher_authentication"] == "not-assessed", (
        "Source metadata invented legal entitlement or publisher authentication"
    )
    assert document["data_license_name"] == "CVE Program Terms of Use", (
        "Data attribution borrowed the separate schema CC0 or implementation license"
    )
    document["data_notice"]["text"] = "changed"
    assert source.ToDict()["data_notice"]["text"] == CVE_TERMS_NOTICE, (
        "Mutating a detached notice changed immutable source identity"
    )


@pytest.mark.parametrize("field,value", [("source_url", "https://evil.invalid/source"),
    ("publisher", "someone"), ("data_license_name", "CC0-1.0"),
    ("terms_url", "https://evil.invalid"), ("data_notice", {}),
    ("publisher_authentication", "verified"), ("legal_rights", "granted"), ("extra", True)])
def test_DecodedSourceRequiresExactFixedDataAttributionAndGeneratedLocator(field, value):
    """Rehashed source declarations cannot change fixed notices or imply stronger guarantees."""

    document = Source().ToDict()
    document[field] = value

    with pytest.raises(ValueError):
        DecodeHttpsSource(document)


@pytest.mark.parametrize("payload,maximum", [(b"{}", 1), ("{}", 10)])
def test_StrictJsonObjectRejectsWrongByteTypeAndProfileOverflow(payload, maximum):
    """The pure byte boundary remains explicit even when called without a filesystem owner."""

    from fuzzy1337.intelligence_cve_remote import JsonObject

    with pytest.raises(ValueError, match="byte profile"):
        JsonObject(payload, maximum)


@pytest.mark.parametrize("field,value", [("commit", "a" * 40),
    ("identifier", "CVE-1900-0001"), ("expected_sha256", "b" * 64)])
def test_SourceRejectsStringSubclassesAtCallerControlledAdmission(field, value):
    """String subclasses cannot override locator derivation or mandatory pin comparisons."""

    class SourceText(str):
        """Represent caller-controlled text with subclass method-dispatch semantics."""

    with pytest.raises(ValueError):
        replace(Source(), **{field: SourceText(value)})
