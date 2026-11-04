# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Check the finite directory-index relationship, bounds and explicit native profile contracts."""

from __future__ import annotations

import hashlib

import pytest

from fuzzy1337.adapters import AdapterRequest, ImpactLevel
from fuzzy1337.adapters.directory_listing import (
    MAX_DIRECTORY_INDEX_BODY_BYTES,
    SupportedDirectoryIndex,
)
from fuzzy1337.adapters.native_web import (
    NATIVE_DIRECTORY_INDEX_CAPABILITY,
    NATIVE_DIRECTORY_INDEX_CHECK_ID,
    NATIVE_FILE_CANARY_CHECK_ID,
    NATIVE_PROMETHEUS_CHECK_ID,
    NATIVE_WEB_CHECK_ID,
    CanonicalRecord,
    MatchesDirectoryIndex,
    NativeWebAdapter,
    NativeWebParameters,
    NativeWebRecordError,
    ParseNativeWebRecord,
)
from fuzzy1337.native_web_worker import Headers, Main
from fuzzy1337.scope import Target, TargetKind

URL = "http://127.0.0.1:8080/selected/"
ENTRY = '<a href="note.txt">note.txt</a>'


def Classic(entries=ENTRY, *, container="pre", title="Index of /selected/", heading=None,
            body_attributes=""):
    """Author closed specimen HTML independently of the production parser implementation."""

    return (f"<!doctype html><html><head><title>{title}</title></head>"
            f"<body{body_attributes}><h1>{title if heading is None else heading}</h1>"
            f"<{container}>{entries}</{container}></body></html>").encode("utf-8")


@pytest.mark.parametrize("payload", [
    Classic(),
    Classic('<a href="../">Parent Directory</a>' + ENTRY + '<a href="sub/">sub/</a>'),
    Classic('<li>' + ENTRY + '</li>', container="ul"),
    Classic('<tr><th><a href="?C=N;O=D">Name</a></th></tr><tr><td>'
            '<a href="note.txt"><img src="/icons/text.png" alt="[TXT]"></a>'
            + ENTRY + '</td></tr>', container="table"),
    Classic('<a href="caf%C3%A9.txt">café.txt</a>'),
    Classic('<a href="some%20note.txt">some note.txt</a>'),
    Classic(ENTRY + '<!-- <script>not interpreted</script> -->'),
    Classic().replace(b"<html>", b'<html lang="en">').replace(b"<pre>", b"<pre><br/>"),
])
def test_CompleteClassicIndexRequiresRelatedVisibleBasenameEntries(payload):
    """Recognize only complete supported structures with matching title, heading and entry label."""

    assert SupportedDirectoryIndex(payload), "Complete independent classic index was refused."


@pytest.mark.parametrize("payload", [
    b"Index of /selected/ note.txt",
    b'<html><head><title>Index of /selected/</title></head><body>Directory tutorial</body></html>',
    Classic(title="Directory listing tutorial"),
    Classic(heading="Index of /different/"),
    Classic('<a href="note.txt">Read the tutorial</a>'),
    Classic('<!-- ' + ENTRY + ' -->'),
    Classic('&lt;a href="note.txt"&gt;note.txt&lt;/a&gt;'),
    Classic('<a href="../">Parent Directory</a>'),
    Classic('<a href="note.txt"><img src="/icons/text.png" alt="[TXT]"></a>'),
    Classic('<a href="https://example.invalid/note.txt">note.txt</a>'),
    Classic('<a href="/other/note.txt">note.txt</a>'),
    Classic('<a href="../note.txt">note.txt</a>'),
    Classic('<a href="%2e%2e">..</a>'),
    Classic('<a href="%2fnote.txt">/note.txt</a>'),
    Classic('<a href="note%QZ.txt">note%QZ.txt</a>'),
    Classic('<a href="note%C0.txt">note.txt</a>'),
    Classic('<a href="note.txt?download=1">note.txt</a>'),
    Classic('<a>note.txt</a>'),
    Classic('<a href="note.txt" href="second.txt">note.txt</a>'),
    Classic('<a href="note.txt" onclick="show()">note.txt</a>'),
    Classic('<script>' + ENTRY + '</script>'),
    Classic(body_attributes=' hidden="hidden"'),
    Classic(body_attributes=' class="index hidden"'),
    Classic(body_attributes=' style="display:none"'),
    Classic().replace(b"<h1>", b'<h1 aria-hidden="true">'),
    Classic().replace(b"<title>", b'<meta name="title" content="Index of /selected/"><title>'),
    Classic().replace(b"<h1>", b"<h1><span>").replace(b"</h1>", b"</span></h1>"),
    Classic().replace(b"</pre>", b"</table>"),
    Classic().replace(b"</pre>", b"</pre extra>"),
    Classic().replace(b"<html>", b"<html/lang=en>"),
    Classic().replace(b"</html>", b""),
    Classic() + b"<",
    Classic() + b"<!-- unfinished",
    Classic().replace(b"</pre>", b'<a href="unfinished</pre>'),
    Classic().replace(b"<!doctype html>", b'<!DOCTYPE html SYSTEM "file:///unselected">'),
    Classic().replace(b"<!doctype html>", b'<?xml version="1.0"?>'),
    Classic().replace(b"<!doctype html>", b'<![CDATA[not-html]]>'),
    Classic().replace(b"<body>", b"<body>\x00"),
    Classic().replace(b"<body>", b"<body>\xff"),
    Classic().replace(b"</pre>", b"</pre><ul><li>" + ENTRY.encode() + b"</li></ul>"),
    Classic().replace(b"</head>", b"</head><head><title>Index of /selected/</title></head>"),
    Classic().replace(b"<pre>", b"<pre><pre>"),
    Classic().replace(b"</html>", b"</html><html></html>"),
    Classic().replace(b"<pre>", b"<pre/>"),
    Classic().replace(b"<pre>", b"<pre><br></br>"),
    Classic().replace(b"<!doctype html>", b"<!doctype html><!doctype html>"),
    b"<img src='/selected'>",
    b"<head><title>Index of /selected/</title></head>",
])
def test_DecoysHiddenMetadataAndIncompleteMarkupNeverEstablishAnIndex(payload):
    """Refuse wrong relationships, hidden/tutorial/comment controls and unfinished HTML."""

    assert not SupportedDirectoryIndex(payload), "Unsupported specimen became a positive index."


def test_OriginalBodyCeilingAndExactBytesAdmissionRemainIndependent():
    """Accept the exact source cap, refuse overflow and never coerce caller-supplied objects."""

    payload = Classic()
    exact = payload + b" " * (MAX_DIRECTORY_INDEX_BODY_BYTES - len(payload))
    assert SupportedDirectoryIndex(exact), "A valid complete exact-cap index was refused."
    assert not SupportedDirectoryIndex(exact + b" "), "Source byte ceiling was not enforced."

    class AlternateBytes(bytes):
        """Represent a potentially behavior-overriding caller byte subclass."""

    for value in (b"", payload.decode(), bytearray(payload), AlternateBytes(payload), None):
        assert not SupportedDirectoryIndex(value), "Parser coerced an unadmitted input type."


def test_EveryTruncatedDocumentAndUnfinishedTrailingTokenRemainsUnsupported():
    """Never let HTMLParser discard an unfinished tag, attribute, declaration or comment."""

    payload = Classic()

    for length in range(len(payload)):
        assert not SupportedDirectoryIndex(payload[:length]), (
            "A truncated source was accepted before its original closing barrier."
        )

    for token in (b"<a href='note.txt'>note.txt</a>", b"<!--ignored-->", b"<?xml?>",
                  b"<![CDATA[ignored]]>"):
        for length in range(1, len(token)):
            if token[:length].endswith(b">"):
                continue

            assert not SupportedDirectoryIndex(payload + token[:length]), (
                "An unfinished suffix was silently discarded after a closed positive."
            )


def test_EntryTagTokenAndAttributeBudgetsHaveFiniteReachableBoundaries():
    """Exercise independent reachable finite ceilings without changing production constants."""

    assert SupportedDirectoryIndex(Classic('<a href="a">a</a>' * 64)), (
        "The exact finite entry count was refused."
    )
    assert not SupportedDirectoryIndex(Classic('<a href="a">a</a>' * 65)), (
        "An additional entry bypassed the entry budget."
    )
    assert SupportedDirectoryIndex(Classic(ENTRY + '<br>' * 249)), "Exact tag count was refused."
    assert not SupportedDirectoryIndex(Classic(ENTRY + '<br>' * 250)), "Tag budget was bypassed."
    assert SupportedDirectoryIndex(Classic(ENTRY + '<!--' + 'x' * 1017 + '-->')), (
        "An exact-cap bounded inert comment was refused."
    )
    assert not SupportedDirectoryIndex(Classic(ENTRY + '<!--' + 'x' * 1018 + '-->')), (
        "An oversized inert token bypassed the parser cap."
    )
    attributes = ' id="index" class="listing" title="index" lang="en" width="1" height="1"' \
                 ' border="0" align="left"'
    assert SupportedDirectoryIndex(Classic(body_attributes=attributes)), (
        "The exact bounded attribute count was refused."
    )
    assert not SupportedDirectoryIndex(Classic(body_attributes=attributes + ' cellpadding="0"')), (
        "An additional attribute bypassed the per-element budget."
    )
    assert SupportedDirectoryIndex(Classic(body_attributes=' id="' + 'x' * 256 + '"')), (
        "The exact bounded attribute value was refused."
    )
    assert not SupportedDirectoryIndex(Classic(body_attributes=' id="' + 'x' * 257 + '"')), (
        "An oversized attribute value bypassed the transient field budget."
    )
    large = ' id="' + 'a' * 256 + '" class="' + 'b' * 256 + '" title="' + 'c' * 256 \
            + '" lang="' + 'd' * 256 + '"'
    assert not SupportedDirectoryIndex(Classic(body_attributes=large)), (
        "A large complete start token bypassed the independent token ceiling."
    )
    assert not SupportedDirectoryIndex(Classic().replace(
        b"</pre>", b"</pre" + b" " * 1020 + b">")), (
        "An oversized complete closing token bypassed the same original-byte ceiling."
    )


def DirectoryRecord():
    """Build one independently specified successful fixed-field worker record."""

    body = Classic()

    return {"schema_version": 1, "check_id": NATIVE_DIRECTORY_INDEX_CHECK_ID,
        "profile_version": "1", "url": URL, "address": "127.0.0.1", "port": 8080,
        "scheme": "http", "status": 200, "media_type": "text/html", "body_bytes": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(), "matched": True}


def test_ExplicitProfileBindsItsOwnCapabilityInvocationAndFixedOutput():
    """Enroll the finite predicate through the existing exact STD invocation and worker report."""

    target = Target(TargetKind.URL, URL)
    parameters = NativeWebParameters(URL, 1, check_id=NATIVE_DIRECTORY_INDEX_CHECK_ID)
    assert parameters == {"url": URL, "timeout_seconds": 1.0,
                          "check_id": NATIVE_DIRECTORY_INDEX_CHECK_ID}, (
        "The explicit directory profile parameters changed or lost their identity."
    )
    adapter = NativeWebAdapter(lambda reference: b"")
    request = AdapterRequest(NATIVE_DIRECTORY_INDEX_CAPABILITY, target.Reference(),
                             ImpactLevel.STANDARD, parameters)
    invocation = adapter.PrepareInvocation(request)
    assert invocation.argv[-3:] == (URL, "1.0", NATIVE_DIRECTORY_INDEX_CHECK_ID), (
        "The selected check did not reach the actual isolated worker invocation."
    )
    record = DirectoryRecord()
    assert ParseNativeWebRecord(CanonicalRecord(record), URL,
                                check_id=NATIVE_DIRECTORY_INDEX_CHECK_ID) == record, (
        "The complete fixed original directory report was not preserved."
    )

    for change in ({"media_type": "text/plain"}, {"status": 403}, {"body_bytes": 0},
                   {"media_type": "unknown"}):
        with pytest.raises(NativeWebRecordError):
            ParseNativeWebRecord(CanonicalRecord({**record, **change}), URL,
                                  check_id=NATIVE_DIRECTORY_INDEX_CHECK_ID)


def test_HtmlClassificationIsSpecificToTheNewCheckAndDoesNotChangeOldProfiles():
    """Keep old schema-one media categories unchanged while the new profile admits HTML."""

    raw = b"HTTP/1.1 200 OK\r\nContent-Type: Text/HTML; charset=utf-8\r\nContent-Length: 0\r\n\r\n"
    assert Headers(raw, check_id=NATIVE_DIRECTORY_INDEX_CHECK_ID) == (200, "text/html", 0), (
        "The new profile did not classify its actual HTML response media."
    )

    for checkId in (NATIVE_WEB_CHECK_ID, NATIVE_FILE_CANARY_CHECK_ID, NATIVE_PROMETHEUS_CHECK_ID):
        assert Headers(raw, check_id=checkId) == (200, "other", 0), (
            "An existing profile's original media representation changed."
        )

    for status, media in ((200, "text/plain"), (403, "text/html"), (True, "text/html")):
        assert not MatchesDirectoryIndex(status, media, Classic()), (
            "Wrong status, media or scalar type established a directory-index observation."
        )

    assert MatchesDirectoryIndex(200, "text/html", Classic()), (
        "The actual supported HTML/200 profile did not establish the finite predicate."
    )


def test_WorkerMainAdmitsOnlyTheExplicitDirectorySelection(monkeypatch, capsys):
    """Resolve the new exact invocation while retaining input refusal for arbitrary selection."""

    calls = []

    def Probe(url, timeout, *, check_id):
        """Record only invocation dispatch; real networking belongs to functional acceptance."""

        calls.append((url, timeout, check_id))

        return DirectoryRecord()

    monkeypatch.setattr("fuzzy1337.native_web_worker.Probe", Probe)
    assert Main([URL, "1.0", NATIVE_DIRECTORY_INDEX_CHECK_ID]) == 0, (
        "The explicit registered directory worker selection failed."
    )
    assert calls == [(URL, 1.0, NATIVE_DIRECTORY_INDEX_CHECK_ID)], (
        "Worker dispatch changed the selected target, deadline or check identity."
    )
    assert b"note.txt" not in capsys.readouterr().out.encode(), "Transient entry label leaked."
    assert Main([URL, "1.0", "native.unregistered"]) == 64, (
        "An arbitrary worker selection bypassed exact registered dispatch."
    )
