# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Compose real CWE ZIP, lexical XML and immutable selection owners on bounded owned streams."""

from __future__ import annotations

import struct
from unittest.mock import Mock

import pytest

import fuzzy1337.intelligence_cwe_selection as selection_module
from fuzzy1337.intelligence import MAX_SOURCE_BYTES
from fuzzy1337.intelligence_cwe_selection import ParseCweSelection
from fuzzy1337.intelligence_cwe_xml import CweXmlCollector
from tests.unit.test_intelligence_cwe_selection import Archive, Catalog, Entry, Selected


@pytest.mark.integration
def test_ProfileStreamsPastLegacySourceBudgetWithoutChangingIt():
    """A separate 32-MiB expanded profile consumes all supplied ignored source bytes."""

    extra = b"x" * (18 * 1024 * 1024)
    xml = Catalog(b"<Weaknesses>" + Entry() + b"</Weaknesses><External_References>"
                  b"<External_Reference><Ignored>" + extra
                  + b"</Ignored></External_Reference></External_References>")
    result = Selected(xml)
    assert result.decoded_size > MAX_SOURCE_BYTES == 16 * 1024 * 1024, (
        "Pure expanded selection reused or raised the legacy source ceiling"
    )
    assert result.xml_text_bytes == len(extra) and len(result.records) == 1, (
        "The selected-ID match bypassed later ignored source bytes"
    )


@pytest.mark.integration
@pytest.mark.parametrize("kind", ["text", "entry-text", "entry-nodes", "nodes", "attributes"])
def test_ActualStreamsIndependentlyReachEachCumulativeResourceDenial(kind):
    """Real callbacks exercise fixed owner ceilings after an earlier valid selected source entry."""

    if kind == "text":
        tail = b"<External_References><External_Reference>" + b"x" * (24 * 1024 * 1024 + 1)
        tail += b"</External_Reference></External_References>"
        inner = b"<Weaknesses>" + Entry() + b"</Weaknesses>" + tail

    elif kind == "entry-text":
        inner = b"<Weaknesses>" + Entry(content=b"x" * (1024 * 1024)) + b"</Weaknesses>"

    elif kind == "entry-nodes":
        inner = b"<Weaknesses>" + Entry(content=b"<x/>" * 65536) + b"</Weaknesses>"

    elif kind == "nodes":
        inner = (b"<External_References><External_Reference>" + b"<x/>" * 1000000
                 + b"</External_Reference></External_References>")

    else:
        element = b"<x a='" + b"x" * 8192 + b"'/>"
        inner = (b"<External_References><External_Reference>" + element * 513
                 + b"</External_Reference></External_References>")

    with pytest.raises(ValueError, match="profile"):
        Selected(Catalog(inner))


@pytest.mark.integration
@pytest.mark.parametrize("kind", ["tag", "comment", "pi", "xml-declaration"])
def test_CompleteTokenAtExact64KiBCeilingAcceptsAndNextByteRefuses(kind):
    """Complete token framing includes delimiters and XML declarations, independently of chunks."""

    if kind == "tag":
        prefix, suffix = b"<x", b"/>"

    elif kind == "comment":
        prefix, suffix = b"<!--", b"-->"

    elif kind == "pi":
        prefix, suffix = b"<?owned ", b"?>"

    else:
        prefix, suffix = b"<?xml version='1.0'", b"?>"

    token = prefix + b" " * (65536 - len(prefix) - len(suffix)) + suffix

    if kind == "xml-declaration":
        xml = Catalog(declaration=token)
        too_large = Catalog(declaration=token.replace(b"?>", b" ?>"))

    else:
        xml = Catalog(b"<External_References><External_Reference>" + token
                      + b"</External_Reference></External_References>")
        too_large = xml.replace(token, prefix + b" " * (65537 - len(prefix) - len(suffix)) + suffix)

    result = Selected(xml)
    observed = (result.maximum_markup_token_bytes if kind in ("tag", "xml-declaration")
                else result.maximum_comment_pi_bytes)
    assert observed == 65536, "Exact token-boundary observation was truncated or refused"

    with pytest.raises(ValueError, match="token"):
        Selected(too_large)


@pytest.mark.integration
def test_ManyShortCommentsPisAndCdataKeepExactAccountingAcrossAllChunks():
    """Dense small literal tokens stay streaming and retain actual source work counters."""

    literals = b"<!--x--><?owned y?><![CDATA[z]]>" * 50000
    result = Selected(Catalog(literals))
    assert result.xml_node_count == 100001, "Dense comment/PI nodes were omitted"
    assert result.xml_text_bytes == 400000, "Dense literal/source PI target bytes were miscounted"
    assert result.maximum_reference_bytes == 0, "CDATA or PI invented live source references"


@pytest.mark.integration
def test_OriginalZipCompletionMustSucceedBeforeXmlFinishCanExposeFacts(monkeypatch):
    """CRC-refused original bytes never reach completed XML selection facts."""

    xml = Catalog(b"<Weaknesses>" + Entry() + b"</Weaknesses>")
    raw = bytearray(Archive(xml))
    central_offset = struct.unpack_from("<I", raw, len(raw) - 6)[0]
    struct.pack_into("<I", raw, 14, 0)
    struct.pack_into("<I", raw, central_offset + 16, 0)
    collector = CweXmlCollector("5.0", ("CWE-79",))
    finish = Mock(wraps=collector.Finish)
    collector.Finish = finish
    monkeypatch.setattr(selection_module, "CweXmlCollector", lambda *args: collector)

    with pytest.raises(ValueError, match="CRC"):
        ParseCweSelection(bytes(raw), ("CWE-79",), catalog_version="5.0")

    assert collector.records and not finish.called, (
        "CRC-refused original bytes exposed completed XML selection facts"
    )


@pytest.mark.integration
def test_ACompleteEmptyZipMemberCannotProduceAPublicSelection():
    """The ZIP owner's complete zero-byte member facts never substitute for a closed XML root."""

    with pytest.raises(ValueError, match="incomplete"):
        ParseCweSelection(Archive(b""), ("CWE-79",), catalog_version="5.0")
