# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise the Internal CWE lexical gate and namespace-aware bounded XML collector."""

from __future__ import annotations

from dataclasses import asdict
from functools import partial
from unittest.mock import Mock

import pytest

from fuzzy1337.intelligence_cwe_xml import (
    CHUNK_BYTES,
    MAX_ATTRIBUTE_BYTES,
    MAX_ENTRY_BYTES,
    MAX_ENTRY_NODES,
    MAX_NODES,
    MAX_TEXT_BYTES,
    CweXmlCollector,
)
from tests.unit.test_intelligence_cwe_selection import Catalog, Entry


def Collect(xml: bytes, size: int = CHUNK_BYTES):
    """Feed owned source at arbitrary permitted boundaries and require complete final facts."""

    collector = CweXmlCollector("5.0", ("CWE-79",))

    for offset in range(0, len(xml), size):
        collector.Feed(xml[offset:offset + size])

    return collector.Finish()


def test_CountersAndPartitionsAreIndependentOfAllRelevantFeedBoundaries():
    """References, quotes, UTF-8, CDATA, comment and PI delimiters may straddle chunks."""

    xml = Catalog(b"<!--literal <!DOCTYPE &fake;--><?owned '?>" + b"<Weaknesses>"
        + Entry(name="  exact & é > ' ", content=b"<Description>one&#65;two&amp;three"
            b"<![CDATA[<!DOCTYPE &literal;]]>tail</Description><Ignored attr='x>y'/>")
        + b"</Weaknesses>", declaration=b'<?xml version="1.0" encoding="UTF-8"?>')
    expected = asdict(Collect(xml))

    for size in (1, 2, 3, 7, 31, 127):
        assert asdict(Collect(xml, size)) == expected, "XML accounting depends on chunk boundaries"

    assert expected["maximum_reference_bytes"] == 6, "Builtin/numeric reference lengths changed"


@pytest.mark.parametrize("declaration", [
    b'<?xml version="1.1"?>', b'<?xml version="1.0" encoding="ISO-8859-1"?>',
    b'<?xml version="1.0" encoding="UTF-16"?>',
])
def test_ExplicitDeclarationGuardRejectsUnsupportedDeclarations(declaration):
    """Forced UTF-8 alone cannot establish the permitted source declaration policy."""

    with pytest.raises(ValueError, match="declaration"):
        Collect(Catalog(declaration=declaration), 1)


@pytest.mark.parametrize("declaration", [
    b"<!DOCTYPE Weakness_Catalog>",
    b'<!DOCTYPE Weakness_Catalog SYSTEM "https://invalid.example/never">',
    b'<!DOCTYPE Weakness_Catalog [<!ENTITY e "expanded">]>',
    b'<!DOCTYPE Weakness_Catalog [<!ENTITY % p SYSTEM "file:///never">%p;]>',
    b"<!ENTITY x 'never'>", b"<!unsupported>",
])
def test_LiveDeclarationsAreDeniedBeforeAnyResolverOrDoctypeCallback(declaration):
    """The lexical gate rejects live DTD/entity syntax before any parser callback."""

    collector = CweXmlCollector("5.0", ("CWE-79",))
    collector.parser = Mock()

    with pytest.raises(ValueError, match="declarations"):
        for byte in declaration:
            collector.Feed(bytes((byte,)))

    assert not collector.parser.Parse.called, "A live forbidden declaration reached Expat"


@pytest.mark.parametrize("raw", [b"\xff", b"\0", b"\xff\xfe<\0r\0/\0>\0", b"\xed\xa0\x80"])
def test_StrictUtf8AndNulDenialAlsoApplyToIgnoredSource(raw):
    """Ignored content cannot introduce another encoding, a surrogate or NUL."""

    with pytest.raises(ValueError, match="UTF-8"):
        Collect(Catalog(raw))


@pytest.mark.parametrize("raw", [b"&evil;", b"&aaaa", b"&#00000000;", b"&#x0000000;", b"&#x;",
                                 b"&#;", b"&AMP;", b"&#0;", b"&#x110000;"])
def test_LiveReferencesHaveBoundedSpellingAndLegalXmlCharacterValues(raw):
    """Numeric/builtin spelling caps are independent of Expat's Unicode and XML character rules."""

    with pytest.raises(ValueError):
        Collect(Catalog(raw), 1)


@pytest.mark.parametrize("raw", [b"&#1114111;", b"&#x10FFFF;"])
def test_LongestTenByteLegalReferenceIsAcceptedWithoutCanonicalizingSource(raw):
    """The finite reference profile permits legal bounded leading and trailing source spellings."""

    facts = Collect(Catalog(raw), 1)
    assert facts.maximum_reference_bytes == 10, "Longest legal reference was shortened or refused"


def test_UnfinishedReferenceIsWithheldFromParserAndRefusedAtItsOwnCeiling():
    """A long unfinished numeric reference cannot make Expat buffer a large token."""

    collector = CweXmlCollector("5.0", ("CWE-79",))
    collector.parser = Mock()

    with pytest.raises(ValueError, match="reference"):
        collector.Feed(b"&#00000000")

    assert all(b"&" not in call.args[0] for call in collector.parser.Parse.call_args_list), (
        "An unfinished live reference reached Expat"
    )


@pytest.mark.parametrize("prefix", [b"<Owned a='", b"<!--", b"<?owned "])
def test_UnfinishedTokensRefuseBeforeAnyLargeParserAllocation(prefix):
    """A complete-token byte ceiling is checked before extending the pre-parser buffer."""

    collector = CweXmlCollector("5.0", ("CWE-79",))
    collector.parser = Mock()
    collector.Feed(prefix)
    collector.Feed(b"x" * (CHUNK_BYTES - len(prefix)))

    with pytest.raises(ValueError, match="token"):
        collector.Feed(b"x")

    assert not collector.parser.Parse.called, "An unfinished oversized markup token reached Expat"
    assert len(collector.pending) == CHUNK_BYTES, "Token buffer grew beyond its fixed byte ceiling"


@pytest.mark.parametrize("token", [
    b"<" + b"x" * 257 + b"/>",
    b"<Owned " + b" ".join(f"a{index}='x'".encode() for index in range(33)) + b"/>",
    b"<Owned " + b" ".join(f"xmlns:p{index}='urn:{index}'".encode()
                            for index in range(33)) + b"/>",
], ids=["raw-qname-overflow", "attribute-count-overflow", "namespace-count-overflow"])
def test_RawQnameAndAttributeCeilingsPrecedeTheStartMappingAllocation(token):
    """Raw prefix names and xmlns declarations count before Expat sees a start token."""

    collector = CweXmlCollector("5.0", ("CWE-79",))
    collector.parser = Mock()

    with pytest.raises(ValueError):
        collector.Feed(token)

    assert not collector.parser.Parse.called, "An over-budget start mapping reached Expat"


@pytest.mark.parametrize("inner", [
    b"<x:include xmlns:x='http://www.w3.org/2001/XInclude' href='never'/>",
    b"<Ignored xmlns='http://www.w3.org/2001/XInclude'/>",
])
def test_XincludeNamespaceIsRejectedInIgnoredNestedFields(inner):
    """No XInclude content is resolved or silently accepted as ordinary ignored metadata."""

    xml = Catalog(b"<Weaknesses>" + Entry(content=inner) + b"</Weaknesses>")

    with pytest.raises(ValueError, match="XInclude"):
        Collect(xml)


@pytest.mark.parametrize("suffix", [b"<", b"<!", b"<!--", b"<?owned", b"&amp", b"<![CDATA["])
def test_FinishRejectsEveryPendingLexicalState(suffix):
    """A source cannot expose private facts with pending delimiters or reference bytes."""

    collector = CweXmlCollector("5.0", ("CWE-79",))
    collector.Feed(Catalog().replace(b"</Weakness_Catalog>", suffix))

    with pytest.raises(ValueError, match="lexical"):
        collector.Finish()


def test_StreamingCdataRetainsOnlyDelimiterSuffixAndCountsTheWholeLiteral():
    """Large CDATA streams while reference-looking and DTD-looking bytes stay literal."""

    collector = CweXmlCollector("5.0", ("CWE-79",))
    collector.Feed(Catalog().replace(b"</Weakness_Catalog>", b"<![CDATA["))

    for _ in range(20):
        collector.Feed(b"x" * CHUNK_BYTES)
        assert len(collector.cdata_tail) <= 2 and not collector.pending, (
            "Streaming CDATA retained an accumulated source node"
        )

    collector.Feed(b"]]></Weakness_Catalog>")
    assert collector.Finish().xml_text_bytes == 20 * CHUNK_BYTES, "CDATA bytes were lost"


def test_DepthAndIndividualAttributeValuesRemainBoundedInsideIgnoredContent():
    """Semantic ignoring cannot evade nesting or normalized attribute value ceilings."""

    for inner in (b"<x>" * 33 + b"</x>" * 33, b"<x a='" + b"v" * 8193 + b"'/>"):
        with pytest.raises(ValueError):
            Collect(Catalog(b"<Weaknesses>" + Entry(content=inner) + b"</Weaknesses>"))


@pytest.mark.parametrize("kind", ["global-node", "entry-node", "global-text", "entry-text",
                                  "global-attributes"])
def test_EachIndependentCumulativeOwnerRefusesItsNextContribution(kind):
    """Reachable owner counters deny one more event independently of source chunk boundaries."""

    collector = CweXmlCollector("5.0", ("CWE-79",))

    if kind == "global-node":
        collector.nodes = MAX_NODES
        action = collector.Node

    elif kind == "entry-node":
        collector.entry_active = True
        collector.entry_nodes = MAX_ENTRY_NODES
        action = collector.Node

    elif kind == "global-text":
        collector.text_bytes = MAX_TEXT_BYTES
        action = partial(collector.Text, "x")

    elif kind == "entry-text":
        collector.entry_active = True
        collector.entry_bytes = MAX_ENTRY_BYTES
        action = partial(collector.Text, "x")

    else:
        collector.attribute_bytes = MAX_ATTRIBUTE_BYTES
        action = partial(collector.Feed, Catalog())

    with pytest.raises(ValueError):
        action()


def test_CompletedCollectorCannotBeReusedAndPartialUtf8CannotFinish():
    """The completion barrier is single-use and includes the incremental UTF-8 decoder."""

    collector = CweXmlCollector("5.0", ("CWE-79",))
    collector.Feed(Catalog())
    collector.Finish()

    with pytest.raises(ValueError):
        collector.Feed(b"")

    with pytest.raises(ValueError):
        collector.Finish()

    partial = CweXmlCollector("5.0", ("CWE-79",))
    partial.Feed(Catalog() + b"\xc3")

    with pytest.raises(ValueError, match="incomplete"):
        partial.Finish()


@pytest.mark.parametrize("payload", [
    b"<Owned a = unquoted/>", b"<Owned&name/>", b"<Owned a='<bad'/>",
    b"<?" + b"x" * 257 + b"?>", b"<?xml version='1.0'>",
])
def test_MalformedNamesAttributesAndDeclarationTokensCannotBypassTheGate(payload):
    """Finite lexical scans fail closed before malformed source tokens become usable facts."""

    with pytest.raises(ValueError):
        Collect(Catalog(payload))


def test_XmlDeclarationQuoteStateIsDistinctFromOrdinaryProcessingInstructions():
    """A quoted declaration terminator is withheld until the real outside-quote terminator."""

    collector = CweXmlCollector("5.0", ("CWE-79",))
    collector.parser = Mock()
    collector.Feed(b"<?xml version='1.0' encoding='UTF-8?>")
    assert not collector.parser.Parse.called and collector.state == "xml-declaration", (
        "An inside-quote declaration terminator reached Expat as a complete token"
    )
    collector.Feed(b"'?>")
    assert collector.parser.Parse.call_count == 1, (
        "Complete declaration token was not released once"
    )


@pytest.mark.parametrize("name,uri", [("p", "x" * 8193)], ids=["namespace-uri-overflow"])
def test_NamespaceUriValueHasItsOwnBoundBeforeStartAttributes(name, uri):
    """Namespace declaration values consume the same finite individual-value ceiling."""

    xml = Catalog().replace(b'Name="Owned CWE"', f'xmlns:{name}="{uri}" Name="Owned CWE"'.encode())

    with pytest.raises(ValueError, match="namespace"):
        Collect(xml)


def test_InternalRuntimeAndFeedAdmissionHaveNoUnsafeFallback(monkeypatch):
    """Unsupported mode/runtime or oversized/nonbytes sink chunks fail explicitly."""

    with pytest.raises(ValueError, match="mode"):
        CweXmlCollector("latest", ("CWE-79",))

    for chunk in (bytearray(b"x"), b"x" * (CHUNK_BYTES + 1)):
        with pytest.raises(ValueError, match="bounded exact bytes"):
            CweXmlCollector("5.0", ("CWE-79",)).Feed(chunk)

    parser = Mock()
    parser.GetReparseDeferralEnabled.return_value = False
    monkeypatch.setattr("fuzzy1337.intelligence_cwe_xml.expat.ParserCreate",
                        lambda **kwargs: parser)

    with pytest.raises(ValueError, match="reparse"):
        CweXmlCollector("5.0", ("CWE-79",))


def test_DefenseInDepthResolutionHandlerAlwaysRaisesWithoutCallingAResolver():
    """Callbacks deny resolution independently of the primary lexical declaration guard."""

    collector = CweXmlCollector("5.0", ("CWE-79",))

    with pytest.raises(ValueError, match="resolution"):
        collector.Forbidden("owned-external-entity", "https://invalid.example/never")


@pytest.mark.parametrize("content", [b"<p:ignored/>", b"<ignored p:attribute='x'/>"])
def test_ExpandedNamesCannotAmplifyLongNamespaceUrisIntoRetainedParserInterns(content):
    """A short raw prefix cannot turn an 8192-byte namespace into many retained expanded names."""

    declaration = b"<External_References xmlns:p='" + b"u" * 8192 + b"'><External_Reference>"
    xml = Catalog(declaration + content + b"</External_Reference></External_References>")

    with pytest.raises(ValueError, match="expanded QName"):
        Collect(xml)
