# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure source-byte and exceptional-cleanup counterexamples for the independent CLI target."""

from __future__ import annotations

from html.parser import HTMLParser
from types import SimpleNamespace

import pytest

from tests.contract import native_header_cli_target as target
from tests.contract.native_response_header_oracle import FrozenOriginals, HeaderAbsent


class LinkReader(HTMLParser):
    """Read only independently authored target links without importing a production parser."""

    def __init__(self) -> None:
        """Collect actual finite anchor href attributes in document order."""

        super().__init__()
        self.links = []

    def handle_starttag(self, tag: str, attributes: list[tuple[str, str | None]]) -> None:
        """Use the standard parser callback spelling for complete target markup."""

        if tag == "a":
            self.links.extend(value for name, value in attributes if name == "href")


def test_SeedAndFrozenSourcesHaveIndependentThreeLinkOneZeroOneTruth() -> None:
    """Render no listener; exact real header names and body-only text establish different truths."""

    graph = target.HeaderPipelineGraph("http://127.0.0.1:19008")
    seed = graph.Response(target.SEED).Wire()
    headers, body = seed.split(b"\r\n\r\n", 1)
    parser = LinkReader()
    parser.feed(body.decode("ascii"))
    assert parser.links == ["/zap-passive/missing", "/zap-passive/fixed",
        "/zap-passive/body-decoy"], "Only three original source links may exist"
    assert len(graph.SelectedUrls()) == 4 and body == target.SEED_BODY, "Four URLs are selected"
    assert b"Content-Length: " + str(len(body)).encode() in headers, "Seed framing must be complete"
    originals = FrozenOriginals()
    observed = []

    for case in target.CASES:
        wire = graph.Response("/zap-passive/" + case).Wire()
        assert wire == originals[case]["response"], "Frozen original wire must remain exact"
        original_header, original_body = wire.split(b"\r\n\r\n", 1)
        observed.append(HeaderAbsent(original_header + b"\r\n\r\n"))
        assert original_body == originals[case]["body"], "Original body bytes must remain exact"

    assert observed == [True, False, True], "Complete field names determine one/zero/one truth"
    assert originals["missing"]["body"] == originals["fixed"]["body"], "Bodies do not decide truth"
    assert b"X-Content-Type-Options: nosniff" in originals["body-decoy"]["body"], (
        "Body-only field text must remain a positive counterexample")


@pytest.mark.parametrize("failure", ["main", "sentinel"])
def test_ConstructorFailureRetainsActualPartialOwnerCleanup(tmp_path, monkeypatch, failure) -> None:
    """Fake construction failures retain actual closure without an invented settled target."""

    closed = []
    records = []

    def Main():
        """Return one inert owner or fail before any original owner was returned."""

        if failure == "main":
            raise RuntimeError("fixed fake constructor failure")

        return SimpleNamespace(state=SimpleNamespace(Counters=lambda: {"contacts": 0},
            Errors=lambda: ()), socket=SimpleNamespace(fileno=lambda: -1 if closed else 7),
            server_close=lambda: closed.append("main"))

    def Sentinel(**_kwargs):
        """Fail only after the original main owner exists, without binding a real descriptor."""

        raise RuntimeError("fixed fake sentinel failure")

    monkeypatch.setattr(target, "HeaderPipelineServer", Main)
    monkeypatch.setattr(target, "CrawlGraphServer", Sentinel)
    evidence = SimpleNamespace(Json=lambda name, value: records.append((name, value)))

    with pytest.raises(RuntimeError, match="fixed fake"):
        with target.HeaderPipelineTarget(evidence):
            raise AssertionError("Failed constructor may never expose a usable target")

    assert closed == ([] if failure == "main" else ["main"]), "Close every returned original owner"
    assert records[0][0] == "target-final.json", "Retain final facts even on constructor failure"
    final = records[0][1]
    assert final["target_yielded"] is False and final["owner_state"] == "unobserved", (
        "Failed construction cannot claim settled runtime acceptance")
    assert final["partial_owners"]["sentinel"] is None, "A failed constructor returned no owner"
    assert (final["partial_owners"]["main"] is None) is (failure == "main"), (
        "Only an actually returned main owner supplies measured partial facts")

    if failure == "sentinel":
        assert final["partial_owners"]["main"]["listener_closed"] is True, (
            "The original returned listener must physically close")
