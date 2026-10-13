# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Handwritten captured-source and bounded-frontier compatibility oracles."""

from __future__ import annotations

import hashlib

import pytest

from fuzzy1337.captured_web import (
    CAPTURED_WEB_PROFILE_VERSION,
    CapturedWebLimits,
    ReadCapturedWebFrontier,
)
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import CanonicalModelJson
from tests.contract.captured_web_fixture import Fixture


def test_HandwrittenSourceAndOracleBindEveryReturnedStructuralCandidate(tmp_path):
    """Verified bytes yield the independently authored links, counts and attribution."""

    fixture = Fixture.Create(tmp_path / "workspace")
    frontier = ReadCapturedWebFrontier(fixture.root, fixture.source, fixture.capture,
                                      fixture.scope.scope_id, at=fixture.at)
    expected = fixture.oracle["complete_entries"]
    assert CAPTURED_WEB_PROFILE_VERSION == frontier.profile_version == 1, "Profile version changed"
    assert frontier.anchor_count == frontier.processed_anchors == 19, "Lexical ordinals changed"
    assert frontier.complete and not frontier.truncation_reasons, "Complete oracle became partial"
    assert frontier.discarded_candidates == 0, "Complete oracle omitted a candidate"
    assert dict(frontier.exclusion_counts) == fixture.oracle["complete_exclusion_counts"], (
        "Exclusion precedence/counts differ from the independent oracle"
    )
    assert [entry.template.endpoint.path_template for entry in frontier.entries] == [
        entry["path"] for entry in expected
    ], "Canonical candidate ordering or lexical template semantics changed"
    assert [entry.ordinals for entry in frontier.entries] == [tuple(entry["ordinals"])
                                                           for entry in expected], (
        "Deduplication lost exact original anchor ordinals"
    )
    assert all(entry.template.endpoint.method == "GET" for entry in frontier.entries), (
        "Lexical links invented a mutation method"
    )
    assert all(entry.decision.Allowed() and
               entry.decision.target_reference == entry.target.Reference()
               for entry in frontier.entries), "Candidate membership was not checked individually"
    assert frontier.capture == LocalEvidenceStore(fixture.root / "evidence").Get(
        fixture.capture.evidence_id
    ), "Full source manifest/provenance was lost"
    assert frontier.capture.provenance.source_version == "synthetic-html-v7", (
        "Source format version was confused with collector version"
    )
    assert frontier.capture.provenance.tool_version == "fixture-collector-v3", (
        "Collector version changed"
    )
    scope_digest = hashlib.sha256(CanonicalModelJson(fixture.scope.ToDict())).hexdigest()
    assert frontier.scope_sha256 == scope_digest, (
        "Full scope contents were replaced with a revision-only pin"
    )
    assert frontier.source == fixture.source and (
        frontier.source_target.value == fixture.oracle["source_url"]
    ), (
        "Explicit source/capture association was changed or inferred"
    )


@pytest.mark.parametrize("case_index", range(4), ids=["work", "candidates", "both", "exact-full"])
def test_IndependentSoftLimitOracleRemainsTruthfulAtExactExhaustion(tmp_path, case_index):
    """Work/candidate bounds retain scoped partial results with explicit omissions."""

    fixture = Fixture.Create(tmp_path / "workspace")
    case = fixture.oracle["bounded_cases"][case_index]
    limits = CapturedWebLimits(case["max_anchor_work"], case["max_candidates"])
    frontier = ReadCapturedWebFrontier(fixture.root, fixture.source, fixture.capture,
                                      fixture.scope.scope_id, at=fixture.at, limits=limits)
    assert frontier.processed_anchors == case["processed_anchors"], "Anchor work count changed"
    actual_paths = [entry.template.endpoint.path_template for entry in frontier.entries]
    assert actual_paths == case["entry_paths"], (
        "Bounded selection did not retain sorted canonical candidates"
    )
    assert [list(entry.ordinals) for entry in frontier.entries] == case["entry_ordinals"], (
        "Unprocessed or discarded ordinals entered the returned candidates"
    )
    assert list(frontier.truncation_reasons) == case["truncation_reasons"], "Partial reason changed"
    assert frontier.complete is (not case["truncation_reasons"]), "Exact completeness changed"
    assert frontier.discarded_candidates == case["discarded_candidates"], "Discarded count changed"
    expected_counts = (fixture.oracle["complete_exclusion_counts"] if
                       case.get("exclusion_counts_use_complete") else case["exclusion_counts"])
    assert dict(frontier.exclusion_counts) == expected_counts, "Excluded counts changed"
