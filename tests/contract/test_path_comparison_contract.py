# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Check the independent paired-state oracle through actual original owning producers."""

from __future__ import annotations

import json

import pytest

from fuzzy1337.evidence import LocalEvidenceStore
from tests.contract.reachability_fixture import FIXTURES, Fixture
from tests.path_command_helpers import Arguments, Files, Run, Value


def OriginalArguments(fixture, records, *, target="event"):
    """Select one exact ordinary analysis without importing any comparison implementation."""

    return Arguments(fixture.root, fixture.model, fixture.objects["source"].Reference(),
        fixture.objects[target].Reference(),
        tuple(item.Reference() for item in fixture.relations.values()),
        assessments=tuple(record.evidence_id for record in records),
        context=fixture.graph["context_reference"], scope=fixture.graph["scope_reference"],
        at=fixture.graph["query_at"])


def PairArguments(fixture, before, after, *, target="event", focus="portal-identity"):
    """Build the declared paired CLI grammar from common explicit original selections."""

    arguments = OriginalArguments(fixture, (), target=target)
    arguments[0] = "compare"
    arguments.remove("--no-assessments")
    arguments.extend(("--focus-transition", fixture.relations[focus].Reference()))

    for side, records in (("before", before), ("after", after)):
        if records:
            for record in records:
                arguments.extend(("--" + side + "-assessment", record.evidence_id))

        else:
            arguments.append("--" + side + "-no-assessments")

    return arguments


def PathsByAliases(fixture, outcome):
    """Resolve original path identities to handwritten hop aliases without recomputing states."""

    aliases = {item.Reference(): alias for alias, item in fixture.relations.items()}

    return {tuple(aliases[reference] for reference in path["hops"]): path["state"]
            for path in outcome["analysis"]["search"]["paths"]}


@pytest.mark.parametrize("target", ["event", "key"])
def test_HandwrittenOneFocusOraclePreservesBothOriginalAnalyses(tmp_path, target):
    """A blocked focus leaves two event detours and the already blocked key routes explicit."""

    oracle = json.loads((FIXTURES / "path-comparison.oracle.v1.json").read_text())
    fixture = Fixture.Create(tmp_path / "workspace")
    before = fixture.Phase(oracle["before_phase"])
    after = fixture.Phase(oracle["after_phase"])
    original_bytes = Files(fixture.root)
    before_status, original_before = Run(OriginalArguments(fixture, before, target=target))
    after_status, original_after = Run(OriginalArguments(fixture, after, target=target))
    status, result = Run(PairArguments(fixture, before, after, target=target))
    assert before_status == after_status == status == 0, "Original paired admission failed"
    assert set(result) == set(oracle["top_level_fields"]), "Paired machine family changed"
    assert result["schema_version"] == result["profile_version"] == 1 and (
        result["profile"] == "same-basis-selected-path-comparison"
        and result["command"] == "paths.compare" and result["status"] == "completed"
    ), "Comparison lost its distinct additive profile"
    assert result["before"] == original_before and result["after"] == original_after, (
        "Comparison rewrote an original outcome, source proof, estimate, limit or completeness"
    )
    focus = fixture.relations[oracle["focus_transition"]].Reference()
    expected_change = oracle["observed_state_change"]
    assert result["focus_transition"] == focus and result["observed_state_change"] is True and (
        result["state_changes"] == [{"relation_reference": focus,
            "before_state": expected_change["before_state"],
            "after_state": expected_change["after_state"]}]
    ), "A path-count comparison replaced the handwritten transition-state change"

    for side in ("before", "after"):
        expected = {tuple(path["hops"]): path[side + "_state"]
                    for path in oracle[target + "_paths"]}
        assert PathsByAliases(fixture, result[side]) == expected, (
            "The one-focus comparison lost a detour or already blocked route"
        )
        assert result[side]["as_of"] == original_before["as_of"], "A replay clock was invented"

    assert result["model_version"] == original_before["model_version"] == (
        original_after["model_version"]
    ), "The comparison joined different saved model bases"
    assert all(result[name] == "none" for name in (
        "core_mutation", "evidence_mutation", "authority"
    )), "The paired presentation acquired write or execution authority"
    assert Files(fixture.root) == original_bytes, "Comparison wrote original owner state"


def test_EqualStatesRetainDistinctOriginalAssessmentProofs(tmp_path):
    """Identical labels do not collapse separately attributed original acquisition manifests."""

    fixture = Fixture.Create(tmp_path / "workspace")
    before = fixture.Phase("confirmed")
    raw = LocalEvidenceStore(fixture.root / "evidence").Read(before[0].reference)
    after = (fixture.Assessment(raw=raw, source_id="separate-owned-attester"),)
    original_bytes = Files(fixture.root)
    before_status, original_before = Run(OriginalArguments(fixture, before))
    after_status, original_after = Run(OriginalArguments(fixture, after))
    status, result = Run(PairArguments(fixture, before, after))
    assert before_status == after_status == status == 0, "Equal-state original proof was refused"
    assert result["observed_state_change"] is False and result["state_changes"] == [], (
        "A provenance difference became an observed transition-state change"
    )
    assert result["before"] == original_before and result["after"] == original_after, (
        "Equal-state comparison merged distinct source outcomes"
    )
    assert original_before["assessment_manifest_ids"] != original_after[
        "assessment_manifest_ids"
    ], "The owned fixture did not independently attribute its copied source bytes"
    assert original_before["analysis"]["transitions"] != original_after["analysis"][
        "transitions"
    ], "Distinct original claim attribution disappeared"
    assert Files(fixture.root) == original_bytes, "Equal-state comparison wrote retained evidence"


def test_UnassessedBothSidesRemainUnknownWithoutInventingRisk(tmp_path):
    """No-assessment selections keep UNKNOWN routes and exact owner output on each side."""

    fixture = Fixture.Create(tmp_path / "workspace")
    original_bytes = Files(fixture.root)
    original_status, original = Run(OriginalArguments(fixture, ()))
    status, result = Run(PairArguments(fixture, (), ()))
    assert original_status == status == 0, "Explicit unassessed comparison was refused"
    assert result["before"] == result["after"] == original, "UNKNOWN source facts were rewritten"
    assert result["observed_state_change"] is False and result["state_changes"] == [], (
        "Unassessed repeated selection acquired a state change"
    )

    for side in ("before", "after"):
        analysis = result[side]["analysis"]
        assert len(analysis["search"]["paths"]) == 3 and all(
            path["state"] == "UNKNOWN" for path in analysis["search"]["paths"]
        ), "UNKNOWN became absent, confirmed or blocked"
        assert all(transition["state"] == "UNKNOWN" and not transition["claims"]
            for transition in analysis["transitions"]), "A claim was fabricated for missing support"

    assert Files(fixture.root) == original_bytes, "Unassessed comparison changed owner state"


@pytest.mark.parametrize("flag,search_complete,cuts_complete", [
    ("--max-paths", False, True), ("--max-cut-work", True, False),
])
def test_SearchAndCutTruncationStayIndependentOriginalFacts(
    tmp_path, flag, search_complete, cuts_complete,
):
    """A paired presentation cannot convert either bounded analysis into a complete risk verdict."""

    fixture = Fixture.Create(tmp_path / "workspace")
    before, after = fixture.Phase("confirmed"), fixture.Phase("remediation")
    original_bytes = Files(fixture.root)
    before_status, original_before = Run(Value(OriginalArguments(fixture, before), flag, "1"))
    after_status, original_after = Run(Value(OriginalArguments(fixture, after), flag, "1"))
    status, result = Run(Value(PairArguments(fixture, before, after), flag, "1"))
    assert before_status == after_status == status == 0, "Honest bounded analysis became failure"
    assert result["before"] == original_before and result["after"] == original_after, (
        "Comparison normalized or combined separate completeness indicators"
    )

    for side in ("before", "after"):
        analysis = result[side]["analysis"]
        assert analysis["search"]["complete"] is search_complete and (
            analysis["cuts"]["complete"] is cuts_complete
        ), "Returned-path and independent cut completeness were confused"

    assert Files(fixture.root) == original_bytes, "Bounded comparison wrote original stores"


@pytest.mark.parametrize("after_phase,focus", [
    ("likely", "portal-identity"), ("remediation", "source-portal"),
    ("potential", "portal-identity"),
])
def test_OriginalStateChangesOutsideFocusRefuseWithoutSuccessfulPartialPair(
    tmp_path, after_phase, focus,
):
    """Original analyses outside the one-focus profile cannot become partial comparison success."""

    fixture = Fixture.Create(tmp_path / "workspace")
    before, after = fixture.Phase("confirmed"), fixture.Phase(after_phase)
    original_bytes = Files(fixture.root)
    before_status, _ = Run(OriginalArguments(fixture, before))
    after_status, _ = Run(OriginalArguments(fixture, after))
    status, result = Run(PairArguments(fixture, before, after, focus=focus))
    assert before_status == after_status == 0, "The independent original phases were invalid"
    assert status == 4 and result["status"] != "completed" and result["failure"], (
        "An unrelated or multiple state change escaped the selected-focus comparison boundary"
    )
    assert result["before"] is None and result["after"] is None, (
        "A refused pair exposed a successful first-only comparison"
    )
    assert Files(fixture.root) == original_bytes, "Refused comparison repaired original state"
