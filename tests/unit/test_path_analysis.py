# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independently verify pure bounded structural graph walks and explicit membership contracts."""

from __future__ import annotations

import pytest

from fuzzy1337.path_analysis import PathAnalysisLimits, PathElement, PathSemanticGroup, Walk
from fuzzy1337.reachability import ReachabilityState, ReachabilityTransition


def Node(index):
    """Use bounded canonical-shaped node tokens for isolated Internal algorithm tests."""

    return "object:" + f"{index:064x}"


def Edge(index, source, target):
    """Construct a typed Internal transition without claiming owner verification."""

    return ReachabilityTransition("relation:" + f"{index:064x}", Node(source), Node(target),
                                  ReachabilityState.UNKNOWN, (), ("unassessed",))


def IndependentExists(edges, source, target, removed):
    """Enumerate tiny simple routes independently by recursive-set expansion for a test oracle."""

    frontier = {source}
    seen = set()

    while frontier:
        next_frontier = set()

        for node in frontier:
            if node == target:
                return True

            for edge in edges:
                excluded = removed is not None and (
                    removed.kind == "node" and edge.target_reference == removed.reference
                    or removed.kind == "relation" and edge.relation_reference == removed.reference
                )

                if not excluded and edge.source_reference == node:
                    next_frontier.add(edge.target_reference)

        seen.update(frontier)
        frontier = next_frontier - seen

    return False


@pytest.mark.parametrize("value", [True, False, 0, -1, 2000001, 1.0, "1", None, 10 ** 100])
def test_CutWorkRejectsCoercionAndUnsupportedBounds(value):
    """Resource allocation never begins with coerced or unsupported successor counts."""

    with pytest.raises(ValueError, match="exact supported"):
        PathAnalysisLimits(value)


@pytest.mark.parametrize("value", [1, 100000, 2000000])
def test_CutWorkPreservesExactInclusiveBounds(value):
    """The default and both inclusive integer endpoints preserve exact caller intent."""

    assert PathAnalysisLimits(value).max_cut_work == value, "Cut budget was rounded or replaced"


@pytest.mark.parametrize("key,members", [
    ("", (Node(1),)), ("a\nb", (Node(1),)), ("x" * 129, (Node(1),)),
    (None, (Node(1),)), ("group", []), ("group", ()),
    ("group", tuple(Node(index) for index in range(513))),
    ("group", (Node(1), Node(1))), ("group", ("object:wrong",)),
    ("group", ("relation:" + "1" * 64,)), ("group", (True,)),
])
def test_SemanticMembershipRejectsMalformedOrUnboundedDeclarations(key, members):
    """No empty, extended, mutable, duplicate or foreign-namespace declaration is admitted."""

    with pytest.raises(ValueError):
        PathSemanticGroup(key, members)


def test_SemanticMembershipSupportsExactBoundedExplicitReferences():
    """A declared group retains the caller's original references until canonical presentation."""

    members = tuple(Node(index) for index in range(512))
    declaration = PathSemanticGroup("caller:declared-members", members)
    assert declaration.member_references == members, "Explicit group membership was inferred"


@pytest.mark.parametrize("mask", range(64))
def test_DirectedWalkAndEveryRemovalMatchIndependentSmallGraphOracle(mask):
    """Cycles, self-loops, ties, alternate paths and absent routes match independent
    reachability.
    """

    possibilities = ((1, 2), (1, 3), (2, 3), (3, 2), (2, 2), (3, 4))
    edges = tuple(Edge(index + 1, source, target)
                  for index, (source, target) in enumerate(possibilities) if mask & (1 << index))
    outgoing = {Node(source): tuple(edge for edge in edges if edge.source_reference == Node(source))
                for source in range(1, 5)}
    removals = [None, PathElement("node", Node(2)), PathElement("node", Node(3))]
    removals.extend(PathElement("relation", edge.relation_reference) for edge in edges)

    for removal in removals:
        exists, witness, work = Walk(outgoing, Node(1), Node(4), 100, removal)
        expected = IndependentExists(edges, Node(1), Node(4), removal)
        assert exists is expected, "Directed structural removal differs from independent oracle"
        assert work <= len(edges), "A graph walk reexamined edges after visiting their source"
        assert (witness is not None) is expected, "Existence and original witness diverged"

        if witness is not None:
            assert witness.nodes[0] == Node(1) and witness.nodes[-1] == Node(4), (
                "Walk witness lost the exact source or destination"
            )
            assert len(set(witness.nodes)) == len(witness.nodes), "BFS witness contains a cycle"
            assert len(witness.relation_references) + 1 == len(witness.nodes), (
                "Witness relation and object sequences lost their pairing"
            )


def test_ParallelRelationsKeepTheirDistinctRemovalIdentity():
    """Removing one original edge cannot remove an independently selected parallel relation."""

    first, second = Edge(1, 1, 2), Edge(2, 1, 2)
    for edge in (first, second):
        exists, witness, work = Walk({Node(1): (first, second)}, Node(1), Node(2), 2,
                                     PathElement("relation", edge.relation_reference))
        assert exists and witness is not None, "Single relation removal collapsed parallel edges"
        assert edge.relation_reference not in witness.relation_references, "Removed edge survived"
        assert work <= 2, "Parallel-edge walk exceeded its exact budget"


def test_ExactFinalSuccessorBudgetIsCompleteAndEarlierExhaustionIsUnknown():
    """An exact terminal examination proves a route; an unexamined successor cannot prove
    absence.
    """

    edges = (Edge(1, 1, 1), Edge(2, 1, 2))
    outgoing = {Node(1): edges}
    exhausted = Walk(outgoing, Node(1), Node(2), 1)
    completed = Walk(outgoing, Node(1), Node(2), 2)
    assert exhausted == (None, None, 1), "Unexamined graph work was reported as no route"
    assert completed[0] is True and completed[2] == 2, "Exact final budget became incomplete"
    assert Walk({}, Node(1), Node(2), 0) == (False, None, 0), "An empty graph consumed work"


def test_RemovedOnlySuccessorCanProveNoRouteAtTheExactBudget():
    """Charged excluded transitions consume work without fabricating pending candidates."""

    edge = Edge(1, 1, 2)
    result = Walk({Node(1): (edge,)}, Node(1), Node(2), 1,
                  PathElement("relation", edge.relation_reference))
    assert result == (False, None, 1), "Final excluded edge hid complete graph exhaustion"
