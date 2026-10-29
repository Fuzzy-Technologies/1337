# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explain selected candidate-path participation, structural cuts and declared presentation
groups.
"""

from __future__ import annotations

import hashlib
import re
from collections import deque
from dataclasses import dataclass
from typing import Literal

from fuzzy1337.model import CanonicalModelJson, ModelState
from fuzzy1337.reachability import (
    ReachabilityLimits,
    ReachabilityProjection,
    ReachabilitySearch,
    ReachabilityState,
    ReachabilityTransition,
    SearchReachabilityPaths,
)

PATH_ANALYSIS_PROFILE_VERSION = 1
_GROUP_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_OBJECT_REF = re.compile(r"object:[0-9a-f]{64}\Z")

__all__ = [
    "PATH_ANALYSIS_PROFILE_VERSION", "PathAnalysisLimits", "PathSemanticGroup",
    "AnalyzeReachabilityPaths",
]


@dataclass(frozen=True, slots=True)
class PathAnalysisLimits:
    """Bound successor examinations shared by the witness and every independent removal check."""

    max_cut_work: int = 100000

    def __post_init__(self) -> None:
        """Refuse coercion, booleans and counts outside the inclusive 1..2000000 budget."""

        if type(self.max_cut_work) is not int or not 1 <= self.max_cut_work <= 2000000:
            raise ValueError("path analysis cut work requires an exact supported positive integer")


@dataclass(frozen=True, slots=True)
class PathSemanticGroup:
    """Declare presentation membership explicitly without asserting shared reachability or
    identity.
    """

    group_key: str
    member_references: tuple[str, ...]

    def __post_init__(self) -> None:
        """Validate bounded unique canonical members before any model lookup or grouping."""

        if not isinstance(self.group_key, str) or not _GROUP_KEY.fullmatch(self.group_key):
            raise ValueError("path analysis group keys require bounded ASCII identifiers")

        if type(self.member_references) is not tuple or not 1 <= len(self.member_references) <= 512:
            raise ValueError("path analysis group membership requires a bounded nonempty tuple")

        if any(not isinstance(item, str) or not _OBJECT_REF.fullmatch(item)
               for item in self.member_references):
            raise ValueError("path analysis group members require canonical object references")

        if len(set(self.member_references)) != len(self.member_references):
            raise ValueError("path analysis group members must be unique")


@dataclass(frozen=True, slots=True)
class PathParticipation:
    """Internal output counting one element across exact returned paths, separately by hop
    summary.
    """

    kind: Literal["node", "relation"]
    reference: str
    path_references: tuple[str, ...]
    state_counts: tuple[tuple[ReachabilityState, int], ...]


@dataclass(frozen=True, slots=True)
class PathRemovalLeverage:
    """Internal structural scenario over returned non-BLOCKED candidates, never remediation
    efficacy.
    """

    kind: Literal["node", "relation"]
    reference: str
    removed_path_references: tuple[str, ...]
    remaining_candidate_count: int


@dataclass(frozen=True, slots=True)
class PathElement:
    """Internal exact modeled element selected for a single structural removal check."""

    kind: Literal["node", "relation"]
    reference: str


@dataclass(frozen=True, slots=True)
class PathWitness:
    """Internal selected nonblocked graph route; supplied UNKNOWN transitions remain possible."""

    nodes: tuple[str, ...]
    relation_references: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PathChokePoints:
    """Internal independently bounded cut result, separate from simple-path enumeration
    completeness.
    """

    candidate_route_exists: bool | None
    witness: PathWitness | None
    verified: tuple[PathElement, ...]
    alternatives_exist: tuple[PathElement, ...]
    unverified: tuple[PathElement, ...]
    complete: bool
    examined_successors: int
    reasons: tuple[str, ...]
    claim_scope: str = "selected-nonblocked-transition-subgraph-only"


@dataclass(frozen=True, slots=True)
class PathPresentationGroup:
    """Internal explicit group or singleton retaining every original object reference."""

    group_reference: str
    group_key: str | None
    member_references: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PathTransitionBundle:
    """Internal presentation bundle retaining original directed transitions without composed
    states.
    """

    source_group_reference: str
    target_group_reference: str
    transitions: tuple[ReachabilityTransition, ...]


@dataclass(frozen=True, slots=True)
class PathAnalysis:
    """Internal frozen explanation with exact search, separate cut bounds and no execution
    authority.
    """

    analysis_reference: str
    search: ReachabilitySearch
    cut_limits: PathAnalysisLimits
    participation: tuple[PathParticipation, ...]
    removal_leverage: tuple[PathRemovalLeverage, ...]
    nonblocked_returned_candidates: int
    leverage_scope: str
    choke_points: PathChokePoints
    groups: tuple[PathPresentationGroup, ...]
    transition_bundles: tuple[PathTransitionBundle, ...]
    semantics: str = "structural-selected-candidate-analysis"


def Identity(namespace: str, value: object) -> str:
    """Internal deterministic identity using the owning canonical JSON serializer.

    Args:
        namespace: First-party result namespace.
        value: Bounded canonical identity fields, never original raw evidence.

    Returns:
        Namespace-prefixed lowercase content digest.
    """

    return namespace + ":" + hashlib.sha256(CanonicalModelJson(value)).hexdigest()


def Participation(search: ReachabilitySearch) -> tuple[
    tuple[PathParticipation, ...], tuple[PathRemovalLeverage, ...], int,
]:
    """Internal single pass retaining exact participation and structural single-removal samples.

    Args:
        search: Exact freshly produced bounded public search output.

    Returns:
        Canonical participation, leverage ordered by descending affected count, and denominator.
    """

    members: dict[tuple[Literal["node", "relation"], str], list[tuple[str, ReachabilityState]]] = {}
    nonblocked = sum(path.state is not ReachabilityState.BLOCKED for path in search.paths)

    for path in search.paths:
        elements: list[tuple[Literal["node", "relation"], str]] = [
            ("node", node) for node in path.nodes
        ]
        elements.extend(("relation", hop.relation_reference) for hop in path.hops)

        for element in elements:
            members.setdefault(element, []).append((path.path_reference, path.state))

    participation = []
    leverage = []

    for (kind, reference), paths in sorted(members.items()):
        path_refs = tuple(sorted(path for path, _ in paths))
        counts = tuple((state, sum(label is state for _, label in paths))
                       for state in ReachabilityState)
        participation.append(PathParticipation(kind, reference, path_refs, counts))
        removed = tuple(sorted(path for path, state in paths
                               if state is not ReachabilityState.BLOCKED))

        if removed and not (kind == "node" and reference in (
            search.source_reference, search.target_reference,
        )):
            leverage.append(PathRemovalLeverage(kind, reference, removed,
                                                 nonblocked - len(removed)))

    leverage.sort(key=lambda item: (-len(item.removed_path_references), item.kind, item.reference))

    return tuple(participation), tuple(leverage), nonblocked


def Walk(
    outgoing: dict[str, tuple[ReachabilityTransition, ...]], source: str, target: str,
    budget: int, removed: PathElement | None = None,
) -> tuple[bool | None, PathWitness | None, int]:
    """Internal bounded breadth-first reachability check without simple-path enumeration.

    Args:
        outgoing: Reference-ordered selected transitions excluding admitted BLOCKED hops.
        source: Exact selected source object reference.
        target: Exact selected distinct destination object reference.
        budget: Remaining shared successor-work budget, including zero.
        removed: Optional exact node or relation whose structural deletion is simulated.

    Returns:
        Reachability or unknown on exhaustion, an original-reference witness, and charged work.
    """

    parents: dict[str, tuple[str, str] | None] = {source: None}
    queue = deque([source])
    work = 0

    while queue:
        node = queue.popleft()

        for edge in outgoing.get(node, ()):
            if work == budget:
                return None, None, work

            work += 1

            if removed is not None and (
                removed.kind == "relation" and edge.relation_reference == removed.reference
                or removed.kind == "node" and edge.target_reference == removed.reference
            ):
                continue

            destination = edge.target_reference

            if destination in parents:
                continue

            parents[destination] = (node, edge.relation_reference)

            if destination == target:
                nodes = [target]
                relations = []
                current = target

                while (parent := parents[current]) is not None:
                    current, relation = parent
                    nodes.append(current)
                    relations.append(relation)

                return True, PathWitness(tuple(reversed(nodes)), tuple(reversed(relations))), work

            queue.append(destination)

    return False, None, work


def ChokePoints(search: ReachabilitySearch, limits: PathAnalysisLimits) -> PathChokePoints:
    """Internal independent removal checks over one witness, retaining explicit unfinished work.

    Args:
        search: Exact public search output, including its validated projection.
        limits: Exact separate budget shared across witness and removal graph walks.

    Returns:
        Verified cuts, witnessed alternatives and unverified candidates with distinct completeness.
    """

    collected: dict[str, list[ReachabilityTransition]] = {}

    for edge in search.projection.transitions:
        if edge.state is not ReachabilityState.BLOCKED:
            collected.setdefault(edge.source_reference, []).append(edge)

    outgoing = {node: tuple(sorted(edges, key=lambda edge: edge.relation_reference))
                for node, edges in collected.items()}
    exists, witness, work = Walk(outgoing, search.source_reference,
                                 search.target_reference, limits.max_cut_work)

    if witness is None:
        return PathChokePoints(exists, None, (), (), (), exists is not None, work,
                               ("cut-work-limit",) if exists is None else ())

    candidates = [PathElement("node", node) for node in witness.nodes[1:-1]]
    candidates.extend(PathElement("relation", relation) for relation in witness.relation_references)
    candidates.sort(key=lambda item: (item.kind, item.reference))
    verified = []
    alternatives = []
    unverified: tuple[PathElement, ...] = ()

    for index, candidate in enumerate(candidates):
        remains, _, charged = Walk(outgoing, search.source_reference, search.target_reference,
                                    limits.max_cut_work - work, candidate)
        work += charged

        if remains is None:
            unverified = tuple(candidates[index:])
            break

        if remains:
            alternatives.append(candidate)

        else:
            verified.append(candidate)

    return PathChokePoints(True, witness, tuple(verified), tuple(alternatives), unverified,
                           not unverified, work, ("cut-work-limit",) if unverified else ())


def Presentation(
    projection: ReachabilityProjection, declarations: tuple[PathSemanticGroup, ...],
) -> tuple[tuple[PathPresentationGroup, ...], tuple[PathTransitionBundle, ...]]:
    """Internal lossless explicit grouping that never constructs traversable synthetic edges.

    Args:
        projection: Exact validated original directed graph with retained hop states and proofs.
        declarations: Bounded distinct explicit memberships over eligible basis object references.

    Returns:
        Canonical groups and bundles of original transitions, including internal group edges.

    Raises:
        ValueError: Membership is overlapping, foreign, malformed or duplicated.
    """

    if type(declarations) is not tuple or len(declarations) > 512:
        raise ValueError("path analysis declarations require a bounded exact tuple")

    eligible = set(projection.nodes)
    membership: dict[str, str] = {}
    keys = set()
    groups = []

    for declaration in declarations:
        if not isinstance(declaration, PathSemanticGroup):
            raise ValueError("path analysis declarations require typed explicit semantic groups")

        PathSemanticGroup.__post_init__(declaration)

        if declaration.group_key in keys or any(
            member not in eligible or member in membership
            for member in declaration.member_references
        ):
            raise ValueError("path analysis group keys and eligible memberships must be disjoint")

        keys.add(declaration.group_key)
        members = tuple(sorted(declaration.member_references))
        reference = Identity("path-group", {"group_key": declaration.group_key, "members": members})
        groups.append(PathPresentationGroup(reference, declaration.group_key, members))
        membership.update((member, reference) for member in members)

    for node in projection.nodes:
        if node not in membership:
            reference = Identity("path-group", {"group_key": None, "members": (node,)})
            groups.append(PathPresentationGroup(reference, None, (node,)))
            membership[node] = reference

    bundled: dict[tuple[str, str], list[ReachabilityTransition]] = {}

    for edge in projection.transitions:
        pair = (membership[edge.source_reference], membership[edge.target_reference])
        bundled.setdefault(pair, []).append(edge)

    bundles = tuple(PathTransitionBundle(source, target,
        tuple(sorted(edges, key=lambda edge: edge.relation_reference)))
        for (source, target), edges in sorted(bundled.items()))
    groups.sort(key=lambda item: item.group_reference)

    return tuple(groups), bundles


def AnalyzeReachabilityPaths(
    projection: ReachabilityProjection, model: ModelState, source_reference: str,
    target_reference: str, *, search_limits: ReachabilityLimits = ReachabilityLimits(),
    cut_limits: PathAnalysisLimits = PathAnalysisLimits(),
    semantic_groups: tuple[PathSemanticGroup, ...] = (),
) -> PathAnalysis:
    """Explain bounded candidates and independent selected-graph cuts without I/O or authority.

    Args:
        projection: Exact frozen output from the existing verified reachability producer.
        model: Exact immutable canonical basis; the search owner rechecks the complete model pin.
        source_reference: Existing eligible original source object, distinct from the target.
        target_reference: Existing eligible original destination object.
        search_limits: Existing bounded simple-path enumeration limits; defaults are unchanged.
        cut_limits: Separate shared graph-walk successor budget, default 100000, maximum 2000000.
        semantic_groups: Explicit disjoint presentation memberships; other nodes stay singletons.

    Returns:
        Frozen original paths, state-specific participation, sample removal leverage, independently
        bounded structural cuts, and a lossless presentation view that must never be traversed.

    Raises:
        ValueError: The owner refuses the basis/projection/query or local bounds/groups are invalid.

    All conclusions apply only to the explicit selected subgraph and supplied hop attestations.
    Counts never establish exploitability, risk reduction, control efficacy or execution permission.
    """

    if not isinstance(cut_limits, PathAnalysisLimits) or not isinstance(
        search_limits, ReachabilityLimits,
    ):
        raise ValueError("path analysis requires exact typed search and cut limits")

    PathAnalysisLimits.__post_init__(cut_limits)
    ReachabilityLimits.__post_init__(search_limits)

    if type(semantic_groups) is not tuple or len(semantic_groups) > 512:
        raise ValueError("path analysis declarations require a bounded exact tuple")

    for declaration in semantic_groups:
        if not isinstance(declaration, PathSemanticGroup):
            raise ValueError("path analysis declarations require typed explicit semantic groups")

        PathSemanticGroup.__post_init__(declaration)

    search = SearchReachabilityPaths(projection, model, source_reference, target_reference,
                                     limits=search_limits)
    groups, bundles = Presentation(projection, semantic_groups)
    participation, leverage, nonblocked = Participation(search)
    cuts = ChokePoints(search, cut_limits)
    identity = Identity("path-analysis", {"profile_version": PATH_ANALYSIS_PROFILE_VERSION,
        "query_reference": search.query_reference, "cut_limits": cut_limits,
        "groups": [{"group_reference": group.group_reference,
                    "member_references": group.member_references} for group in groups]})

    return PathAnalysis(identity, search, cut_limits, participation, leverage, nonblocked,
        "complete-returned-candidates" if search.complete else "truncated-returned-candidates",
        cuts, groups, bundles)
