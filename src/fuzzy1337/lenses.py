# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental read-only workflow descriptors and reference views over shared model state."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TypedDict, TypeVar, cast

from fuzzy1337.adapters.contracts import JsonValue, RequireIdentifier, RequireText
from fuzzy1337.model import (
    CanonicalModelJson,
    ModelAttributes,
    ModelSequence,
    ModelState,
    ObjectKind,
    RelationKind,
    SecurityObject,
)
from fuzzy1337.workspace import RequireWorkspaceInteger, RequireWorkspaceText, WorkspaceFields

LENS_SCHEMA_VERSION = 1
__all__ = [
    "LENS_SCHEMA_VERSION", "LENS_CATALOG", "LensQuery", "LensAction",
    "LensPresentation", "LensDescriptor", "LensView", "ResolveLens",
]
_KIND = TypeVar("_KIND", ObjectKind, RelationKind)
_OVERLAYS = ("evidence-references", "source-provenance", "observation-history")


def LensKinds(value: object, expected: type[_KIND], field_name: str) -> tuple[_KIND, ...]:
    """Freeze unique typed kinds without coercing unknown values at the runtime boundary.

    Args:
        value: Explicit list or tuple of already typed enum members.
        expected: First-party object or relation kind enum.
        field_name: Collection label used in validation errors.

    Returns:
        Validated immutable collection in declaration order.

    Raises:
        ValueError: The input has invalid types, duplicate members, or no sequence boundary.
    """

    items = ModelSequence(value, field_name)

    if any(not isinstance(item, expected) for item in items) or len(set(items)) != len(items):
        raise ValueError(f"{field_name} must contain unique {expected.__name__} values")

    return cast(tuple[_KIND, ...], items)


def DecodeLensKinds(value: object, expected: type[_KIND], field_name: str) -> tuple[_KIND, ...]:
    """Decode textual enum values and reuse strict typed uniqueness validation.

    Args:
        value: Explicit JSON collection of textual enum values.
        expected: First-party object or relation kind enum.
        field_name: Collection label used in validation errors.

    Returns:
        Validated immutable collection of typed kinds.

    Raises:
        ValueError: The input has unsupported kinds, malformed text, or duplicate members.
    """

    return LensKinds(tuple(
        expected(RequireWorkspaceText(item, field_name))
        for item in ModelSequence(value, field_name)
    ), expected, field_name)


def LensNames(value: object, field_name: str) -> tuple[str, ...]:
    """Freeze explicit identifier lists instead of accepting text or arbitrary iterables.

    Args:
        value: Explicit list or tuple of machine-readable names.
        field_name: Collection label used in validation errors.

    Returns:
        Validated immutable names in declaration order.

    Raises:
        ValueError: The collection or any identifier is malformed or duplicated.
    """

    names = ModelSequence(value, field_name)

    for name in names:
        RequireIdentifier(name, field_name)  # type: ignore[arg-type]

    if len(set(names)) != len(names):
        raise ValueError(f"{field_name} must contain unique identifiers")

    return tuple(str(name) for name in names)


@dataclass(frozen=True, slots=True)
class LensQuery:
    """Describe offline object filters and induced relations without executable query syntax."""

    object_kinds: tuple[ObjectKind, ...] = ()
    relation_kinds: tuple[RelationKind, ...] = ()
    attributes_match: Mapping[str, object] = field(default_factory=dict)
    key_contains: str = ""
    require_provenance: bool = False
    include_observations: bool = True

    def __post_init__(self) -> None:
        """Validate typed filters and freeze exact JSON attribute matches."""

        object.__setattr__(self, "object_kinds", LensKinds(
            self.object_kinds, ObjectKind, "object_kinds",
        ))
        object.__setattr__(self, "relation_kinds", LensKinds(
            self.relation_kinds, RelationKind, "relation_kinds",
        ))
        object.__setattr__(self, "attributes_match", ModelAttributes(self.attributes_match))

        if not isinstance(self.key_contains, str) or len(self.key_contains) > 4096:
            raise ValueError("key_contains must be bounded text")

        CanonicalModelJson(self.key_contains)

        if type(self.require_provenance) is not bool or type(self.include_observations) is not bool:
            raise ValueError("query flags must be booleans")

    def Matches(self, item: SecurityObject) -> bool:
        """Evaluate explicit filters offline without changing an object's interpretation.

        Args:
            item: Canonical object from the authoritative model snapshot.

        Returns:
            True when every specified object filter matches.
        """

        return (
            (not self.object_kinds or item.identity.kind in self.object_kinds)
            and self.key_contains.casefold() in item.identity.key.casefold()
            and (not self.require_provenance or bool(item.provenance))
            and all(
                key in item.attributes
                and CanonicalModelJson(item.attributes[key]) == CanonicalModelJson(value)
                for key, value in self.attributes_match.items()
            )
        )

    def ToDict(self) -> dict[str, object]:
        """Render the exact query fields for machine-readable consumers.

        Returns:
            Strict JSON-compatible query metadata.
        """

        return {
            "object_kinds": [kind.value for kind in self.object_kinds],
            "relation_kinds": [kind.value for kind in self.relation_kinds],
            "attributes_match": JsonValue(self.attributes_match),
            "key_contains": self.key_contains,
            "require_provenance": self.require_provenance,
            "include_observations": self.include_observations,
        }

    @classmethod
    def FromDict(cls, value: object) -> LensQuery:
        """Decode an exact query boundary and reject unknown enum values or fields.

        Args:
            value: Decoded JSON query object.

        Returns:
            Validated immutable offline query.

        Raises:
            ValueError: Fields, types, enum values, or attribute matches are invalid.
        """

        record = WorkspaceFields(value, {
            "object_kinds", "relation_kinds", "attributes_match", "key_contains",
            "require_provenance", "include_observations",
        }, "lens query")

        return cls(
            DecodeLensKinds(record["object_kinds"], ObjectKind, "object_kinds"),
            DecodeLensKinds(record["relation_kinds"], RelationKind, "relation_kinds"),
            record["attributes_match"],  # type: ignore[arg-type]
            record["key_contains"],  # type: ignore[arg-type]
            record["require_provenance"],  # type: ignore[arg-type]
            record["include_observations"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class LensAction:
    """Advertise a contextual suggestion; metadata is neither execution nor authorization."""

    identifier: str
    summary: str
    object_kinds: tuple[ObjectKind, ...] = ()

    def __post_init__(self) -> None:
        """Validate an immutable suggestion without resolving handlers or providers."""

        RequireIdentifier(self.identifier, "action identifier")
        RequireText(self.summary, "action summary")
        CanonicalModelJson(self.summary)
        object.__setattr__(self, "object_kinds", LensKinds(
            self.object_kinds, ObjectKind, "action object_kinds",
        ))


@dataclass(frozen=True, slots=True)
class LensPresentation:
    """Provide client-neutral columns, grouping, and ordering hints over canonical records."""

    columns: tuple[str, ...] = ("kind", "key")
    group_by: str = "kind"
    observation_order: str = "reference"

    def __post_init__(self) -> None:
        """Reject unsupported grouping/order semantics while preserving column hints."""

        object.__setattr__(self, "columns", LensNames(self.columns, "columns"))
        RequireIdentifier(self.group_by, "group_by")
        RequireIdentifier(self.observation_order, "observation_order")

        if self.group_by not in {"kind", "source", "none"}:
            raise ValueError("group_by must be kind, source, or none")

        if self.observation_order not in {"reference", "observed-at"}:
            raise ValueError("observation_order must be reference or observed-at")


class LensView(TypedDict):
    """Carry a detached reference projection without becoming a writable model snapshot."""

    schema_version: int
    lens: str
    workspace_id: str
    revision: int
    query: dict[str, object]
    object_references: list[str]
    relation_references: list[str]
    observation_references: list[str]


@dataclass(frozen=True, slots=True)
class LensDescriptor:
    """Define one view preset independently from scope, policy, impact, and execution profiles."""

    identifier: str
    title: str
    summary: str
    preferred_object_kinds: tuple[ObjectKind, ...]
    preferred_relation_kinds: tuple[RelationKind, ...]
    default_query: LensQuery
    contextual_actions: tuple[LensAction, ...] = ()
    preferred_capabilities: tuple[str, ...] = ()
    overlays: tuple[str, ...] = ()
    attribute_mappings: Mapping[str, str] = field(default_factory=dict)
    presentation: LensPresentation = field(default_factory=LensPresentation)

    def __post_init__(self) -> None:
        """Freeze descriptor data and reject unsupported or ambiguous metadata."""

        RequireIdentifier(self.identifier, "lens identifier")
        RequireText(self.title, "lens title")
        RequireText(self.summary, "lens summary")
        CanonicalModelJson((self.title, self.summary))
        object.__setattr__(self, "preferred_object_kinds", LensKinds(
            self.preferred_object_kinds, ObjectKind, "preferred_object_kinds",
        ))
        object.__setattr__(self, "preferred_relation_kinds", LensKinds(
            self.preferred_relation_kinds, RelationKind, "preferred_relation_kinds",
        ))

        if not isinstance(self.default_query, LensQuery) or not isinstance(
            self.presentation, LensPresentation,
        ):
            raise ValueError("descriptor query and presentation must be typed contracts")

        actions = ModelSequence(self.contextual_actions, "contextual_actions")

        if any(not isinstance(action, LensAction) for action in actions):
            raise ValueError("contextual_actions must contain LensAction values")

        typed_actions = tuple(action for action in actions if isinstance(action, LensAction))

        if len({action.identifier for action in typed_actions}) != len(typed_actions):
            raise ValueError("contextual_actions must have unique identifiers")

        object.__setattr__(self, "contextual_actions", typed_actions)
        object.__setattr__(self, "preferred_capabilities", LensNames(
            self.preferred_capabilities, "preferred_capabilities",
        ))
        overlays = LensNames(self.overlays, "overlays")

        if set(overlays) - set(_OVERLAYS):
            raise ValueError("unsupported lens overlay")

        object.__setattr__(self, "overlays", overlays)
        mappings = ModelAttributes(self.attribute_mappings)

        for label, attribute in mappings.items():
            RequireIdentifier(label, "mapping label")
            RequireIdentifier(attribute, "mapping attribute")  # type: ignore[arg-type]

        object.__setattr__(self, "attribute_mappings", mappings)

    def ToDict(self) -> dict[str, object]:
        """Render schema-versioned metadata without runtime handlers or policy fields.

        Returns:
            Detached JSON descriptor with declarative presentation and query metadata.
        """

        return {
            "schema_version": LENS_SCHEMA_VERSION,
            "identifier": self.identifier,
            "title": self.title,
            "summary": self.summary,
            "preferred_object_kinds": [kind.value for kind in self.preferred_object_kinds],
            "preferred_relation_kinds": [kind.value for kind in self.preferred_relation_kinds],
            "default_query": self.default_query.ToDict(),
            "contextual_actions": JsonValue(self.contextual_actions),
            "preferred_capabilities": list(self.preferred_capabilities),
            "overlays": list(self.overlays),
            "attribute_mappings": JsonValue(self.attribute_mappings),
            "presentation": JsonValue(self.presentation),
        }

    @classmethod
    def FromDict(cls, value: object) -> LensDescriptor:
        """Decode published descriptor fields without importing plugins or executing expressions.

        Args:
            value: Decoded schema-versioned JSON descriptor.

        Returns:
            Validated immutable descriptor.

        Raises:
            ValueError: The version, exact fields, enum values, or typed metadata are invalid.
        """

        record = WorkspaceFields(value, {
            "schema_version", "identifier", "title", "summary", "preferred_object_kinds",
            "preferred_relation_kinds", "default_query", "contextual_actions",
            "preferred_capabilities", "overlays", "attribute_mappings", "presentation",
        }, "lens descriptor")

        version = RequireWorkspaceInteger(record["schema_version"], "schema_version")

        if version != LENS_SCHEMA_VERSION:
            raise ValueError("unsupported lens schema version")

        actions = []

        for action in ModelSequence(record["contextual_actions"], "contextual_actions"):
            fields = WorkspaceFields(action, {"identifier", "summary", "object_kinds"}, "action")
            actions.append(LensAction(
                fields["identifier"], fields["summary"],  # type: ignore[arg-type]
                DecodeLensKinds(fields["object_kinds"], ObjectKind, "action object_kinds"),
            ))

        presentation = WorkspaceFields(
            record["presentation"], {"columns", "group_by", "observation_order"}, "presentation",
        )

        return cls(
            record["identifier"], record["title"], record["summary"],  # type: ignore[arg-type]
            DecodeLensKinds(record["preferred_object_kinds"], ObjectKind, "preferred_object_kinds"),
            DecodeLensKinds(
                record["preferred_relation_kinds"], RelationKind, "preferred_relation_kinds",
            ),
            LensQuery.FromDict(record["default_query"]), tuple(actions),
            record["preferred_capabilities"], record["overlays"],  # type: ignore[arg-type]
            record["attribute_mappings"],  # type: ignore[arg-type]
            LensPresentation(
                presentation["columns"], presentation["group_by"],  # type: ignore[arg-type]
                presentation["observation_order"],  # type: ignore[arg-type]
            ),
        )

    def Project(self, state: ModelState, query: LensQuery | None = None) -> LensView:
        """Return a deterministic reference-only view of one authoritative snapshot.

        Args:
            state: Validated immutable canonical model; no I/O or updates occur.
            query: Explicit replacement query, or None to use the descriptor default.

        Returns:
            Schema-versioned workspace/revision identity and canonical reference arrays.

        Raises:
            ValueError: The snapshot or override is not the typed contract.
        """

        if not isinstance(state, ModelState) or (
            query is not None and not isinstance(query, LensQuery)
        ):
            raise ValueError("Project requires a ModelState and optional LensQuery")

        selected_query = self.default_query if query is None else query
        objects = tuple(item for item in state.objects if selected_query.Matches(item))
        object_references = {item.Reference() for item in objects}
        relations = tuple(
            item for item in state.relations
            if (not selected_query.relation_kinds or item.kind in selected_query.relation_kinds)
            and {item.source_reference, item.target_reference} <= object_references
        )
        subjects = object_references | {item.Reference() for item in relations}
        observations = tuple(
            item for item in state.observations
            if selected_query.include_observations and item.subject_reference in subjects
        )

        if self.presentation.observation_order == "observed-at":
            observations = tuple(sorted(
                observations, key=lambda item: (item.provenance.observed_at, item.Reference()),
            ))

        return {
            "schema_version": LENS_SCHEMA_VERSION,
            "lens": self.identifier,
            "workspace_id": state.workspace_id,
            "revision": state.revision,
            "query": selected_query.ToDict(),
            "object_references": [item.Reference() for item in objects],
            "relation_references": [item.Reference() for item in relations],
            "observation_references": [item.Reference() for item in observations],
        }


_SURFACE_OBJECTS = (
    ObjectKind.TARGET, ObjectKind.DOMAIN, ObjectKind.HOST, ObjectKind.PORT,
    ObjectKind.SERVICE, ObjectKind.ENDPOINT, ObjectKind.TECHNOLOGY,
)
_SURFACE_RELATIONS = (
    RelationKind.RESOLVES_TO, RelationKind.HAS_PORT, RelationKind.HOSTS_SERVICE,
    RelationKind.EXPOSES, RelationKind.USES_TECHNOLOGY,
)
_FORENSIC_OBJECTS = (ObjectKind.HOST, ObjectKind.ASSET, ObjectKind.DOMAIN)
_FORENSIC_RELATIONS = (RelationKind.CONTAINS, RelationKind.RESOLVES_TO, RelationKind.RELATED_TO)
_BUILD_OBJECTS = (ObjectKind.ASSET, ObjectKind.SERVICE, ObjectKind.ENDPOINT, ObjectKind.TECHNOLOGY)
_BUILD_RELATIONS = (RelationKind.CONTAINS, RelationKind.EXPOSES, RelationKind.USES_TECHNOLOGY)
_ACTIONS = (
    LensAction("inspect-object", "Inspect the canonical object and its attributes."),
    LensAction("inspect-evidence", "Inspect source provenance and evidence references."),
    LensAction("review-observations", "Review retained attributable observations."),
)
LENS_CATALOG = (
    LensDescriptor(
        "pentest", "Pentest", "Prioritize the observed network and application surface.",
        _SURFACE_OBJECTS, _SURFACE_RELATIONS, LensQuery(_SURFACE_OBJECTS, _SURFACE_RELATIONS),
        _ACTIONS, ("network.tcp-connect", "network.service-discovery"), _OVERLAYS,
        {"reported-state": "state"}, LensPresentation(("kind", "key", "state")),
    ),
    LensDescriptor(
        "dfir", "DFIR", "Prioritize attributable objects and chronological observation history.",
        _FORENSIC_OBJECTS, _FORENSIC_RELATIONS,
        LensQuery(_FORENSIC_OBJECTS, _FORENSIC_RELATIONS, require_provenance=True),
        (_ACTIONS[1], _ACTIONS[2], _ACTIONS[0]), (), _OVERLAYS,
        {}, LensPresentation(("kind", "key", "source", "observed-at"), "source", "observed-at"),
    ),
    LensDescriptor(
        "devsecops", "DevSecOps", "Prioritize inventory, application endpoints, and technologies.",
        _BUILD_OBJECTS, _BUILD_RELATIONS, LensQuery(_BUILD_OBJECTS, _BUILD_RELATIONS),
        _ACTIONS, ("network.service-discovery",), _OVERLAYS,
        {"software-version": "version"}, LensPresentation(("kind", "key", "version")),
    ),
    LensDescriptor(
        "purple", "Purple Team", "Compare shared observations without inferring paths.",
        _SURFACE_OBJECTS + (ObjectKind.ASSET,), _SURFACE_RELATIONS + (RelationKind.RELATED_TO,),
        LensQuery(), (_ACTIONS[2], _ACTIONS[1], _ACTIONS[0]),
        ("network.service-discovery",), _OVERLAYS,
        {}, LensPresentation(("kind", "key", "source"), "kind", "observed-at"),
    ),
)


def ResolveLens(identifier: str) -> LensDescriptor:
    """Resolve a canonical catalog entry without fuzzy matching or ambient configuration.

    Args:
        identifier: Exact lowercase lens identifier.

    Returns:
        Immutable built-in descriptor.

    Raises:
        ValueError: The identifier is malformed or unsupported.
    """

    RequireIdentifier(identifier, "lens identifier")

    for descriptor in LENS_CATALOG:
        if descriptor.identifier == identifier:
            return descriptor

    raise ValueError(f"Unknown lens: {identifier}")
