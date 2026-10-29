# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Build the handwritten reachability profile through independent existing storage producers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.model import (
    CanonicalModelJson,
    LocalModelStore,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    Observation,
    Relation,
    RelationKind,
    SecurityObject,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

FIXTURES = Path(__file__).parent / "fixtures"


@dataclass
class Fixture:
    """Synthetic source producer that never derives expected semantics from reachability code."""

    root: Path
    graph: dict
    model: object
    objects: dict
    relations: dict
    observations: dict
    records: dict

    @classmethod
    def Create(cls, root, *, support_time=None, support_started_at=None, execution=None,
               raw_support=None, empty_evidence=False):
        """Persist exact synthetic objects and independent support before assessment acquisition.

        Args:
            root: Isolated test-owned workspace directory.
            support_time: Optional explicit finished/observed timestamp override.
            support_started_at: Optional independent acquisition start override.
            execution: Optional explicit owning acquisition outcome.
            raw_support: Optional original support bytes for allocation/integrity tests.
            empty_evidence: Whether retained support observations have no evidence.

        Returns:
            Independent real owning stores and their retained snapshot/records.
        """

        graph = json.loads((FIXTURES / "reachability.graph.v1.json").read_text())
        workspace = graph["workspace_id"]
        scope = graph["scope_reference"]
        finished = support_time or graph["support_time"]
        started = support_started_at or finished
        LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned reachability"), workspace)
        store = LocalModelStore(root)
        initial = store.Create()
        evidence = LocalEvidenceStore(root / "evidence")
        common = ModelProvenance("synthetic-reachability-witness", "run:fixture", finished,
            scope, "target:fixture", "review-tool-v3", execution=execution)
        objects = {}

        for node in graph["nodes"]:
            attributes = {"asset_type": node["asset_type"]} if "asset_type" in node else {}
            objects[node["alias"]] = SecurityObject(
                ObjectIdentity(workspace, ObjectKind(node["kind"]), node["key"]),
                attributes, (common,),
            )

        relations = {edge["alias"]: Relation(RelationKind(edge["kind"]),
            objects[edge["source"]].Reference(), objects[edge["target"]].Reference(),
            provenance=(common,)) for edge in graph["transitions"]}
        subjects = {**{alias: item.Reference() for alias, item in relations.items()},
                    **{alias: item.Reference() for alias, item in objects.items()
                       if item.attributes.get("asset_type") == "reachability-control"}}
        observations = {}
        records = {}

        for alias, reference in subjects.items():
            raw = raw_support if raw_support is not None else (
                "synthetic-witness:" + alias + ":synthetic-private-source-value"
            ).encode()
            record = evidence.Put(raw, "transition-witness", "application/octet-stream",
                EvidenceProvenance(workspace, scope, common.source_id, "format-v17",
                    common.provider_version, started, finished, execution=execution))
            records[alias] = record
            provenance = ModelProvenance(common.source_id, "run:fixture", finished, scope,
                "target:fixture", common.provider_version,
                () if empty_evidence else (record.reference,), execution)
            observations[alias] = Observation("reachability-support", reference,
                                             {"witness_alias": alias}, provenance)

        changed, _ = initial.Apply(objects=tuple(objects.values()),
            relations=tuple(relations.values()), observations=tuple(observations.values()))
        saved = store.Save(changed, expected_revision=initial.revision)

        return cls(root, graph, saved, objects, relations, observations, records)

    def Version(self):
        """Derive the profile's snapshot pin independently through the existing model serializer.

        Returns:
            Literal complete model_version envelope fields.
        """

        return {"schema_version": 1, "workspace_id": self.model.workspace_id,
                "revision": self.model.revision,
                "snapshot_sha256": hashlib.sha256(
                    CanonicalModelJson(self.model.ToDict()),
                ).hexdigest()}

    def Basis(self, alias):
        """Expose exact independent source observation and manifest identities.

        Args:
            alias: Synthetic transition or control alias.

        Returns:
            Normative basis grammar containing existing producer references.
        """

        return {"observation_reference": self.observations[alias].Reference(),
                "evidence_manifest_ids": [self.records[alias].evidence_id]}

    def Declaration(self, alias, state="CONFIRMED", confidence=0.99, *, controls=(), rule=None):
        """Build a literal supplied attestation rather than computing a state from evidence.

        Args:
            alias: Explicit transition alias.
            state: Exact independent supplied profile label.
            confidence: Exact independent numeric estimate.
            controls: Explicit blocking-control aliases.
            rule: Optional supplied inference identifier.

        Returns:
            Exact six-field normative declaration grammar.
        """

        return {"relation_reference": self.relations[alias].Reference(), "state": state,
                "confidence": confidence, "inference_rule": rule,
                "basis": [] if state == "UNKNOWN" else [self.Basis(alias)],
                "blocking_controls": [{"control_reference": self.objects[control].Reference(),
                                       **self.Basis(control)} for control in controls]}

    def Envelope(self, declarations):
        """Bind separately acquired source declarations to the complete already persisted basis.

        Args:
            declarations: Explicit independently supplied transition assertions.

        Returns:
            Literal version-one profile envelope.
        """

        return {"profile_version": 1, "assessment_kind": "supplied-transition-attestation",
                "model_version": self.Version(),
                "context_reference": self.graph["context_reference"],
                "scope_reference": self.graph["scope_reference"], "claims": declarations}

    def Assessment(self, envelope=None, *, raw=None, role="reachability-claims",
                   media_type="application/json", **provenance_changes):
        """Acquire original source bytes after the pinned model's independent support observations.

        Args:
            envelope: Explicit grammar; defaults to a single confirmed transition.
            raw: Optional hostile original JSON bytes without prevalidation.
            role: Caller-declared evidence role.
            media_type: Caller-declared original media type.
            provenance_changes: Explicit synthetic acquisition attribution overrides.

        Returns:
            Existing owner's immutable EvidenceRecord.
        """

        if raw is None:
            if envelope is None:
                envelope = self.Envelope([self.Declaration("source-portal")])

            raw = CanonicalModelJson(envelope)

        fields = {"workspace_id": self.model.workspace_id,
            "scope_reference": self.graph["scope_reference"],
            "source_id": "synthetic-reachability-attester", "source_version": "1",
            "tool_version": "review-attester-v2",
            "started_at": self.graph["assessment_started_at"],
            "finished_at": self.graph["assessment_finished_at"], **provenance_changes}

        return LocalEvidenceStore(self.root / "evidence").Put(
            raw, role, media_type, EvidenceProvenance(**fields),
        )

    def Phase(self, name):
        """Materialize the handwritten phase assertions, including distinct conflicting sources.

        Args:
            name: Explicit symbolic phase identifier.

        Returns:
            One or more independent acquired assessment records.
        """

        phase = next(item for item in self.graph["phases"] if item["id"] == name)
        overrides = {item["relation"]: item for item in phase["overrides"]
                     if not item.get("independent_artifact")}
        declarations = []

        for alias in self.relations:
            override = overrides.get(alias, {})
            declarations.append(self.Declaration(alias,
                override.get("state", phase["default_state"]),
                override.get("confidence", phase["default_confidence"]),
                controls=override.get("controls", ()), rule=override.get("inference_rule")))

        records = [self.Assessment(self.Envelope(declarations))]

        for override in phase["overrides"]:
            if override.get("independent_artifact"):
                declarations = [self.Declaration(override["relation"], override["state"],
                    override["confidence"], controls=override.get("controls", ()))]
                records.append(self.Assessment(self.Envelope(declarations),
                                               source_id="second-reachability-attester"))

        return tuple(records)
