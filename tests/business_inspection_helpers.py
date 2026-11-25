# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned saved business declarations without technical paths, scoring or active providers."""

import json
from io import StringIO

from fuzzy1337.business_commands import RunBusinessCommands
from fuzzy1337.business_events import ApplyBusinessEvent, ReadBusinessEventDefinition
from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
from fuzzy1337.model import (
    CanonicalModelJson,
    LocalModelStore,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from fuzzy1337.reachability import ReachabilityModelVersion
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration


def Owned(parent, *, persisted=True, count=2):
    """Retain literal owner facts and optionally persist their accepted declaration profile."""

    root = parent / "owned business workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned business inspection"), "owned")
    evidence = LocalEvidenceStore(root / "evidence")
    attribution = EvidenceProvenance("owned", "scope:business", "synthetic-owner", "1", None,
                                    "2026-10-13T00:00:00Z", "2026-10-13T00:00:00Z")
    support = evidence.Put(b"Owned saved asset inventory", "inventory", "text/plain", attribution)
    provenance = ModelProvenance("synthetic-inventory", "inventory:owned",
        "2026-10-13T00:00:00Z", "scope:business", "assets:owned",
        evidence_references=(support.reference,))
    assets = tuple(SecurityObject(
        ObjectIdentity("owned", ObjectKind.ASSET, f"billing:{index}"),
        {"asset_type": "business-service", "version": "1"}, (provenance,),
    ) for index in range(count))
    store = LocalModelStore(root)
    model, delta = store.Create().Apply(objects=assets)
    store.Save(model, expected_revision=delta.previous_revision)
    fields = {
        "profile_version": 1, "workspace_id": "owned",
        "definition_key": "billing-disruption", "definition_version": "2026.1",
        "owner_reference": "owner:synthetic-billing", "title": "Billing service disruption",
        "unacceptable_outcome": "Owner-declared loss of billing service availability",
        "declared_at": "2026-10-13T00:00:00Z",
        "critical_asset_references": [asset.Reference() for asset in assets],
    }
    record = evidence.Put(CanonicalModelJson(fields), "business-event-definition",
                          "application/json", attribution)

    if persisted:
        definition = ReadBusinessEventDefinition(model, record, workspace_root=root,
            expected_model_version=ReachabilityModelVersion.FromModel(model),
            scope_reference="scope:business")
        model, delta = ApplyBusinessEvent(definition, model)
        model = store.Save(model, expected_revision=delta.previous_revision)

    return root, record, model, support


def Arguments(root, record, model):
    """Select one independently retained manifest and the complete current canonical model pin."""

    version = ReachabilityModelVersion.FromModel(model)

    return ["inspect", str(root), "--definition", record.evidence_id,
        "--scope-reference", "scope:business", "--expected-revision", str(version.revision),
        "--expected-snapshot-sha256", version.snapshot_sha256]


def Files(root):
    """Capture only the explicitly owned fixture's saved file bytes."""

    return {str(path.relative_to(root)): path.read_bytes()
            for path in root.rglob("*") if path.is_file()}


def Run(arguments, *, human=False):
    """Invoke the actual read-only command while retaining its structured process status."""

    output = StringIO()
    status = RunBusinessCommands(arguments, output, machine=not human)

    return status, output.getvalue() if human else json.loads(output.getvalue())
