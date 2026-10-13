# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent static HTML producer using actual workspace, scope and evidence owners."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from fuzzy1337.evidence import EvidenceProvenance, EvidenceRecord, LocalEvidenceStore
from fuzzy1337.requests import Endpoint, RequestTemplate
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

FIXTURES = Path(__file__).parent / "fixtures"


@dataclass(frozen=True)
class Fixture:
    """Retain exact synthetic acquisition independently of consumer results."""

    root: Path
    source: RequestTemplate
    capture: EvidenceRecord
    scope: ScopeSnapshot
    at: datetime
    oracle: dict

    @classmethod
    def Create(cls, root: Path, *, raw: bytes | None = None) -> Fixture:
        """Publish caller-owned HTML and exact declared scope independently of captured_web.

        Args:
            root: Isolated test workspace, never an unrelated physical path.
            raw: Optional original bytes for negative/source-budget tests.

        Returns:
            Actual existing owners and the handwritten source/oracle context.
        """

        oracle = json.loads((FIXTURES / "captured-web.oracle.v1.json").read_text())
        workspace_id = oracle["workspace_id"]
        source = RequestTemplate(Endpoint(workspace_id, "http://127.0.0.1:19091", "/docs/index"))
        LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned captured HTML"),
                                         workspace_id)

        def Targets(field: str) -> tuple[Target, ...]:
            """Build exact declared synthetic URLs without discovering or authorizing any target.

            Args:
                field: Handwritten declaration list in the independent oracle.

            Returns:
                Typed exact URL records for the existing scope owner.
            """

            return tuple(Target(TargetKind.URL, source.endpoint.origin + path)
                         for path in oracle[field])

        scope = ScopeSnapshot(oracle["scope_id"], workspace_id,
            ScopeAuthorization(AuthorizationState.GRANTED, "operator:synthetic",
                               "consent:synthetic"),
            targets=Targets("registered_paths"), allow=Targets("allowed_paths"),
            deny=Targets("denied_paths"))
        saved = LocalScopeStore(root).Create(scope)
        data = (FIXTURES / "captured-web.v1.html").read_bytes() if raw is None else raw
        capture = LocalEvidenceStore(root / "evidence").Put(data, "response-body", "text/html",
            EvidenceProvenance(workspace_id, saved.Reference(), "synthetic-html-collector",
                oracle["source_version"], oracle["tool_version"],
                oracle["capture_started_at"], oracle["capture_finished_at"]))

        return cls(root, source, capture, saved,
                   datetime.fromisoformat(oracle["checked_at"]), oracle)


def WorkspaceBytes(root: Path) -> dict[str, bytes]:
    """Snapshot only an explicit test-owned workspace before a claimed read-only operation.

    Args:
        root: Physical isolated fixture workspace.

    Returns:
        Relative file names and exact owned bytes.
    """

    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*") if path.is_file()}
