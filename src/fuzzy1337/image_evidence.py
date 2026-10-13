# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Original image operation capture production; interpretation belongs to synthetic_images."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import cast

from fuzzy1337.adapters import SerializeContract
from fuzzy1337.artifact_inputs import ArtifactStage
from fuzzy1337.artifact_policy import (
    ArtifactExecutionOutcome,
    ArtifactStagePayload,
    PreparedArtifact,
)
from fuzzy1337.evidence import EvidenceProvenance, NormalizeEvidenceTime
from fuzzy1337.executors import InvocationDigest

SYNTHETIC_IMAGE_SOURCE = "synthetic.trivy"
SYNTHETIC_IMAGE_VERSION = "0.75.0-synthetic"


def Detached(value: object) -> dict[str, object]:
    """Serialize original SDK facts through their owner without retaining caller aliases.

    Args:
        value: Typed original SDK payload or first-party capture document.

    Returns:
        Detached canonical finite JSON object, without verification or authority.
    """

    return cast(dict[str, object], json.loads(SerializeContract(value)))


@dataclass(frozen=True, slots=True)
class ImageOperationCapture:
    """Original per-operation outcome/request/stage and actual observed collection window."""

    outcome: ArtifactExecutionOutcome
    prepared: PreparedArtifact
    stage: ArtifactStage
    started_at: str
    finished_at: str

    def __post_init__(self) -> None:
        """Require typed original SDK objects and increasing clock readings without I/O."""

        if not isinstance(self.outcome, ArtifactExecutionOutcome) or not isinstance(
            self.prepared, PreparedArtifact
        ) or not isinstance(self.stage, ArtifactStage):
            raise ValueError("image capture requires original typed operation facts")

        object.__setattr__(self, "started_at", NormalizeEvidenceTime(self.started_at))
        object.__setattr__(self, "finished_at", NormalizeEvidenceTime(self.finished_at))

        if self.started_at >= self.finished_at:
            raise ValueError("image capture requires an increasing observed collection window")

    def Envelope(self) -> dict[str, object]:
        """Produce the exact schema-one envelope consumed by the canonical image interpreter.

        Returns:
            Detached original schema-two SDK facts, complete payloads and collection readings.
        """

        return Detached({
            "schema_version": 1, "artifact_metadata": self.outcome.Metadata(),
            "prepared_payload": self.prepared.Payload(),
            "stage_payload": ArtifactStagePayload(self.stage),
            "collection_started_at": self.started_at, "collection_finished_at": self.finished_at,
        })

    def Provenance(self) -> EvidenceProvenance:
        """Attribute captured streams/receipt to this operation's actual invocation and execution.

        Returns:
            Original owning-workspace/source facts; never authority or interpretation provenance.
        """

        plan = self.outcome.grant.plan

        return EvidenceProvenance(plan.workspace_id, plan.scope_reference,
            SYNTHETIC_IMAGE_SOURCE, "1", SYNTHETIC_IMAGE_VERSION, self.started_at, self.finished_at,
            InvocationDigest(self.prepared.invocation), self.outcome.raw_result.execution)
