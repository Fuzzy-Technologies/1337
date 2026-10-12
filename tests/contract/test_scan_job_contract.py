# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Schema-v1 lifecycle event serialization and shared model payload contracts."""

from __future__ import annotations

import asyncio
import json

from fuzzy1337.adapters import NormalizedObservation, SerializeContract
from fuzzy1337.jobs import JOB_SCHEMA_VERSION, JobContext, JobEventKind, JobSpec, JobState, ScanJob
from fuzzy1337.model import ModelDelta


class StructuredProvider:
    """Emit typed data using the same contracts as future scan and live UI consumers."""

    async def Run(self, context: JobContext) -> None:
        """Publish version-independent observations and existing model deltas."""

        context.Progress(1, 2)
        context.Heartbeat()
        context.Observe(NormalizedObservation("host", "target:local", {"alive": True}))
        context.ModelChanged(ModelDelta(0, 0))
        context.Progress(2, 2)


def test_JobEventWireContractIsVersionedContiguousAndDeterministic() -> None:
    """Make discriminators, cursors and shared payload fields explicit for consumers."""

    async def Scenario() -> None:
        """Complete a synthetic job and compare repeated canonical serialization."""

        job = ScanJob(
            JobSpec(
                "job:contract", "workspace-local", "scope:local", "owner:local", "test.provider",
            ),
            StructuredProvider(),
        )
        job.Start()

        result = await job.Wait()

        events = job.EventsSince()
        serialized = SerializeContract(events)
        wire = json.loads(serialized)
        assert serialized == SerializeContract(events), "Wire serialization must be deterministic."
        assert JOB_SCHEMA_VERSION == 1, "The initial event schema version must be explicit."
        assert result.state is JobState.COMPLETED, "Valid event contracts must preserve success."
        assert [item["sequence"] for item in wire] == list(range(len(wire))), (
            "Wire cursors must be zero-based and contiguous."
        )

        for item in wire:
            assert set(item) == {"job_id", "sequence", "kind", "data", "schema_version"}, (
                "Schema-v1 event fields must remain explicit."
            )
            assert item["job_id"] == "job:contract", "Every wire event must retain job ownership."
            assert item["schema_version"] == 1, "Every wire event must declare its schema."

        assert [item["data"] for item in wire if item["kind"] == "state"] == [
            "queued", "running", "completed",
        ], "Wire state transitions must preserve canonical names."
        observation = next(item["data"] for item in wire if item["kind"] == "observation")
        assert observation == {
            "kind": "host", "subject_reference": "target:local", "attributes": {"alive": True},
        }, "Observation events must reuse the provider-neutral envelope."
        delta = next(item["data"] for item in wire if item["kind"] == "model_delta")
        assert delta == {"previous_revision": 0, "revision": 0, "created": [], "updated": []}, (
            "Model delta events must reuse the owning model's schema."
        )

    asyncio.run(Scenario())


def test_EventKindsAndStateNamesRemainSeparateFromExecutorStates() -> None:
    """Fix the user-level lifecycle without conflating it with an individual process result."""

    assert {state.value for state in JobState} == {
        "queued", "running", "completed", "failed", "cancelled",
    }, "Jobs must retain the five canonical lifecycle states."
    assert {kind.value for kind in JobEventKind} == {
        "state", "progress", "heartbeat", "cancellation_requested", "observation", "artifact",
        "model_delta", "failure",
    }, "Schema-v1 live consumers must have an explicit finite event discriminator set."
