# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""User-level closed synthetic image collection, durable reopening and separate export failures."""

from __future__ import annotations

import asyncio
import json

from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.findings import Findings
from fuzzy1337.image_workflow import RunSyntheticImageScan
from fuzzy1337.jobs import JobState
from fuzzy1337.model import LocalModelStore
from fuzzy1337.synthetic_images import VerifySyntheticTrivyImageReplay
from fuzzy1337.workspace import LocalWorkspaceStore
from tests.image_helpers import CreateOwnedImage


def test_OperatorCanCollectReopenVerifyAndExportClosedSyntheticImageInventory(tmp_path):
    """Drive the assembled SDK workflow over an owned no-findings fixture and reopen it."""

    owned = CreateOwnedImage(tmp_path, "no_findings")
    output = tmp_path / "inventory.json"
    summary = asyncio.run(RunSyntheticImageScan(owned.root, "image-scope", "owner:image-test",
        owned.selection, approve_safe_image=True, report_format="json", report_output=output))
    assert summary.snapshot.state is JobState.COMPLETED and summary.ExitCode() == 0, (
        "User workflow completes only after actual governed operations, durable saves and export"
    )
    reopened = LocalModelStore(owned.root).Open()
    workspace = LocalWorkspaceStore(owned.root).Open()
    store = LocalEvidenceStore(owned.root / "evidence")
    roles = {"provider-version", "provider-version-stderr", "stdout", "stderr",
        "artifact-version-receipt", "artifact-scan-receipt"}
    acquisitions = tuple(store.Get(record_id) for record_id in workspace.evidence_record_references)
    records = tuple(item for item in acquisitions if item.reference.role in roles)
    original = VerifySyntheticTrivyImageReplay(records, owned.root)
    report = json.loads(output.read_bytes())
    assert len(records) == 6 and original.provenance.source_id == "synthetic.trivy", (
        "A reopened workspace retains exact original synthetic operation provenance"
    )
    assert not Findings(reopened) and report["scan_completeness"] == "not-assessed", (
        "No Findings remains explicit inventory without a clean-scan or completeness claim"
    )
    assert report["model"] == reopened.ToDict() and summary.model_revision == reopened.revision, (
        "User report and terminal summary describe the exact durable reopened model"
    )
