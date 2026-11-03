# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned receiver fixtures verify the pinned-source wrapper without live publisher access."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from fuzzy1337 import intelligence_acquisition
from fuzzy1337.evidence import EvidenceError, LocalEvidenceStore
from fuzzy1337.intelligence import IntelligenceFeed
from fuzzy1337.intelligence_acquisition import (
    AcquireIntelligenceSnapshot,
    AcquisitionOutcome,
    AcquisitionState,
    CisaKevSource,
    SnapshotRequest,
)
from fuzzy1337.model import CanonicalModelJson
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration
from tests.integration.test_intelligence_acquisition_persistence import FeedBody
from tools import intel_source_acceptance as acceptance


def OwnedSource(monkeypatch: pytest.MonkeyPatch) -> bytes:
    """Replace expected source content with an explicitly synthetic one-record receiver fixture.

    Args:
        monkeypatch: Pytest-owned isolation for expected fixture facts and the receiver boundary.

    Returns:
        Original fixture bytes; no live publisher call or actual official acceptance occurs.
    """

    raw = FeedBody(IntelligenceFeed.KEV)
    monkeypatch.setattr(acceptance, "EXPECTED_SHA256", hashlib.sha256(raw).hexdigest())
    monkeypatch.setattr(acceptance, "EXPECTED_CATALOG_VERSION", "synthetic-1")
    monkeypatch.setattr(acceptance, "EXPECTED_RECORDS", 1)
    monkeypatch.setattr(acceptance, "EXPECTED_BYTES", len(raw))

    def Receive(request: SnapshotRequest) -> tuple[bytes, AcquisitionState, int]:
        """Supply owned bytes at the SDK receiver seam while retaining actual acquisition stores.

        Args:
            request: Actual fixed HTTPS request built by the acceptance wrapper.

        Returns:
            One complete owned response, without making a network call.
        """

        assert request.payload is None and request.source == CisaKevSource(
            acceptance.SOURCE_COMMIT, "synthetic-1",
            expected_sha256=hashlib.sha256(raw).hexdigest(),
        ), "The wrapper replaced explicit HTTPS acquisition with local or generic source bytes."

        return raw, AcquisitionState.SUCCEEDED, 200

    monkeypatch.setattr(intelligence_acquisition, "FetchRemoteBytes", Receive)

    return raw


def Acquired(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, AcquisitionOutcome]:
    """Acquire owned receiver bytes through real immutable source/snapshot/receipt publication.

    Args:
        tmp_path: Disposable pytest-owned filesystem root.
        monkeypatch: Pytest-owned fixture substitutions; no live networking is permitted.

    Returns:
        Existing owning workspace and actual acquisition outcome.
    """

    OwnedSource(monkeypatch)
    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Owned source acceptance fixture"),
                                     "owned-fixture")
    outcome = AcquireIntelligenceSnapshot(root, SnapshotRequest(
        CisaKevSource(acceptance.SOURCE_COMMIT, acceptance.EXPECTED_CATALOG_VERSION,
                      expected_sha256=acceptance.EXPECTED_SHA256),
        max_bytes=acceptance.EXPECTED_BYTES,
        timeout_seconds=acceptance.RECEIVER_TIMEOUT_SECONDS,
    ), scope_reference="scope:owned-fixture")

    return root, outcome


def test_WrapperRetainsActualOriginalSourceAndSuccessfulReceipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Traverse actual acquisition, original reparse and receipt comparison on owned bytes.

    Args:
        tmp_path: Disposable owning output root.
        monkeypatch: Isolated fixture receiver and expected-content substitutions.
        capsys: Captured terminal facts for comparison with saved output.
    """

    raw = OwnedSource(monkeypatch)
    output = tmp_path / "acceptance"
    assert acceptance.RunAcceptance(output) == 0, "Owned actual receiver composition failed."
    summary = json.loads((output / "summary.json").read_bytes())
    assert summary["status"] == "succeeded" and summary["verification"]["receipt"] == "verified", (
        "The wrapper claimed success without original receipt verification."
    )
    assert summary["verification"]["verified_records"] == 1 and summary["verification"][
        "target_applicability"
    ] == "not-evaluated", "Source retrieval manufactured target applicability or catalog coverage."
    store = LocalEvidenceStore(output / "workspace" / "evidence")
    reference = summary["acquisition"]["raw"]["reference"]
    assert (output / "workspace" / "evidence" / reference["locator"]).read_bytes() == raw, (
        "The acceptance wrapper changed the original retained bytes."
    )
    assert json.loads(capsys.readouterr().out) == summary, "Terminal and saved facts differ."
    assert store.Get(summary["acquisition"]["snapshot_record"]["evidence_id"]), (
        "The terminal summary references no original immutable snapshot manifest."
    )


@pytest.mark.parametrize("field,value", [("transport", "local-bytes"), ("http_status", 302),
                                        ("body_complete", False), ("received_bytes", 1),
                                        ("receipt", None), ("max_bytes", 1),
                                        ("timeout_seconds", 1)])
def test_VerifierRefusesIncompleteOrSubstitutedTransportFacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object,
) -> None:
    """Local success, redirects and partial facts cannot become official HTTPS success.

    Args:
        tmp_path: Disposable owning output root.
        monkeypatch: Isolated fixture receiver and expected-content substitutions.
        field: Terminal outcome field whose verified meaning is changed.
        value: Explicit inconsistent replacement value.
    """

    root, outcome = Acquired(tmp_path, monkeypatch)

    with pytest.raises(ValueError):
        acceptance.VerifyOutcome(root, replace(outcome, **{field: value}))


@pytest.mark.parametrize("mutation", ["state", "publisher", "unknown-field"])
def test_RehashedReceiptCannotReplaceExactAcquisitionFacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    """A rehashed receipt must agree with all original terminal and source fields.

    Args:
        tmp_path: Disposable owning output root.
        monkeypatch: Isolated fixture receiver and expected-content substitutions.
        mutation: Controlled conflicting receipt statement.
    """

    root, outcome = Acquired(tmp_path, monkeypatch)
    store = LocalEvidenceStore(root / "evidence")
    document = json.loads(store.Read(outcome.receipt.reference))

    if mutation == "state":
        document["state"] = "transport-failed"

    elif mutation == "publisher":
        document["source"]["publisher"] = "Substituted publisher"

    else:
        document["invented"] = True

    replacement = store.Put(json.dumps(document).encode(), "intelligence-acquisition",
                            "application/json", outcome.receipt.provenance)

    with pytest.raises(ValueError):
        acceptance.VerifyOutcome(root, replace(outcome, receipt=replacement))


@pytest.mark.parametrize("field,value", [("role", "unrelated-artifact"),
                                        ("media_type", "text/plain")])
def test_RehashedReceiptCannotSubstituteRawSourceReference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: str,
) -> None:
    """Same-byte artifacts cannot replace the exact raw source bound to the saved snapshot.

    Args:
        tmp_path: Disposable owning workspace with actual acquisition records.
        monkeypatch: Owned receiver fixture; no live publisher request occurs.
        field: Raw-reference metadata changed without changing its byte digest.
        value: Explicit valid but unrelated role or media type.
    """

    root, outcome = Acquired(tmp_path, monkeypatch)
    store = LocalEvidenceStore(root / "evidence")
    original = outcome.raw.reference
    replacement = store.Put(
        store.Read(original), value if field == "role" else original.role,
        value if field == "media_type" else original.media_type, outcome.raw.provenance,
    )
    substituted = replace(outcome, raw=replacement)
    receipt = store.Put(CanonicalModelJson(substituted.ToDict()), "intelligence-acquisition",
                        "application/json", outcome.receipt.provenance)
    substituted = replace(substituted, receipt=receipt)
    assert replacement.reference.sha256 == original.sha256 and (
        store.Get(replacement.evidence_id) == replacement
        and store.Get(receipt.evidence_id) == receipt
        and CanonicalModelJson(json.loads(store.Read(receipt.reference)))
        == CanonicalModelJson(substituted.ToDict())
    ), "The regression requires valid same-byte manifests and a self-consistent rehashed receipt."

    with pytest.raises(ValueError, match="original source or verified reparse"):
        acceptance.VerifyOutcome(root, substituted)


def test_OriginalSourceCorruptionCannotPassReceiptAndReparseChecks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unchanged successful receipt cannot hide corruption of original raw bytes.

    Args:
        tmp_path: Disposable owning output root.
        monkeypatch: Isolated fixture receiver and expected-content substitutions.
    """

    root, outcome = Acquired(tmp_path, monkeypatch)
    (root / "evidence" / outcome.raw.reference.locator).write_bytes(
        b"x" * acceptance.EXPECTED_BYTES,
    )

    with pytest.raises(EvidenceError):
        acceptance.VerifyOutcome(root, outcome)


def test_FailedReceiverPreservesHonestFailureReceiptWithoutFallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """A transport failure retains its receipt and no usable snapshots or fallback.

    Args:
        tmp_path: Disposable owning output root.
        monkeypatch: Isolated fixture receiver and expected-content substitutions.
        capsys: Captured terminal facts for comparison with saved failure output.
    """

    OwnedSource(monkeypatch)

    def Refuse(request: SnapshotRequest) -> tuple[bytes, AcquisitionState, None]:
        """Return one controlled receiver refusal without fetching a source.

        Args:
            request: Actual immutable source selection, retained by the owning importer.

        Returns:
            No response bytes and an explicit transport failure.
        """

        return b"", AcquisitionState.TRANSPORT_FAILED, None

    monkeypatch.setattr(intelligence_acquisition, "FetchRemoteBytes", Refuse)
    output = tmp_path / "failed"
    assert acceptance.RunAcceptance(output) == 4, "Transport failure became successful acceptance."
    summary = json.loads((output / "summary.json").read_bytes())
    assert summary["status"] == "failed" and summary["acquisition"]["state"] == (
        "transport-failed"
    ), (
        "The wrapper replaced actual acquisition failure with cached or invented success."
    )
    assert summary["verification"] is None and summary["acquisition"]["snapshot_record"] is None, (
        "A failed source produced a usable snapshot or verification claim."
    )
    assert summary["acquisition"]["publisher_authentication"] == "not-assessed", (
        "A transport attempt fabricated publisher authentication."
    )
    assert json.loads(capsys.readouterr().out) == summary, "Failed terminal and saved facts differ."


@pytest.mark.parametrize("kind", ["existing", "symlink", "traversal"])
def test_OutputGuardsRefuseBeforeAcquisition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str,
) -> None:
    """Existing output, linked destinations and traversal never initiate acquisition.

    Args:
        tmp_path: Disposable owning output root.
        monkeypatch: Instrumentation that observes any unintended acquisition call.
        kind: Controlled unsafe output selection.
    """

    output = tmp_path / "output"
    target = tmp_path / "target"
    target.mkdir()

    if kind == "existing":
        output.mkdir()

    elif kind == "symlink":
        output.symlink_to(target, target_is_directory=True)

    else:
        output = tmp_path / ".." / "refused"

    calls = []
    monkeypatch.setattr(acceptance, "AcquireIntelligenceSnapshot", lambda *args, **kwargs:
                        calls.append(args))

    with pytest.raises(ValueError):
        acceptance.RunAcceptance(output)

    assert not calls, "Unsafe artifact output reached the live acquisition boundary."


def test_MainReportsSetupRefusalWithoutUntrustedPath(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    """An existing output yields fixed failure JSON without a local path traceback.

    Args:
        tmp_path: Existing directory that must not be overwritten.
        capsys: Captured terminal failure for checking its fixed public shape.
    """

    assert acceptance.Main(["--output", str(tmp_path)]) == 2, "Setup refusal did not fail closed."
    assert json.loads(capsys.readouterr().out) == {"status": "failed",
                                                  "failure": "acceptance-setup"}, (
        "Setup refusal leaked path details or an invented acceptance result."
    )


def test_HostedLaneHasOnlyExplicitDraftSameRepositoryReadOnlyAuthority() -> None:
    """The live data retrieval lane cannot run on a schedule, fork or ordinary ready PR."""

    root = Path(__file__).absolute().parents[2]
    workflow = yaml.load((root / ".github/workflows/intel-source-acceptance.yml").read_text(),
                         Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"pull_request"} and workflow["on"]["pull_request"] == {
        "branches": ["develop"], "types": ["opened", "synchronize", "reopened"],
    }, "Official-source acquisition gained an unrequested schedule or event authority."
    assert workflow["permissions"] == {"contents": "read"}, (
        "Read-only official-source acceptance gained repository mutation permission."
    )
    job = workflow["jobs"]["pinned-kev"]
    assert all(condition in job["if"] for condition in (
        "github.event.pull_request.draft", "github.repository",
        "github.event.pull_request.head.repo.full_name == github.repository",
        "contains(github.event.pull_request.body, '[intel-source-acceptance-checkpoint]')",
    )), "Live source retrieval lost draft, same-repository or explicit checkpoint guards."
    assert int(job["timeout-minutes"]) <= 8, "Live source job lost its finite whole-job deadline."
    checkout = next(step for step in job["steps"] if "actions/checkout@" in step.get("uses", ""))
    assert checkout["with"]["persist-credentials"] == "false", (
        "Read-only acceptance unexpectedly persisted repository credentials in checkout."
    )
