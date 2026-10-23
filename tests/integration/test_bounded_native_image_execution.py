# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual installed material readers and owned synthetic wire composition, never genuine Trivy."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import sys
import time
from pathlib import Path

import pytest

from fuzzy1337.adapters import AdapterRequest, ExecutionState, ImpactLevel, SerializeContract
from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.executors import (
    ExecutionAuthorization,
    ExecutionEventKind,
    ExecutionTermination,
    InvocationDigest,
    LocalExecutionError,
    LocalExecutor,
)
from fuzzy1337.executors.owned_process import RequireLinuxOwnership
from fuzzy1337.model import LocalModelStore, ObjectKind
from fuzzy1337.native_image_admission import (
    ApplyVerifiedNativeTrivyImages,
    VerifyNativeTrivyImageReplay,
)
from fuzzy1337.native_image_bounded_capture import CaptureBoundedNativeTrivyOperation
from fuzzy1337.native_image_capture import NativeTrivyOperation, NativeTrivySelection
from fuzzy1337.native_image_observation import (
    NativeImageMaterialObserver,
    NativeImageObservationBudget,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

pytestmark = pytest.mark.integration
PAIR = "operation:owned-bounded-wire-pair"
WORKSPACE = "owned-bounded-wire"
OWNER = "owner:owned-bounded-wire"
METADATA = b'{"Version":2,"UpdatedAt":"2026-06-22T14:30:14Z"}'
VERSION_STDOUT = (
    b'{"Version": "0.75.0", "VulnerabilityDB": {"Version": 2, '
    b'"UpdatedAt": "2026-06-22T14:30:14Z"}, '
    b'"Fixture": "owned simulated native wire; no genuine scanner"}\n'
)
SCAN_STDOUT = (
    b'{"SchemaVersion": 2, "ArtifactType": "container_image", '
    b'"Metadata": {"ImageID": "sha256:' + b"a" * 64
    + b'"}, "Results": [{"Type": "python-pkg", "Packages": [{"ID": "owned-lib@1.0", '
    b'"Name": "owned-lib", "Version": "1.0", '
    b'"Identifier": {"PURL": "pkg:pypi/owned-lib@1.0"}}], "Vulnerabilities": []}]}\n'
)
SCAN_STDERR = b"owned simulated native wire; no image decode or network activity\n"


@pytest.fixture
def actual_linux_owner() -> None:
    """Require real ownership in designated Linux CI; unsupported optional hosts explicitly skip."""

    try:
        if sys.platform != "linux":
            raise LocalExecutionError("Closed composition requires actual Linux ownership")

        RequireLinuxOwnership()

    except LocalExecutionError:
        if os.environ.get("FUZZY1337_RUN_DESCENDANT_ACCEPTANCE") == "1":
            pytest.fail("Required closed composition lacks actual Linux descendant ownership")

        pytest.skip("Actual bounded native composition is unavailable; not acceptance")


def JournalFrames(path: Path) -> list[dict]:
    """Independently reopen the finite private SHA-framed original journal before post-observation.

    Args:
        path: Exact collector-owned journal associated with an already completed real wire request.

    Returns:
        Original prepared/complete frame dictionaries after independent bounded integrity checks.
    """

    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and (
        stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    ), "Original outcome custody must remain in its collector's private 0600/0700 association"

    with path.open("rb") as source:
        raw = source.read(32 * 1024 * 1024 + 1)

    assert len(raw) <= 32 * 1024 * 1024, "Private custody exceeded the fixed journal ceiling"
    magic = b"1337-native-outcome-v1\n"
    assert raw.startswith(magic), "Private original custody changed its fixed framing discriminator"
    cursor = len(magic)
    frames = []

    while cursor < len(raw):
        assert cursor + 40 <= len(raw), "Private custody contains an incomplete frame header"
        size = int.from_bytes(raw[cursor:cursor + 8], "big")
        digest = raw[cursor + 8:cursor + 40]
        cursor += 40
        assert 0 < size <= len(raw) - cursor, "Private original custody has an invalid frame length"
        payload = raw[cursor:cursor + size]
        assert hashlib.sha256(payload).digest() == digest, "Private original frame digest changed"
        frame = json.loads(payload)
        assert json.dumps(frame, sort_keys=True, separators=(",", ":")).encode() == payload, (
            "Private original custody must preserve exact canonical frame bytes"
        )
        frames.append(frame)
        cursor += size

    assert [frame["state"] for frame in frames] == ["prepared", "complete"], (
        "Complete original custody must already precede the post-material helper launch"
    )

    return frames


def OriginalEvents(outcome) -> list[dict]:
    """Render original observed event facts without assuming any subprocess read-chunk boundaries.

    Args:
        outcome: Unchanged real LocalExecutor result observed after owned cleanup.

    Returns:
        Exact historical four-field event dictionaries in their original order.
    """

    return [{"sequence": event.sequence, "kind": event.kind.value, "data_hex": event.data.hex(),
             "termination": None if event.termination is None else event.termination.value}
            for event in outcome.events]


def test_RealInstalledReadersAndOwnedWirePairPreserveOriginalCustody(
    tmp_path, actual_linux_owner, monkeypatch,
):
    """Cross actual process boundaries and preserve historical replay without saving a proposal."""

    del actual_linux_owner
    root = tmp_path / "workspace"
    workspace = LocalWorkspaceStore(root)
    workspace_before = workspace.Create(WorkspaceConfiguration("Owned bounded wire"), WORKSPACE)
    original_model = LocalModelStore(root).Create()
    database = root / "trivy-cache" / "db"
    database.mkdir(parents=True)
    (database / "trivy.db").write_bytes(b"owned simulated database bytes")
    (database / "metadata.json").write_bytes(METADATA)
    (root / "owned.tar").write_bytes(b"owned fixed fixture")
    fixture = Path(__file__).parents[1] / "fixtures/trivy/native_capture_wire.py"
    executable = root / "owned-bounded-wire"
    executable_bytes = f"#!{sys.executable}\n".encode() + fixture.read_bytes()
    executable.write_bytes(executable_bytes)
    executable.chmod(0o700)
    selection = NativeTrivySelection(root, executable, "owned.tar", "trivy-cache",
        ArtifactReadConsent(OWNER, "read:owned-bounded-wire"))
    store = LocalEvidenceStore(root / "evidence")
    observer = NativeImageMaterialObserver(selection, WORKSPACE, OWNER)
    budget = NativeImageObservationBudget(overall_deadline=time.monotonic() + 64)
    executions = []
    provider_results = []
    retained_before_post = []
    execute = LocalExecutor.Execute

    async def ObserveExecution(executor, request, **options):
        """Delegate actual execution unchanged and inspect already durable original custody."""

        helper = request.invocation.argv[:4] == (sys.executable, "-I", "-m",
            "fuzzy1337.native_image_material_worker")
        assert options.get("own_descendants") is True, "Every process needs descendant ownership"

        if helper and provider_results:
            original_request, original = provider_results[-1]
            journals = tuple(root.glob("native-image-bounded-*/outcome.journal"))
            assert len(journals) == 1, "Only this operation's private journal may be active"
            journal = journals[0]
            operation_directory = journal.parent
            assert Path(request.invocation.argv[4]).parent != operation_directory, (
                "The observation owner must not borrow the collector's original-custody directory"
            )
            assert root / original_request.workspace != operation_directory, (
                "Historical root-level provider scratch must stay separate from its private journal"
            )
            frames = JournalFrames(journal)
            header, complete = frames
            assert header["control"]["pair_reference"] == PAIR and (
                header["control"]["request"]["authorization"]["authorization_id"]
                == original_request.authorization.authorization_id
            ), "Private custody must bind the exact original operation before another helper starts"
            assert complete["stdout_hex"] == original.stdout.hex() and (
                complete["stderr_hex"] == original.stderr.hex()
                and complete["events"] == OriginalEvents(original)
            ), "Original streams and events must be durable before post-material observation"
            retained_before_post.append(journal)

        elif not helper:
            assert request.invocation.argv[0] == str(executable), (
                "Only the explicitly selected owned synthetic wire producer may execute"
            )

        outcome = await execute(executor, request, **options)
        executions.append((request, helper, outcome))

        if not helper:
            provider_results.append((request, outcome))

        return outcome

    monkeypatch.setattr(LocalExecutor, "Execute", ObserveExecution)
    invocations = []
    authorizations = {}
    authority_checks = []

    def ValidateAuthority(request) -> None:
        """Confirm the caller's original explicit decision at each fresh owner callback."""

        expected = authorizations[request.authorization.authorization_id]
        assert request.authorization == expected and (
            expected.invocation_sha256 == InvocationDigest(request.invocation)
        ), "Actual launch must retain the caller's exact original invocation-bound decision"
        authority_checks.append(request.authorization.authorization_id)

    async def CapturePair():
        """Share one observer, pair reference and ledger through exactly three actual reads."""

        initial = await observer.Observe(budget, operation_reference=PAIR)
        previous = None
        proof = initial
        captured = []

        for operation in (NativeTrivyOperation.VERSION, NativeTrivyOperation.SCAN):
            adapter = selection.Adapter(store,
                None if previous is None else previous.observed_version)
            request = AdapterRequest("image.archive-vulnerabilities", "target:owned-bounded-wire",
                ImpactLevel.SAFE, {"archive": "owned.tar", "timeout_seconds": 3})
            invocation = adapter.PrepareVersionInvocation(request) if previous is None else (
                adapter.PrepareInvocation(request))
            authority = ExecutionAuthorization("authorization:owned-bounded-" + operation.value,
                "scope:owned-bounded-wire", "policy:owned-bounded-wire",
                InvocationDigest(invocation))
            authorizations[authority.authorization_id] = authority
            invocations.append(invocation)
            result = await CaptureBoundedNativeTrivyOperation(operation, selection, invocation,
                authority, store, WORKSPACE, OWNER, observer=observer, budget=budget,
                material_proof=proof, operation_reference=PAIR, version_prerequisite=previous,
                validate_authority=ValidateAuthority)
            assert result.material_proof is not None, "A successful pair needs its post-read proof"
            captured.append(result)
            previous = result.capture
            proof = result.material_proof

        return initial, captured[0], captured[1]

    initial, version_result, scan_result = asyncio.run(CapturePair())
    version, scan = version_result.capture, scan_result.capture
    assert [helper for _, helper, _ in executions] == [True, False, True, False, True], (
        "The actual pair must use exactly three installed readers and two owned wire processes"
    )
    assert budget.ObservationCount == 3 and not budget.Failed and budget.SpentSeconds <= 45 and (
        budget.FinalizationSeconds <= 9
    ), "The actual pair must share three observations and one cumulative finalization reserve"
    assert len(retained_before_post) == 2 and all(
        not path.exists() for path in retained_before_post
    ), (
        "Both originals must precede post-read and confirmed publication must remove their journals"
    )
    assert set(authority_checks) == set(authorizations) and len(authorizations) == 2, (
        "VERSION and SCAN must retain their separately checked original execution authorizations"
    )
    assert invocations[0].argv == (str(executable), "--cache-dir", str(root / "trivy-cache"),
        "--config=", "--version", "--format", "json") and (
        invocations[0].provider_version is None and invocations[0].timeout_seconds == 3
    ), "Original VERSION factory argv and unknown provider version must remain unchanged"
    assert invocations[1].argv == (str(executable), "--cache-dir", str(root / "trivy-cache"),
        "--config=", "image", "--input", str(root / "owned.tar"), "--format", "json",
        "--scanners", "vuln", "--disable-telemetry", "--offline-scan", "--skip-db-update",
        "--skip-java-db-update", "--skip-check-update", "--skip-version-check",
        "--skip-vex-repo-update", "--ignorefile=", "--list-all-pkgs", "--exit-code", "0",
        "--no-progress", "--timeout", "3s") and invocations[1].timeout_seconds == 3, (
        "The owned wire must receive exactly the original finite offline SCAN argv"
    )
    assert version.observed_version == "0.75.0" and (
        scan.version_prerequisite_sha256 == version.Digest()
    ), (
        "SCAN must bind the actual original owned-wire VERSION without rewriting that invocation"
    )
    proofs = (initial, version_result.material_proof, scan_result.material_proof)
    assert len({proof.observation_id for proof in proofs}) == 3 and all(
        proof.operation_reference == PAIR and proof.facts == initial.facts for proof in proofs
    ), "Three distinct real observations must retain one pair association and unchanged material"
    expected_material = (("archive", root / "owned.tar", b"owned fixed fixture"),
        ("executable", executable, executable_bytes),
        ("database", database / "trivy.db", b"owned simulated database bytes"),
        ("database-metadata", database / "metadata.json", METADATA))

    for fact, (role, path, raw) in zip(initial.facts, expected_material, strict=True):
        info = path.stat(follow_symlinks=False)
        assert (fact.role, fact.path, fact.size_bytes, fact.sha256, fact.physical_identity) == (
            role, str(path), len(raw), hashlib.sha256(raw).hexdigest(),
            (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        ), "Actual installed readers must retain exactly four independently owned file identities"

    records = (*version.records, *scan.records)
    assert [record.reference.role for record in records] == ["provider-version",
        "provider-version-stderr", "native-version-receipt", "stdout", "stderr",
        "native-scan-receipt"], (
        "The bounded pair must preserve exactly the six original canonical custody roles"
    )
    expected_raw = {}

    for capture, (original_request, original), expected_stdout, expected_stderr in zip(
        (version, scan), provider_results, (VERSION_STDOUT, SCAN_STDOUT),
        (b"", SCAN_STDERR), strict=True):
        assert capture.refusal is None and capture.request == original_request and (
            capture.outcome == original
            and capture.material_before == capture.material_after == initial.facts
        ) and (
            original.execution.state is ExecutionState.SUCCEEDED
            and original.execution.exit_code == 0
            and original.termination is ExecutionTermination.PROCESS_EXIT
        ), "Accepted custody must retain the actual unchanged successful owned-wire terminal result"
        assert original.stdout == expected_stdout and original.stderr == expected_stderr, (
            "Actual owned-wire bytes differ from the independent closed VERSION/SCAN oracle"
        )
        assert b"".join(event.data for event in original.events
            if event.kind is ExecutionEventKind.STDOUT) == expected_stdout and (
            b"".join(event.data for event in original.events
                if event.kind is ExecutionEventKind.STDERR) == expected_stderr
        ), "Original event chunks must retain both exact streams without rechunking assumptions"

        for record in capture.records:
            raw = store.Read(record.reference)
            expected = SerializeContract(capture.Envelope()).encode() if (
                record.reference.role.endswith("-receipt")) else (
                    expected_stderr if record.reference.role.endswith("stderr")
                    else expected_stdout)
            assert raw == expected and store.Get(record.evidence_id) == record, (
                "Every original stream and canonical receipt must reopen with exact immutable bytes"
            )
            assert record.provenance.invocation_sha256 == (
                InvocationDigest(capture.request.invocation)
            ) and record.provenance.execution == original.execution, (
                "Every original role must preserve its invocation and terminal outcome provenance"
            )
            expected_raw[record.evidence_id] = raw

    replay = VerifyNativeTrivyImageReplay(records, root)
    assert replay.version_request == version.request and replay.scan_request == scan.request, (
        "The unchanged historical replay owner must accept both exact original bounded requests"
    )
    proposal, delta = ApplyVerifiedNativeTrivyImages(original_model, version, scan, root)
    assert proposal.revision == delta.revision == original_model.revision + 1 and (
        not proposal.Objects(ObjectKind.FINDING)
    ), "The fixed empty-vulnerability wire must form an in-memory compatibility proposal only"
    assert LocalModelStore(root).Open() == original_model and (
        workspace.Open() == workspace_before
    ), (
        "Historical pure proposal verification must not save model or workspace state"
    )
    assert not tuple(root.glob("native-material-*")) and (
        not tuple(root.glob("native-image-bounded-*"))
    ), (
        "Confirmed helper and collector owners must clean their completed private directories"
    )
    assert all(not (root / request.workspace).exists() for request, _ in provider_results), (
        "Both historical provider scratch directories must be removed after confirmed publication"
    )

    for selected in (root / "owned.tar", executable,
                     database / "trivy.db", database / "metadata.json"):
        selected.unlink()

    moved = tmp_path / "relocated"
    root.rename(moved)
    reopened = LocalEvidenceStore(moved / "evidence")

    for record in records:
        assert reopened.Get(record.evidence_id) == record and (
            reopened.Read(record.reference) == expected_raw[record.evidence_id]
        ), "Original custody must reopen after selected inputs disappear and workspace relocation"

    assert VerifyNativeTrivyImageReplay(records, moved) == replay and (
        LocalModelStore(moved).Open() == original_model
    ), "Historical replay and the unsaved original model must survive target removal and relocation"
