# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise ordered pinned CVE batch custody with owned receiver fixtures."""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import replace

import pytest

from fuzzy1337 import intelligence_cve_batch as batch
from fuzzy1337 import intelligence_cve_remote as remote
from fuzzy1337.evidence import EvidenceStorageError, LocalEvidenceStore
from fuzzy1337.intel_references import CanonicalReferenceJson
from fuzzy1337.intelligence_acquisition import SyncState
from fuzzy1337.intelligence_cve_batch import AcquireHttpsCveBatch, CveHttpsBatchMemberState
from fuzzy1337.intelligence_cve_remote import (
    CveHttpsAcknowledgement,
    CveHttpsRequest,
    CveHttpsSource,
    CveHttpsState,
    LoadHttpsCveSelection,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

_SCOPE = "scope:owned-batch"


def SourceBytes(identifier):
    """Produce a controlled CVE 5.2 source record with one distinct identifier."""

    return CanonicalReferenceJson({"dataType": "CVE_RECORD", "dataVersion": "5.2",
        "cveMetadata": {"cveId": identifier, "state": "PUBLISHED",
            "dateUpdated": "2025-01-02T12:00:30Z"},
        "containers": {"cna": {"providerMetadata": {"orgId": "owned-cna"},
            "descriptions": [{"lang": "en", "value": "Owned source for " + identifier}]}}})


def Requests(count=3):
    """Select distinct original records at one immutable owned fixture revision."""

    sources = (f"CVE-1900-{number:04d}" for number in range(count, 0, -1))

    return tuple(CveHttpsRequest(CveHttpsSource(
        "a" * 40, identifier, hashlib.sha256(SourceBytes(identifier)).hexdigest(),
    )) for identifier in sources)


def Workspace(tmp_path, name="owned"):
    """Create a physical workspace owned by this controlled test."""

    workspace = LocalWorkspaceStore(tmp_path / name)
    workspace.Create(WorkspaceConfiguration("Owned CVE batch fixture"), name)

    return workspace


def OwnedReceiver(monkeypatch, requests, failures=None):
    """Record every exact synthetic receiver call and prohibit all undeclared locators."""

    sources = {request.source.SourceUrl: SourceBytes(request.source.identifier)
               for request in requests}
    calls = []
    supplied_failures = failures or {}

    def Receive(url, maximum, timeout):
        """Return only selected, bounded test bytes in the declared call order."""

        calls.append((url, maximum, timeout))

        return supplied_failures.get(url, (sources[url], "succeeded", 200))

    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", Receive)

    return calls


def ExpectedCalls(requests):
    """Project the caller's original independent receive limits without reordering."""

    return [(request.source.SourceUrl, request.max_bytes, request.timeout_seconds)
            for request in requests]


def Inventory(root):
    """Hash all regular files under one controlled workspace."""

    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*") if path.is_file()}


@pytest.mark.parametrize("count", [2, 4])
def test_ExactBatchLimitsPreserveSerialOrderAndPortablePerMemberCustody(
    tmp_path, monkeypatch, count,
):
    """Run a controlled batch, then reopen both original handle types after relocation."""

    requests = Requests(count)
    calls = OwnedReceiver(monkeypatch, requests)
    owner = Workspace(tmp_path)
    result = AcquireHttpsCveBatch(owner.root, requests, scope_reference=_SCOPE)
    assert result.state is SyncState.SUCCEEDED, "Verified members did not all succeed"
    assert (result.workspace_id, result.scope_reference) == ("owned", _SCOPE), (
        "Batch changed the original owner or collection scope"
    )
    assert tuple(member.request for member in result.members) == requests, (
        "Batch result changed the selected request order"
    )
    assert calls == ExpectedCalls(requests), "Source call order or independent limits changed"
    assert all(member.state is CveHttpsBatchMemberState.SUCCEEDED for member in result.members), (
        "An admitted complete member did not succeed"
    )
    before = Inventory(owner.root)
    relocated = tmp_path / "relocated"
    shutil.move(owner.root, relocated)
    store = LocalEvidenceStore(relocated / "evidence")

    for member in result.members:
        outcome = member.outcome
        assert outcome.raw and outcome.snapshot_record and outcome.receipt and outcome.envelope, (
            "Successful member omitted one or more custody handles"
        )
        assert member.raw_ack is member.snapshot_ack is member.receipt_ack is (
            CveHttpsAcknowledgement.CONFIRMED
        ), "Successful member did not confirm all independent publications"
        assert store.Read(outcome.raw.reference) == SourceBytes(member.request.source.identifier), (
            "Original stored bytes differ from the selected record"
        )
        assert LoadHttpsCveSelection(relocated, outcome.snapshot_record.evidence_id,
                                     outcome.receipt.evidence_id) == outcome.envelope, (
            "Relocated replay changed the original selected envelope"
        )

    first, second = (member.outcome for member in result.members[:2])

    with pytest.raises(ValueError):
        LoadHttpsCveSelection(relocated, first.snapshot_record.evidence_id,
                              second.receipt.evidence_id)

    assert calls == ExpectedCalls(requests), "Offline inspection attempted a receive"
    assert Inventory(relocated) == before and not (relocated / "model").exists(), (
        "Offline replay changed workspace files or created a model"
    )


@pytest.mark.parametrize("invalid", [
    "empty", "one", "five", "list", "untyped", "duplicate", "mixed-commit", "timeout", "scope",
])
def test_PreflightRefusesEntireInvalidBatchBeforeWorkspaceOrReceive(tmp_path, monkeypatch, invalid):
    """A bad later request cannot cause even the first source operation."""

    requests = Requests()
    scope = _SCOPE

    if invalid == "empty":
        requests = ()

    elif invalid == "one":
        requests = requests[:1]

    elif invalid == "five":
        requests = Requests(5)

    elif invalid == "list":
        requests = list(requests)

    elif invalid == "untyped":
        requests = (*requests, {})

    elif invalid == "duplicate":
        requests = (*requests, requests[0])

    elif invalid == "mixed-commit":
        requests = (*requests[:2], replace(requests[2],
            source=replace(requests[2].source, commit="b" * 40)))

    elif invalid == "timeout":
        requests = (*requests[:2], replace(requests[2], timeout_seconds=30.001))

    else:
        scope = ""

    def Forbidden(*args, **kwargs):
        """Prove invalid input is refused before either side-effect boundary."""

        pytest.fail("Invalid batch entered a workspace or contacted a source")

    monkeypatch.setattr(batch, "LocalWorkspaceStore", Forbidden)
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", Forbidden)

    with pytest.raises(ValueError):
        AcquireHttpsCveBatch(tmp_path / "missing", requests, scope_reference=scope)


def test_UnavailableInitialWorkspaceLeavesEveryMemberNotAttempted(tmp_path, monkeypatch):
    """Report an actual setup stop separately from malformed request admission."""

    requests = Requests(2)
    calls = OwnedReceiver(monkeypatch, requests)
    result = AcquireHttpsCveBatch(tmp_path / "missing", requests, scope_reference=_SCOPE)

    assert result.workspace_id is None and result.state is SyncState.FAILED, (
        "Unavailable workspace did not fail without an owner"
    )
    assert calls == [], "Unavailable workspace caused a receive"
    assert [member.state for member in result.members] == [
        CveHttpsBatchMemberState.NOT_ATTEMPTED,
        CveHttpsBatchMemberState.NOT_ATTEMPTED,
    ], "Setup failure changed a member into an attempted outcome"
    assert all(member.stop_reason == "workspace-unavailable" for member in result.members), (
        "Setup failure lost the workspace-unavailable reason"
    )
    assert all(member.raw_ack is CveHttpsAcknowledgement.NOT_ATTEMPTED
               for member in result.members), (
        "Setup failure claimed original publication was attempted"
    )


def test_OrdinaryReceiveFailureKeepsPartialOriginalAndContinues(tmp_path, monkeypatch):
    """Preserve partial transport facts while attempting every admitted independent member."""

    requests = Requests()
    owner = Workspace(tmp_path)
    partial = b"bounded owned partial"
    calls = OwnedReceiver(monkeypatch, requests, {
        requests[1].source.SourceUrl: (partial, "timed-out", 200),
    })
    result = AcquireHttpsCveBatch(owner.root, requests, scope_reference=_SCOPE)

    assert result.state is SyncState.PARTIAL and calls == ExpectedCalls(requests), (
        "A recoverable receive failure hid partial success or stopped later members"
    )
    assert [member.state for member in result.members] == [
        CveHttpsBatchMemberState.SUCCEEDED, CveHttpsBatchMemberState.FAILED,
        CveHttpsBatchMemberState.SUCCEEDED,
    ], "Partial receive did not preserve independent member outcomes"
    member = result.members[1]
    assert member.stop_reason is None and member.outcome.state is CveHttpsState.TIMED_OUT, (
        "Member timeout became a structural stop or lost its original state"
    )
    assert member.outcome.received_bytes == len(partial) and not member.outcome.body_complete, (
        "Member timeout changed partial-body completeness or byte count"
    )
    assert member.outcome.http_status == 200 and member.outcome.envelope is None, (
        "Partial receive changed HTTP status or exposed a usable selection"
    )
    assert member.raw_ack is member.receipt_ack is CveHttpsAcknowledgement.CONFIRMED, (
        "Partial receive lost confirmed original or receipt custody"
    )
    assert member.snapshot_ack is CveHttpsAcknowledgement.NOT_ATTEMPTED, (
        "Incomplete body attempted selected-envelope publication"
    )
    assert (
        LocalEvidenceStore(owner.root / "evidence").Read(member.outcome.raw.reference) == partial
    ), "Retained partial bytes differ from the actual receiver output"


def test_AllAttemptedFailuresKeepEveryIndependentReceipt(tmp_path, monkeypatch):
    """Return an all-failed summary without collapsing independent original outcomes."""

    requests = Requests(2)
    owner = Workspace(tmp_path)
    calls = OwnedReceiver(monkeypatch, requests, {
        request.source.SourceUrl: (b"", "transport-failed", None) for request in requests
    })
    result = AcquireHttpsCveBatch(owner.root, requests, scope_reference=_SCOPE)

    assert result.state is SyncState.FAILED and calls == ExpectedCalls(requests), (
        "All-failed batch hid attempted receives or reported success"
    )
    assert all(member.state is CveHttpsBatchMemberState.FAILED for member in result.members), (
        "An attempted transport failure was relabeled"
    )
    assert all(
        member.outcome.receipt and not member.outcome.envelope for member in result.members
    ), "Transport failure lost its receipt or exposed a usable selection"


@pytest.mark.parametrize("when", ["before", "after"])
@pytest.mark.parametrize("fault", ["mismatch", "unreadable", "invalid"])
def test_OwnerStopPreservesPriorOutcomeAndRefusesLaterContact(
    tmp_path, monkeypatch, when, fault,
):
    """Do not publish or continue after an observed owner stop at either boundary."""

    owner = Workspace(tmp_path)
    requests = Requests()
    calls = OwnedReceiver(monkeypatch, requests)
    open_calls = []
    put_calls = []
    open_original = LocalWorkspaceStore.Open
    put_original = LocalEvidenceStore.Put

    def Open(workspace):
        """Inject one authoritative read fault before or after the second receive."""

        state = open_original(workspace)
        open_calls.append(workspace.root)

        if len(open_calls) == (4 if when == "before" else 5):
            if fault == "unreadable":
                raise OSError("controlled owner read failure")

            if fault == "invalid":
                raise ValueError("controlled invalid workspace metadata")

            return replace(state, workspace_id="foreign")

        return state

    def Put(store, data, role, media_type, provenance):
        """Observe actual store writes for the successfully completed first member only."""

        put_calls.append(provenance.workspace_id)

        return put_original(store, data, role, media_type, provenance)

    monkeypatch.setattr(LocalWorkspaceStore, "Open", Open)
    monkeypatch.setattr(LocalEvidenceStore, "Put", Put)
    result = AcquireHttpsCveBatch(owner.root, requests, scope_reference=_SCOPE)

    first, stopped, later = result.members
    assert result.state is SyncState.PARTIAL and result.workspace_id == "owned", (
        "Owner stop lost prior partial success or original workspace identity"
    )
    assert first.state is CveHttpsBatchMemberState.SUCCEEDED and first.outcome.receipt, (
        "Owner stop discarded the earlier confirmed receipt"
    )
    assert put_calls == ["owned"] * 3, "Owner failure attempted new publication"
    assert later.state is CveHttpsBatchMemberState.NOT_ATTEMPTED, (
        "A later member became attempted after an owner stop"
    )
    reason = "workspace-changed" if fault == "mismatch" else "workspace-unavailable"
    assert stopped.stop_reason == later.stop_reason == reason, (
        "Member slots lost the structural stop reason"
    )
    assert stopped.outcome is None and later.outcome is None, (
        "An owner stop exposed a usable single-record outcome"
    )
    assert stopped.raw_ack is stopped.snapshot_ack is stopped.receipt_ack is (
        CveHttpsAcknowledgement.NOT_ATTEMPTED
    ), "Owner stop claimed one of its publications was attempted"

    if when == "before":
        assert stopped.state is CveHttpsBatchMemberState.NOT_ATTEMPTED, (
            "Pre-receive stop was presented as attempted"
        )
        assert stopped.stopped_receive is None and calls == ExpectedCalls(requests[:1]), (
            "Pre-receive stop recorded transport or continued contact"
        )

    else:
        assert stopped.state is CveHttpsBatchMemberState.FAILED, (
            "Post-receive stop was not classified as attempted failure"
        )
        assert calls == ExpectedCalls(requests[:2]), (
            "Post-receive stop lost its attempted receive or continued contact"
        )
        observed = stopped.stopped_receive
        assert observed.receive_state == "succeeded" and observed.http_status == 200, (
            "Post-receive stop lost receiver state or HTTP status"
        )
        assert observed.received_bytes == len(SourceBytes(stopped.request.source.identifier)), (
            "Post-receive stop changed the observed byte count"
        )
        assert observed.body_complete and observed.started_at <= observed.finished_at, (
            "Post-receive stop lost completeness or timestamp order"
        )


def test_SameOwnerRevisionAdvanceDoesNotReplaceWorkspace(tmp_path, monkeypatch):
    """Accept a cooperating metadata revision change with unchanged authoritative owner."""

    owner = Workspace(tmp_path)
    requests = Requests(2)

    def Receive(url, maximum, timeout):
        """Advance the owning metadata and return controlled original content."""

        owner.Save(owner.Open())

        return SourceBytes(url.rsplit("/", 1)[1].removesuffix(".json")), "succeeded", 200

    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", Receive)
    result = AcquireHttpsCveBatch(owner.root, requests, scope_reference=_SCOPE)

    assert result.state is SyncState.SUCCEEDED and owner.Open().revision == 2, (
        "Same-owner revisions prevented otherwise valid acquisitions"
    )
    assert result.workspace_id == "owned", (
        "Same-owner revision advancement changed the reported owner"
    )


def test_LostReceiptAckRetainsUnknownAndPermitsNextFreshlyCheckedMember(tmp_path, monkeypatch):
    """Preserve a real partial publication boundary rather than inferring rollback."""

    owner = Workspace(tmp_path)
    requests = Requests(2)
    calls = OwnedReceiver(monkeypatch, requests)
    original_put = LocalEvidenceStore.Put
    retained = []

    def Put(store, data, role, media_type, provenance):
        """Publish one receipt but simulate loss of its acknowledgement."""

        record = original_put(store, data, role, media_type, provenance)

        if role == remote.RECEIPT_ROLE and not retained:
            retained.append(record)
            raise EvidenceStorageError("controlled receipt acknowledgement loss")

        return record

    monkeypatch.setattr(LocalEvidenceStore, "Put", Put)
    result = AcquireHttpsCveBatch(owner.root, requests, scope_reference=_SCOPE)

    first, second = result.members
    assert result.state is SyncState.PARTIAL and calls == ExpectedCalls(requests), (
        "Uncertain receipt publication stopped a later admitted member"
    )
    assert first.outcome.state is CveHttpsState.STORAGE_FAILED, (
        "Lost receipt acknowledgement was not reported as a storage failure"
    )
    assert first.raw_ack is first.snapshot_ack is CveHttpsAcknowledgement.CONFIRMED, (
        "Lost receipt acknowledgement discarded earlier confirmed publications"
    )
    assert first.receipt_ack is CveHttpsAcknowledgement.UNKNOWN, (
        "Lost acknowledgement was treated as confirmed or not attempted"
    )
    assert first.outcome.receipt is first.outcome.envelope is None, (
        "Unacknowledged receipt exposed successful custody"
    )
    assert (
        LocalEvidenceStore(owner.root / "evidence").Get(retained[0].evidence_id) == retained[0]
    ), "Storage failure discarded the independently retained receipt"
    assert second.state is CveHttpsBatchMemberState.SUCCEEDED, (
        "Later member failed after a recoverable acknowledgement loss"
    )


@pytest.mark.parametrize("bad", [
    "foreign-owner", "foreign-scope", "request", "missing-receipt", "swapped-receipt",
    "wrong-media", "wrong-importer", "envelope-byte-limit", "envelope-timeout",
    "raw-size", "present-without-ack", "absent-with-ack",
])
def test_InvalidReturnedCustodyCannotSupplyUsableBatchHandles(tmp_path, monkeypatch, bad):
    """Fail closed if a returned record cannot be joined to the owning batch."""

    owner = Workspace(tmp_path)
    requests = Requests(2)
    calls = OwnedReceiver(monkeypatch, requests)
    acquire = batch._AcquireHttpsCveSelection

    def Acquire(*args, **kwargs):
        """Inject a damaged returned fact after the real owned publication."""

        outcome = acquire(*args, **kwargs)

        if bad == "request":
            return replace(outcome, max_bytes=outcome.max_bytes - 1)

        if bad == "missing-receipt":
            return replace(outcome, receipt=None)

        if bad == "swapped-receipt":
            return replace(outcome, receipt=outcome.raw)

        if bad == "wrong-media":
            return replace(outcome, receipt=replace(outcome.receipt,
                reference=replace(outcome.receipt.reference, media_type="text/plain")))

        if bad == "wrong-importer":
            return replace(outcome, receipt=replace(outcome.receipt,
                provenance=replace(outcome.receipt.provenance, source_id="foreign")))

        if bad == "envelope-byte-limit":
            return replace(outcome, envelope=replace(outcome.envelope,
                max_bytes=outcome.max_bytes - 1))

        if bad == "envelope-timeout":
            return replace(outcome, envelope=replace(outcome.envelope,
                timeout_seconds=outcome.timeout_seconds + 1))

        if bad == "raw-size":
            return replace(outcome, received_bytes=outcome.received_bytes + 1)

        if bad == "present-without-ack":
            return replace(outcome, state=CveHttpsState.STORAGE_FAILED, envelope=None,
                raw_ack=CveHttpsAcknowledgement.NOT_ATTEMPTED)

        if bad == "absent-with-ack":
            return replace(outcome, state=CveHttpsState.STORAGE_FAILED, envelope=None, raw=None)

        provenance = outcome.receipt.provenance
        wrong = (replace(provenance, workspace_id="foreign") if bad == "foreign-owner"
                 else replace(provenance, scope_reference="scope:foreign"))

        return replace(outcome, receipt=replace(outcome.receipt, provenance=wrong))

    monkeypatch.setattr(batch, "_AcquireHttpsCveSelection", Acquire)
    result = AcquireHttpsCveBatch(owner.root, requests, scope_reference=_SCOPE)

    failed, later = result.members
    assert result.state is SyncState.FAILED and calls == ExpectedCalls(requests[:1]), (
        "Invalid returned custody did not fail closed or caused later contact"
    )
    assert failed.state is CveHttpsBatchMemberState.FAILED and failed.outcome is None, (
        "Invalid returned custody exposed a usable result"
    )
    assert failed.stop_reason == later.stop_reason == "outcome-mismatch", (
        "Batch lost its returned-custody mismatch reason"
    )
    assert failed.stopped_receive.http_status == 200, (
        "Batch discarded the observed HTTP status on custody mismatch"
    )
    assert failed.raw_ack is failed.snapshot_ack is failed.receipt_ack is (
        CveHttpsAcknowledgement.UNKNOWN
    ), "Invalid joins appeared to confirm attributed publication"
    assert later.state is CveHttpsBatchMemberState.NOT_ATTEMPTED and later.outcome is None, (
        "Later slot reported an attempt or result after invalid custody"
    )
