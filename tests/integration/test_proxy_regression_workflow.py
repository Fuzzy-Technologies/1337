# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual ordinary Quick Scan denial, partial-state and independent proxy-fixture evidence."""

from __future__ import annotations

import http.client
import json

import pytest

from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import LocalModelStore, ObjectKind
from fuzzy1337.workspace import LocalWorkspaceStore
from tests import proxy_regression_helpers as helpers
from tests.proxy_regression_helpers import (
    PRIVATE_MARKER,
    Oracle,
    OwnedProxy,
    Product,
    Scan,
    Setup,
    Verify,
)


@pytest.mark.parametrize("case", Oracle()["cases"][:-1], ids=lambda case: case["id"])
def test_IndependentFixtureRequestsEstablishTheOriginalBackendHitOracle(case):
    """A direct test-only client verifies fixture behavior independently of the scanner."""

    with OwnedProxy() as lab:
        client = http.client.HTTPConnection("127.0.0.1", lab.frontend.server_port, timeout=1)

        try:
            client.request("GET", case["frontend_route"])
            response = client.getresponse()
            assert response.status == case["frontend_status"] and PRIVATE_MARKER in (
                response.read(128).decode()
            ), "First-party target does not expose its declared finite response"
            assert lab.Observe() == ([case["frontend_route"]], case["backend_hits"]), (
                "Independent test-only backend log differs from handwritten source oracle"
            )

        finally:
            client.close()

    assert not any(thread.is_alive() for thread in lab.request_threads), (
        "Owned fixture cleanup abandoned an accepted request thread"
    )


@pytest.mark.parametrize("condition", ["unknown-consent", "excluded", "missing-safe-permission"])
def test_OrdinaryProductDenialsContactNeitherFrontendNorBackend(tmp_path, condition):
    """A reverse-proxy fixture never supplies missing current target consent or SAFE permission."""

    case = Oracle()["cases"][0]

    with OwnedProxy() as lab:
        root = tmp_path / "workspace"
        Setup(root, (lab.Url(case),), granted=condition != "unknown-consent",
              excluded=condition == "excluded")
        status, summary = Product(Scan(root, (lab.Url(case),),
                                      approved=condition != "missing-safe-permission"))
        assert status == 3 and summary["job"]["failure"]["code"] == "authorization", (
            "Proxy fixture masked an ordinary scope or explicit capability denial"
        )
        assert lab.Observe() == ([], []) and not LocalModelStore(root).Open().objects and (
            not LocalWorkspaceStore(root).Open().evidence_record_references
        ), "Denied proxy scan made network contact or fabricated successful acquisition"


def test_HandlerBlockedResponseIsObservedWithoutInventingBlockedReachability(tmp_path):
    """The fixture's declared 403 affects only original endpoint response facts."""

    case = Oracle()["cases"][1]

    with OwnedProxy() as lab:
        root = tmp_path / "workspace"
        Setup(root, (lab.Url(case),))
        status, summary = Product(Scan(root, (lab.Url(case),)))
        assert status == 0, "A bounded observed HTTP error became a failed discovery workflow"
        Verify(root, summary, case, lab)


def test_LaterProxyTimeoutRetainsOnlyActuallySavedEarlierFrontendFacts(tmp_path):
    """Whole-run timeout preserves earlier original evidence without a phantom backend endpoint."""

    first, final = Oracle()["cases"][0], Oracle()["cases"][-1]

    with OwnedProxy() as lab:
        root = tmp_path / "workspace"
        urls = (lab.Url(first), lab.Url(final))
        Setup(root, urls)
        status, summary = Product(Scan(root, urls))
        assert status == 4 and summary["state"] == "failed" and (
            summary["job"]["failure"]["code"] == "timeout"
        ), "Later proxy timeout was hidden by an earlier valid frontend response"
        assert lab.Observe() == (["/transparent", "/timeout"], ["/owned-resource"]), (
            "Timed-out proxy scan contacted an unselected backend or retried a frontend"
        )
        state = LocalModelStore(root).Open()
        assert state.revision == 1 and len(state.Objects(ObjectKind.ENDPOINT)) == 1 and (
            state.Objects(ObjectKind.ENDPOINT)[0].identity.key == urls[0]
        ), "Timeout destroyed earlier model facts or invented a second successful endpoint"
        workspace = LocalWorkspaceStore(root).Open()
        assert len(workspace.evidence_record_references) == 2, (
            "Original success/timeout acquisitions did not both survive the failed run"
        )
        store = LocalEvidenceStore(root / "evidence")
        raw = [json.loads(store.Read(store.Get(identity).reference))
               for identity in workspace.evidence_record_references]
        assert any(record == {"schema_version": 1, "error": "timeout"} for record in raw), (
            "Partial failure rewrote original timeout output into a successful worker record"
        )
        before = lab.Observe()
        status, reopened = Product(["workspace", "open", str(root)])
        assert status == 0 and reopened["verified_evidence_records"] == 2 and (
            lab.Observe() == before
        ), "Reopen cannot verify original partial state without new network access"


def test_FailedOracleComparisonStillRetainsOriginalSourceConfigurationAndEvidence(
    tmp_path, monkeypatch,
):
    """Unexpected regression truth remains reviewable instead of disappearing with an assertion."""

    case = Oracle()["cases"][0]
    written = []
    original = helpers.PreservePacket

    def Preserve(packet):
        """Observe only this worker's actual uniquely published artifact without directory races."""

        path = original(packet)
        written.append(path)

        return path

    monkeypatch.setattr(helpers, "PreservePacket", Preserve)

    with OwnedProxy() as lab:
        root = tmp_path / "workspace"
        Setup(root, (lab.Url(case),))
        status, summary = Product(Scan(root, (lab.Url(case),)))
        assert status == 0, "Original transparent fixture could not establish a real comparison"
        with pytest.raises(AssertionError, match="handwritten proxy oracle"):
            Verify(root, summary, {**case, "backend_hits": []}, lab)

        assert len(written) == 1, "Failed comparison did not retain one actual evidence packet"
        packet = json.loads(written[0].read_text())
        assert packet["product_summary"] == summary, "Original failed-comparison outcome changed"
        assert packet["profile"] == Oracle() and packet["test_only_backend_hits"] == [
            "/owned-resource"
        ] and packet["original_safe_worker_records"][0]["status"] == 200, (
            "Failed comparison hid original backend/worker truth or source version/configuration"
        )
        assert PRIVATE_MARKER not in json.dumps(packet), (
            "Failed comparison diagnostics copied private fixture response fields"
        )


def test_FixtureFailureReleasesStalledHandlerAndClosesBothOwnedListeners():
    """Even an interrupted test releases its waiting request and joins non-daemon handlers."""

    with pytest.raises(RuntimeError, match="controlled fixture failure"):
        with OwnedProxy() as lab:
            client = http.client.HTTPConnection("127.0.0.1", lab.frontend.server_port, timeout=1)

            try:
                client.request("GET", "/timeout")
                assert lab.stalled.wait(timeout=2), (
                    "Owned stalled handler did not receive its request"
                )

                raise RuntimeError("controlled fixture failure")

            finally:
                client.close()

    assert lab.frontend.fileno() == lab.backend.fileno() == -1 and all(
        not thread.is_alive() for thread in lab.request_threads
    ), "Failure cleanup left an owned listener or stalled handler active"


def test_PartialFixtureStartupFailureStopsTheAlreadyStartedServer(monkeypatch):
    """An unstarted frontend is closed without waiting on its never-running service loop."""

    started = []
    original = helpers.Thread.start

    def Start(thread):
        """Start the backend then refuse the frontend's actual owning thread creation."""

        started.append(thread)

        if len(started) == 2:
            raise RuntimeError("controlled startup failure")

        original(thread)

    monkeypatch.setattr(helpers.Thread, "start", Start)

    with pytest.raises(RuntimeError, match="controlled startup failure"):
        with OwnedProxy():
            pytest.fail("Partial proxy startup failure incorrectly yielded an active fixture")

    assert len(started) == 2 and not any(thread.is_alive() for thread in started), (
        "Partial proxy startup abandoned its already-started backend server"
    )
