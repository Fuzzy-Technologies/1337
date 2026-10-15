# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Actual ordinary Quick Scan denial, partial-state and independent proxy-fixture evidence."""

from __future__ import annotations

import http.client
import json
import socket
import ssl
import threading
from threading import Thread

import pytest

from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import LocalModelStore, ObjectKind
from fuzzy1337.workspace import LocalWorkspaceStore
from tests import proxy_regression_helpers as helpers
from tests.proxy_regression_helpers import (
    PRIVATE_MARKER,
    Oracle,
    OwnedProxy,
    OwnedTls,
    Product,
    Scan,
    Setup,
    TlsCertificateOracle,
    TlsEvidencePacket,
    TlsOracle,
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


@pytest.mark.parametrize("mode", ["fatal-alert", "stalled-clienthello"])
def test_IndependentVerifyingTlsClientEstablishesNegotiationFixtureTruth(mode):
    """An ordinary verifying TLS client independently proves the finite refusal/stall fixture."""

    context = ssl.create_default_context()
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED, (
        "Independent fixture client disabled normal certificate/identity verification"
    )

    with OwnedTls(mode) as tls:
        connection = socket.create_connection(tls.listener.getsockname(), timeout=0.2)

        try:
            expected = ssl.SSLError if mode == "fatal-alert" else TimeoutError

            with pytest.raises(expected):
                context.wrap_socket(connection, server_hostname="127.0.0.1")

            assert tls.Observe() == {"connections": 1, "client_hellos": 1, "errors": []}, (
                "Independent TLS client did not encounter the declared negotiation barrier"
            )

        finally:
            connection.close()

    assert tls.listener.fileno() == -1, "Independent TLS fixture left its listener active"


@pytest.mark.parametrize("condition", ["unknown-consent", "excluded", "missing-safe-permission"])
@pytest.mark.parametrize("mode", ["fatal-alert", "untrusted-self-signed"])
def test_TlsDenialPrecedesAnyTcpConnectionOrClientHello(tmp_path, condition, mode):
    """TLS fixture metadata grants no current target consent or SAFE execution permission."""

    with OwnedTls(mode) as tls:
        root = tmp_path / "workspace"
        urls = (tls.Url(),)
        Setup(root, urls, granted=condition != "unknown-consent", excluded=condition == "excluded")
        status, summary = Product(Scan(root, urls, approved=condition != "missing-safe-permission",
                                      request_timeout=2))
        assert status == 3 and summary["job"]["failure"]["code"] == "authorization", (
            "TLS target overrode missing ordinary scope or explicit SAFE permission"
        )
        assert tls.Observe() == {"connections": 0, "client_hellos": 0, "errors": []} and (
            not LocalModelStore(root).Open().objects
            and not LocalWorkspaceStore(root).Open().evidence_record_references
        ), "Denied TLS scan connected, began TLS negotiation or fabricated acquisition evidence"


@pytest.mark.parametrize("case", TlsOracle()["cases"][:2] + TlsCertificateOracle()["cases"],
                         ids=lambda case: case["id"])
def test_LaterTlsFailurePreservesEarlierHttpFactsAndBothOriginalAcquisitions(tmp_path, case):
    """Real TLS refusal/timeout cannot erase a saved earlier frontend or invent a TLS endpoint."""

    with OwnedTls(case["mode"]) as tls, OwnedProxy() as proxy:
        root = tmp_path / "workspace"
        urls = (proxy.Url(Oracle()["cases"][0]), tls.Url())
        Setup(root, urls)
        status, summary = Product(Scan(root, urls, request_timeout=2))

        handled = case["mode"] != "untrusted-self-signed" or tls.handled.wait(timeout=3)
        packet = TlsEvidencePacket(root, summary, case, proxy, tls, preceding_http=True)
        assert handled, "Partial-state certificate attempt did not finish"
        assert status == 4 and summary["state"] == "failed" and (
            summary["job"]["failure"]["code"] == case["failure_code"]
        ), "Later TLS failure was hidden by an earlier successful HTTP observation"
        expected_contact = {"connections": 1, "client_hellos": 1, "errors": []}

        if case["mode"] == "untrusted-self-signed":
            expected_contact = {"connections": 1, "handshake_attempts": 1,
                "certificate_rejections": 1, "completed_handshakes": 0, "errors": []}

        assert packet["test_only_tls"] == expected_contact and (
            proxy.Observe() == (["/transparent"], ["/owned-resource"])
        ), "Partial TLS failure contacted an unselected target or repeated acquisition"
        state = LocalModelStore(root).Open()
        assert state.revision == 1 and [item.identity.key for item in state.Objects(
            ObjectKind.ENDPOINT
        )] == [urls[0]], "TLS failure destroyed the original frontend or fabricated a TLS endpoint"
        raw = packet["original_safe_worker_records"]
        assert len(raw) == 2 and {"schema_version": 1, "error": case["worker_error"]} in raw, (
            "Original HTTP success and safe TLS failure records did not both survive"
        )
        before = (tls.Observe(), proxy.Observe())
        status, reopened = Product(["workspace", "open", str(root)])
        assert status == 0 and reopened["verified_evidence_records"] == 2 and (
            before == (tls.Observe(), proxy.Observe())
        ), "Partial reopen cannot verify both original acquisitions without new contact"


def test_InterruptedTlsFixtureReleasesRealStalledHandshakeAndJoinsItsThread():
    """Exception teardown releases the actual TLS client and closes the owned listener."""

    client_errors = []
    client = None

    try:
        with pytest.raises(RuntimeError, match="controlled TLS fixture failure"):
            with OwnedTls("stalled-clienthello") as tls:
                address = tls.listener.getsockname()

                def Connect():
                    """Run a real verifying handshake until fixture teardown closes it."""

                    try:
                        with socket.create_connection(address, timeout=2) as connection:
                            with ssl.create_default_context().wrap_socket(
                                connection, server_hostname="127.0.0.1",
                            ):
                                client_errors.append("unexpected-success")

                    except OSError:
                        client_errors.append("expected-refusal")

                client = Thread(target=Connect, daemon=False)
                client.start()
                assert tls.client_hello.wait(timeout=3), "TLS cleanup fixture never got ClientHello"

                raise RuntimeError("controlled TLS fixture failure")

    finally:
        if client is not None:
            client.join(timeout=3)
            assert not client.is_alive(), "Interrupted TLS fixture abandoned its waiting client"

    assert tls.listener.fileno() == -1 and client_errors == ["expected-refusal"], (
        "Interrupted TLS fixture leaked its listener or incorrectly completed a handshake"
    )


@pytest.mark.parametrize("mode", ["fatal-alert", "untrusted-self-signed"])
def test_TlsFixtureStartupFailureClosesItsUnstartedListener(monkeypatch, mode):
    """Listener allocation is unwound even if its owning thread cannot start."""

    listeners = []
    original = helpers.socket.socket

    def Allocate(*args, **kwargs):
        """Observe only the fixture's real owned socket without replacing socket behavior."""

        listener = original(*args, **kwargs)
        listeners.append(listener)

        return listener

    def RefuseStart(thread):
        """Fail before any fixture server thread is running."""

        raise RuntimeError("controlled TLS startup failure")

    monkeypatch.setattr(helpers.socket, "socket", Allocate)
    monkeypatch.setattr(helpers.Thread, "start", RefuseStart)

    with pytest.raises(RuntimeError, match="controlled TLS startup failure"):
        with OwnedTls(mode):
            pytest.fail("TLS startup failure incorrectly exposed an active fixture")

    assert len(listeners) == 1 and listeners[0].fileno() == -1, (
        "TLS startup failure abandoned its allocated listener"
    )


@pytest.mark.parametrize("mode", ["fatal-alert", "untrusted-self-signed"])
def test_PartialTlsHeaderInterruptionClosesTheOwnedAcceptedSocket(mode):
    """Teardown interrupts incomplete ClientHello input without waiting for more peer bytes."""

    connection = None

    try:
        with pytest.raises(RuntimeError, match="controlled partial TLS header failure"):
            with OwnedTls(mode) as tls:
                connection = socket.create_connection(tls.listener.getsockname(), timeout=1)
                connection.sendall(b"\x16\x03")
                assert tls.accepted.wait(timeout=2), "Partial-header fixture accepted no connection"

                if mode == "untrusted-self-signed":
                    assert tls.handshake_started.wait(timeout=2), (
                        "Partial-header certificate fixture did not begin its actual TLS handshake"
                    )

                raise RuntimeError("controlled partial TLS header failure")

    finally:
        if connection is not None:
            connection.close()

    assert tls.listener.fileno() == -1 and tls.Observe() == {
        "connections": 1, "client_hellos": 0, "errors": [],
    }, "Partial-header teardown abandoned a socket/thread or invented complete TLS negotiation"

    if mode == "untrusted-self-signed":
        assert tls.ObserveCertificate() == {"connections": 1, "handshake_attempts": 1,
            "certificate_rejections": 0, "completed_handshakes": 0, "errors": []}, (
            "Interrupted certificate handshake fabricated a rejection or retained an active socket"
        )


def test_TlsTeardownBeforeHandshakeKeepsSslStateWithItsOwningThread(monkeypatch):
    """Actual TCP interruption cannot clear SSL state before its owner starts the handshake."""

    entered, peer_closed = threading.Event(), threading.Event()
    original = ssl.SSLSocket.do_handshake
    thread_errors, secure_sockets, owners, peer_results = [], [], [], []
    client, peer = None, None

    def HoldHandshake(connection, block=False):
        """Resume the actual handshake only after the peer observes real transport shutdown."""

        secure_sockets.append(connection)
        owners.append(threading.current_thread())
        entered.set()
        assert peer_closed.wait(timeout=3), "The peer never observed actual TCP interruption"

        return original(connection, block)

    def ObservePeer(connection):
        """Independently observe EOF or connection reset without releasing the fixture itself."""

        try:
            assert connection.recv(1) == b"", "Interrupted TLS fixture returned unexpected bytes"
            peer_results.append("eof")

        except ConnectionResetError:
            peer_results.append("reset")

        peer_closed.set()

    monkeypatch.setattr(ssl.SSLSocket, "do_handshake", HoldHandshake)
    monkeypatch.setattr(threading, "excepthook", thread_errors.append)

    try:
        with OwnedTls("untrusted-self-signed") as tls:
            client = socket.create_connection(tls.listener.getsockname(), timeout=2)
            client.sendall(b"\x16\x03")
            peer = Thread(target=ObservePeer, args=(client,), daemon=False)
            peer.start()
            assert entered.wait(timeout=2), "Certificate handshake never reached its real barrier"

    finally:
        if client is not None:
            client.close()

        if peer is not None:
            peer.join(timeout=3)
            assert not peer.is_alive(), "The independent peer observer was not reaped"

    assert not thread_errors, "TLS teardown caused an unhandled owning-thread exception"
    assert peer_results in (["eof"], ["reset"]), "No actual transport interruption was observed"
    assert len(secure_sockets) == len(owners) == 1 and secure_sockets[0].fileno() == -1, (
        "The owning server did not close its single wrapped TLS socket"
    )
    assert not owners[0].is_alive() and tls.listener.fileno() == -1, (
        "TLS teardown abandoned its serving thread or listener"
    )
    assert tls.handled.is_set() and tls.active_connection is None, "TLS ownership was not released"
    assert tls.ObserveCertificate() == {"connections": 1, "handshake_attempts": 1,
        "certificate_rejections": 0, "completed_handshakes": 0, "errors": []}, (
        "Interrupted certificate handshake fabricated a TLS result or lost lifecycle state"
    )


def test_InvalidTlsHeaderIsRecordedAsFixtureFailureWithoutUnobservedThreadError():
    """Unexpected wire input remains explicit test failure truth with deterministic cleanup."""

    with OwnedTls() as tls:
        with socket.create_connection(tls.listener.getsockname(), timeout=1) as connection:
            connection.sendall(b"wrong")
            assert tls.handled.wait(timeout=2), "Invalid-header fixture did not finish its handler"

        assert tls.Observe() == {"connections": 1, "client_hellos": 0,
            "errors": ["negotiation-fixture-failure"]}, (
            "Unexpected TLS input disappeared instead of retaining fixed fixture failure truth"
        )


def test_UnexpectedTlsListenerFailureRetainsExplicitFixtureError():
    """A closed listening socket becomes an observed failure instead of a lost thread exception."""

    with OwnedTls() as tls:
        tls.listener.close()
        assert tls.listener_failed.wait(timeout=2), "TLS listener failure remained unobserved"
        assert tls.Observe() == {"connections": 0, "client_hellos": 0,
            "errors": ["listener-failure"]}, (
            "Unexpected listening failure was hidden or misreported as a completed TLS contact"
        )


def test_IndependentVerifyingClientRejectsTheActualSelfSignedCertificate():
    """Unchanged trust and matching IP/lifetime yield a specific self-signed verification error."""

    context = ssl.create_default_context()
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED, (
        "Independent certificate oracle disabled ordinary chain or hostname verification"
    )

    with OwnedTls("untrusted-self-signed") as tls:
        with socket.create_connection(tls.listener.getsockname(), timeout=2) as connection:
            with pytest.raises(ssl.SSLCertVerificationError) as captured:
                context.wrap_socket(connection, server_hostname="127.0.0.1")

        assert captured.value.verify_code == TlsCertificateOracle()["certificate"][
            "independent_client_verify_code"
        ] == 18, "Independent client failure was not the expected self-signed chain rejection"
        assert tls.handled.wait(timeout=3), "Certificate target did not observe client rejection"
        assert tls.ObserveCertificate() == {"connections": 1, "handshake_attempts": 1,
            "certificate_rejections": 1, "completed_handshakes": 0, "errors": []}, (
            "Real server did not independently observe one rejected certificate handshake"
        )

    assert tls.listener.fileno() == -1 and tls.active_connection is None, (
        "Certificate rejection fixture retained a live listener, client or owning thread"
    )


def test_InvalidCertificateFixtureFailsBeforeAllocatingAListener(tmp_path, monkeypatch):
    """A broken test certificate cannot become a misleading generic network failure."""

    invalid = tmp_path / "invalid-certificate.pem"
    invalid.write_text("not a synthetic certificate", encoding="ascii")
    monkeypatch.setattr(helpers, "TLS_CERTIFICATE", invalid)
    allocations = []

    def RefuseSocket(*args, **kwargs):
        """Detect an attempted listener allocation after invalid fixture configuration."""

        allocations.append(True)

        raise AssertionError("Invalid certificate fixture allocated a listening socket")

    monkeypatch.setattr(helpers.socket, "socket", RefuseSocket)

    with pytest.raises(ssl.SSLError):
        with OwnedTls("untrusted-self-signed"):
            pytest.fail("Invalid certificate fixture became an active TLS target")

    assert not allocations, "Invalid certificate fixture reached network resource allocation"
