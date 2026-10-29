# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Genuine installed raw Nmap CLI against only pytest-owned loopback listener and closed port."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from xml.etree import ElementTree

import pytest

from fuzzy1337.adapters import ImpactLevel, SerializeContract
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import LocalModelStore, ObjectKind
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy
from tests.functional.test_nmap_product_loopback import PINNED_VERSION, ScopedWorkspace

pytestmark = pytest.mark.skipif(os.environ.get("FUZZY1337_RUN_NMAP_ACCEPTANCE") != "1",
    reason="Genuine raw Nmap acceptance requires explicit installed-provider opt-in")
EVIDENCE = Path("functional-evidence/nmap-raw")


class OwnedHandler(BaseHTTPRequestHandler):
    """Answer native version probes using only a finite locally owned HTTP resource."""

    def do_GET(self):
        """Provide deterministic small local content for the native HTTP service probe."""

        self.send_response(200)
        self.send_header("Content-Length", "12")
        self.end_headers()
        self.wfile.write(b"owned local\n")

    def log_message(self, format, *args):
        """Keep untrusted native request strings out of test diagnostics."""


class OwnedServer(ThreadingHTTPServer):
    """Bound native HTTP probe read time and release all test-owned worker connections."""

    daemon_threads = True
    requests = 0

    def GetRequest(self):
        """Admit only loopback socket data with a bounded native-probe idle read."""

        connection, address = super().get_request()
        self.requests += 1
        connection.settimeout(0.5)

        return connection, address

    # socketserver owns this exact callback spelling.
    get_request = GetRequest


def Console(arguments):
    """Run the actual isolated installed product command with bounded native execution time."""

    return subprocess.run([sys.executable, "-I", "-m", "fuzzy1337", "raw", *arguments],
        capture_output=True, timeout=50, check=False)


@pytest.mark.parametrize("service", [False, True], ids=["tcp-connect", "light-services"])
def test_GenuineRawProfilesRetainExactArgvCustodyAndRelocatedOfflineReplay(tmp_path, service):
    """Genuine reports retain exact selected argv, explicit port facts and offline custody."""

    executable = os.environ.get("F1337_NMAP_TEST_EXECUTABLE")
    assert executable and Path(executable).is_absolute() and Path(executable).is_file(), (
        "Required genuine raw acceptance cannot skip an absent explicit pinned Nmap")
    root = tmp_path / "raw genuine workspace"
    ScopedWorkspace(root)
    policy = ImpactPolicy("owned-raw-nmap", maximum_impact=ImpactLevel.STANDARD,
        permissions=tuple(CapabilityPermission(capability, "native.nmap", ImpactLevel.STANDARD)
            for capability in ("network.tcp-connect", "network.service-discovery")))
    policy_path = root / "raw-policy.json"
    policy_path.write_text(SerializeContract(policy), encoding="utf-8")

    with OwnedServer(("127.0.0.1", 0), OwnedHandler) as server, socket.socket() as closed:
        closed.bind(("127.0.0.1", 0))
        opened, refused = server.server_address[1], closed.getsockname()[1]
        thread = threading.Thread(target=server.serve_forever)
        thread.start()

        try:
            native = ["127.0.0.1", "-oX", "-", "--host-timeout", "30s", "-p",
                f"{refused},{opened}", "-sT", "-Pn", "-n", "--unprivileged"]

            if service:
                native += ["--version-light", "-sV"]

            prefix = [str(root), "--tool", "nmap", "--scope", "local", "--owner",
                "operator:owned", "--policy", str(policy_path), "--executable", executable]
            plan_result = Console(["plan", *prefix, "--", *native])
            assert plan_result.returncode == 0, "Genuine raw native planning failed"
            plan = json.loads(plan_result.stdout)
            assert plan["invocation"]["argv"] == [executable, *native], (
                "Genuine plan must bind original reordered native tokens without canonical rewrite")
            assert plan["invocation"]["provider_version"] == PINNED_VERSION, (
                "Genuine raw health metadata must identify the pinned installed version")
            denied = Console(["run", *prefix, "--json", "--", *native])
            assert denied.returncode == 3 and not LocalModelStore(root).Open().objects, (
                "Unconfirmed genuine raw selection must remain denied without positive model facts")
            assert server.requests == 0, "Planning or denied work contacted the owned listener"
            result = Console(["run", *prefix, "--json", "--confirm-plan", plan["intent_sha256"],
                "--confirmation-reference", "approval:genuine-raw", "--", *native])
            assert result.returncode == 0, "Confirmed genuine raw installed command failed"
            summary = json.loads(result.stdout)

        finally:
            server.shutdown()
            thread.join(timeout=3)

        assert not thread.is_alive(), "Owned genuine HTTP server cleanup did not finish"

    assert summary["native_exit_code"] == 0 and summary["model_commit"] == "acknowledged", (
        "Genuine native zero requires acknowledged successful canonical persistence")
    store = LocalEvidenceStore(root / "evidence")
    records = {item["evidence"]["reference"]["role"]: item["evidence"]["evidence_id"]
        for item in summary["job"]["artifacts"]}
    assert set(records) == {"stdout", "stderr", "raw-cli-receipt"}, (
        "Genuine original stdout, stderr and receipt need distinct retained acquisition records")
    destination = EVIDENCE / ("service" if service else "tcp")
    destination.mkdir(parents=True, exist_ok=True)

    for role, identifier in records.items():
        record = store.Get(identifier)
        raw = store.Read(record.reference)
        assert hashlib.sha256(raw).hexdigest() == record.reference.sha256, (
            "Genuine retained original stream digest differs from its acquisition")
        assert record.provenance.tool_version == PINNED_VERSION, (
            "Genuine original acquisition must retain its actual observed provider version")
        (destination / (role + ".raw")).write_bytes(raw)

    stdout = store.Read(store.Get(records["stdout"]).reference)
    xml = ElementTree.fromstring(stdout)
    states = {int(item.attrib["portid"]): item.find("state").attrib["state"]
        for item in xml.findall("./host/ports/port")}
    assert xml.attrib["version"] == PINNED_VERSION and states[opened] == "open", (
        "Genuine original XML must identify the pinned native binary and owned listener")
    assert states.get(refused) == "closed" or any(
        item.attrib.get("state") == "closed" for item in xml.findall("./host/ports/extraports")), (
        "Independent bound non-listener must remain closed in actual original native output")
    model = LocalModelStore(root).Open()
    assert len(model.Objects(ObjectKind.HOST)) == 1 and not model.Objects(ObjectKind.FINDING), (
        "Genuine raw host/port/service facts must never invent vulnerability Findings")
    actual_ports = {int(item.attributes["number"]): item
        for item in model.Objects(ObjectKind.PORT)}
    assert set(actual_ports) == set(states), (
        "Grouped native counts invented individual Port objects")

    for number, item in actual_ports.items():
        assert item.attributes["state"] == states[number] and item.provenance, (
            "Canonical Port facts must match their actual original native evidence")

    relocated = tmp_path / "relocated genuine raw workspace"
    shutil.copytree(root, relocated)
    before = {str(path.relative_to(relocated)): path.read_bytes()
        for path in relocated.rglob("*") if path.is_file()}
    replay = Console(["replay", str(relocated), "--receipt", summary["receipt_id"]])
    assert replay.returncode == 0 and json.loads(replay.stdout)["state"] == "verified", (
        "Relocated genuine raw replay must verify original custody after owned target shutdown")
    assert before == {str(path.relative_to(relocated)): path.read_bytes()
        for path in relocated.rglob("*") if path.is_file()}, (
        "Genuine offline replay must not execute, refresh authority or write workspace bytes")
    (destination / "summary.json").write_bytes(result.stdout)
    (destination / "replay.json").write_bytes(replay.stdout)
