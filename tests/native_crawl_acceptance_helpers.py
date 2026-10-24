# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent installed-consumer lifecycle and handwritten crawl assertions; no parser truth."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4
from zipfile import ZipFile

import pytest

from tests.native_crawl_graph_helpers import (
    CrawlGraphOracle,
    OwnedCrawlGraph,
    OwnedNativeCrawlGraph,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONSUMER = Path(__file__).parent / "functional/native_crawl_installed_consumer.py"
MAX_STREAM_BYTES = 8 * 1024 * 1024
MAX_INSTALL_LOG_BYTES = 1024 * 1024
MAX_PROCESS_RECORDS = 128
SOURCE_MODULES = ("adapters/native_crawl.py", "native_crawl_worker.py", "native_crawl.py",
                  "native_crawl_workflow.py", "native_crawl_commands.py", "native_web.py")


def CanonicalNative(value: object) -> bytes:
    """Encode explicit independent input or retained original metadata with standard JSON only."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


@dataclass(slots=True)
class NativeCaseEvidence:
    """Own fixed per-case original evidence in scratch and the canonical CI artifact selection."""

    local: Path
    retained: Path
    sequence: int = 0

    def Write(self, name: str, data: bytes) -> None:
        """Mirror only bounded fixed test inputs/original evidence, never an entire runtime tree."""

        relative = Path(name)

        if relative.is_absolute() or ".." in relative.parts or len(relative.parts) > 3:
            raise ValueError("Native evidence requires a fixed owned relative path")

        if len(data) > 2 * MAX_STREAM_BYTES:
            raise ValueError("Native evidence exceeds its finite per-artifact ceiling")

        for root in (self.local, self.retained):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)

    def Json(self, name: str, value: object) -> None:
        """Preserve one standards-compliant metadata object in both owned artifact destinations."""

        self.Write(name, CanonicalNative(value))

    def NextProcess(self, label: str) -> str:
        """Allocate a bounded unique original subprocess record before any launch or assertion."""

        if re.fullmatch(r"[a-z][a-z0-9-]{0,47}", label) is None:
            raise ValueError("Native evidence labels are fixed source-owned identifiers")

        if self.sequence >= MAX_PROCESS_RECORDS:
            raise ValueError("Native case exceeded its finite subprocess evidence count")

        self.sequence += 1

        return f"process-{self.sequence:03d}-{label}"


@pytest.fixture(scope="session")
def native_acceptance_run() -> Path:
    """Allocate a unique safe CI-uploaded owner independently for each bounded pytest worker."""

    root = REPOSITORY_ROOT / "functional-evidence/native-crawl" / ("run-" + uuid4().hex)
    root.mkdir(parents=True)

    return root


@pytest.fixture
def native_case_evidence(request, tmp_path, native_acceptance_run) -> NativeCaseEvidence:
    """Give one pytest case its own mirrored original streams and final both-origin ledger."""

    identity = hashlib.sha256(request.node.nodeid.encode("utf-8")).hexdigest()[:20]
    retained = native_acceptance_run / ("case-" + identity + "-" + uuid4().hex[:8])
    owner = NativeCaseEvidence(tmp_path / "original-evidence", retained)
    owner.Json("case.json", {"schema_version": 1, "pytest_case": request.node.nodeid})

    return owner


def NativeProcess(
    owner: NativeCaseEvidence, label: str, argv: tuple[str, ...], *, cwd: Path,
    environment: dict[str, str], timeout: int, maximum: int = MAX_STREAM_BYTES,
    installation: dict | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Retain original process facts before caller assertions, decoding or timeout escape."""

    prefix = owner.NextProcess(label)
    metadata = {"schema_version": 1, "argv": list(argv), "cwd": str(cwd),
        "timeout_seconds": timeout, "stdin": "closed-devnull", "state": "not-launched",
        "returncode": None, "terminal_return_observed": False,
        "installation": installation}
    owner.Json(prefix + "/invocation.json", metadata)
    stdout: bytes | None = None
    stderr: bytes | None = None

    try:
        result = subprocess.run(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=timeout, check=False)
        stdout, stderr = result.stdout, result.stderr
        metadata.update(state="returned", returncode=result.returncode,
                        terminal_return_observed=True)

    except subprocess.TimeoutExpired as error:
        stdout, stderr = error.stdout, error.stderr
        metadata.update(state="timeout", exception_type=type(error).__name__)

        raise

    except OSError as error:
        metadata.update(state="launch-failed", exception_type=type(error).__name__)

        raise

    finally:
        for role, raw in (("stdout", stdout), ("stderr", stderr)):
            metadata[role] = {"observed": raw is not None,
                "observed_size_bytes": None if raw is None else len(raw),
                "observed_sha256": None if raw is None else hashlib.sha256(raw).hexdigest(),
                "retained_size_bytes": 0 if raw is None else min(len(raw), maximum),
                "complete_original": raw is not None and len(raw) <= maximum and
                    metadata["state"] == "returned",
                "timeout_prefix": metadata["state"] == "timeout" and raw is not None,
                "retention_overflow": raw is not None and len(raw) > maximum}

            if raw is not None:
                owner.Write(prefix + "/" + role + ".bin", raw[:maximum])

        owner.Json(prefix + "/process.json", metadata)

    assert len(result.stdout) <= maximum and len(result.stderr) <= maximum, (
        "Original subprocess output exceeded bounded retention; recorded prefix is incomplete."
    )

    return result


def NativeInstallation(python: Path) -> dict:
    """Read the fixture-owned actual wheel/source binding rather than inferring package identity."""

    path = python.parents[2] / "installation.json"
    raw = path.read_bytes()

    return {"manifest_sha256": hashlib.sha256(raw).hexdigest(), "identity": json.loads(raw)}


def FinalNativeTargetFacts(target: OwnedCrawlGraph | None) -> dict:
    """Read actual post-cleanup facts; an unyielded target remains explicitly unobserved."""

    if target is None:
        return {"schema_version": 1, "target_yielded": False, "owner_state": "unobserved"}

    main = target.state.Counters()
    sentinel = target.sentinel_state.Counters()
    alive = {"main": target.thread.is_alive(), "sentinel": target.sentinel_thread.is_alive()}
    settled = not any(alive.values()) and all(counters[name] == 0
        for counters in (main, sentinel)
        for name in ("active_connections", "active_handlers", "active_dispatches"))

    return {"schema_version": 1, "target_yielded": True,
        "owner_state": "settled" if settled else "unsettled", "listener_alive": alive,
        "main": {"origin": target.graph.origin, "contacts": [item.ToDict() for item in
            target.state.Observe()], "counters": main, "errors": list(target.state.Errors())},
        "sentinel": {"origin": target.sentinel_origin, "contacts": [item.ToDict() for item in
            target.sentinel_state.Observe()], "counters": sentinel,
            "errors": list(target.sentinel_state.Errors())}}


def NativeEnvironment(root: Path) -> dict[str, str]:
    """Isolate actual installed-consumer home/config/cache/temp state without capability fakes."""

    environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "PATH")
                   if key in os.environ}

    for name, directory in (("HOME", "home"), ("XDG_CONFIG_HOME", "config"),
                            ("XDG_CACHE_HOME", "cache"), ("XDG_DATA_HOME", "data"),
                            ("TMPDIR", "tmp"), ("TMP", "tmp"), ("TEMP", "tmp")):
        path = root / directory
        path.mkdir(parents=True, exist_ok=True)
        environment[name] = str(path)

    return environment


@pytest.fixture(scope="module")
def installed_native_crawl(tmp_path_factory, native_acceptance_run) -> Path:
    """Retain bounded original install logs, source checkpoint and actual wheel digest."""

    root = tmp_path_factory.mktemp("installed-native-crawl")
    owner = NativeCaseEvidence(root / "build-evidence",
        native_acceptance_run / ("installation-" + uuid4().hex))
    environment = NativeEnvironment(root / "owned-state")
    status = NativeProcess(owner, "source-status", ("git", "status", "--porcelain"),
        cwd=REPOSITORY_ROOT, environment=environment, timeout=5, maximum=MAX_INSTALL_LOG_BYTES)
    checkpoint = NativeProcess(owner, "source-checkpoint",
        ("git", "rev-parse", "HEAD", "HEAD^{tree}"),
        cwd=REPOSITORY_ROOT, environment=environment, timeout=5, maximum=MAX_INSTALL_LOG_BYTES)
    assert status.returncode == checkpoint.returncode == 0 and status.stdout == b"", (
        "Genuine installed acceptance requires an actual clean immutable source composition."
    )
    commit, tree = checkpoint.stdout.decode("ascii").split()
    sources = {name: hashlib.sha256(
        (REPOSITORY_ROOT / "src/fuzzy1337" / name).read_bytes()).hexdigest()
               for name in SOURCE_MODULES}
    identity = {"schema_version": 1, "source_commit": commit, "source_tree": tree,
                "source_modules_sha256": sources}
    owner.Json("source-checkpoint.json", identity)
    wheel_directory = root / "wheel"
    wheel_directory.mkdir()
    built = NativeProcess(owner, "build",
        (sys.executable, "-m", "build", "--wheel", "--no-isolation",
        "--outdir", str(wheel_directory)), cwd=REPOSITORY_ROOT, environment=environment,
        timeout=40, maximum=MAX_INSTALL_LOG_BYTES)
    assert built.returncode == 0, "Wheel build failed; original logs retained."
    wheels = tuple(wheel_directory.glob("*.whl"))
    assert len(wheels) == 1, "Acceptance requires exactly one freshly built actual package wheel."
    wheel = wheels[0]
    assert wheel.stat().st_size <= 32 * 1024 * 1024, "Actual wheel exceeds its finite ceiling."
    identity.update(wheel_name=wheel.name, wheel_size_bytes=wheel.stat().st_size,
                    wheel_sha256=hashlib.sha256(wheel.read_bytes()).hexdigest())

    with ZipFile(wheel) as archive:
        assert all(archive.getinfo("fuzzy1337/" + name).file_size <= 1024 * 1024
            for name in SOURCE_MODULES), "Wheel module exceeded its source ceiling."
        members = {name: hashlib.sha256(archive.read("fuzzy1337/" + name)).hexdigest()
                   for name in SOURCE_MODULES}

    identity["wheel_modules_sha256"] = members
    owner.Json("wheel-identity.json", identity)
    assert members == sources, "Wheel bytes must equal exact checkpoint source."
    venv = root / "environment"
    created = NativeProcess(owner, "create-interpreter", (sys.executable, "-m", "venv", str(venv)),
        cwd=root, environment=environment, timeout=40, maximum=MAX_INSTALL_LOG_BYTES)
    assert created.returncode == 0, "Clean interpreter creation failed; original logs retained."
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    installed = NativeProcess(owner, "install", (str(python), "-I", "-B", "-m", "pip", "--isolated",
        "install", "--no-index", "--no-deps", "--no-compile", "--disable-pip-version-check",
        str(wheel)), cwd=root, environment=environment, timeout=40, maximum=MAX_INSTALL_LOG_BYTES)
    assert installed.returncode == 0, "Wheel installation failed; original logs retained."
    probe_input = root / "import-probe.json"
    probe_input.write_bytes(CanonicalNative({"workspace": str(root / "unused-probe-workspace")}))
    owner.Write("import-probe-input.json", probe_input.read_bytes())
    probe = NativeProcess(owner, "import-identity",
        (str(python), "-I", "-B", str(CONSUMER), "identity", str(probe_input)), cwd=root,
        environment=environment, timeout=10, maximum=MAX_INSTALL_LOG_BYTES,
        installation={"identity": identity})
    assert probe.returncode == 0 and probe.stderr == b"", (
        "The actual installed capability/import probe failed; original process evidence retained."
    )
    imported = json.loads(probe.stdout)
    actual_modules = {name: value["sha256"]
                      for name, value in imported["installed_sources"].items()}
    assert actual_modules == members, "Installed source hashes must match the original wheel."
    identity.update(installed_sources=imported["installed_sources"],
                    distribution_version=imported["distribution_version"])
    (root / "installation.json").write_bytes(CanonicalNative(identity))
    owner.Json("installation.json", identity)

    return python


@contextmanager
def NativeAcceptanceGraph(evidence: NativeCaseEvidence) -> Iterator[OwnedCrawlGraph]:
    """Always persist original post-cleanup facts, including caller and process failures."""

    target = None

    try:
        with OwnedNativeCrawlGraph() as target:
            yield target

            assert target.state.WaitIdle() and target.sentinel_state.WaitIdle(), (
                "Both actual origin owners must settle before leaving the target context."
            )

    finally:
        final = FinalNativeTargetFacts(target)
        evidence.Json("target-final.json", final)

    assert final["owner_state"] == "settled", "Every original target owner must actually settle."
    assert final["main"]["errors"] == [] and final["main"]["counters"]["contact_overflow"] == 0, (
        "Main-origin cleanup failures or omitted contacts invalidate acceptance."
    )
    counters = final["sentinel"]["counters"]
    assert counters["contacts"] == counters["contact_overflow"] == 0 and (
        final["sentinel"]["contacts"] == [] and final["sentinel"]["errors"] == []
    ), "Off-origin exclusion requires its own zero original accept-time facts after cleanup."


def NativeConsumer(
    python: Path, directory: Path, mode: str, config: dict[str, Any], evidence: NativeCaseEvidence,
) -> dict:
    """Retain original consumer input/argv/result before checking or decoding streams."""

    directory.mkdir(parents=True, exist_ok=True)
    name = "consumer-input-" + uuid4().hex + ".json"
    path = directory / name
    raw_input = CanonicalNative(config)
    path.write_bytes(raw_input)
    evidence.Write(name, raw_input)
    installation = NativeInstallation(python)
    result = NativeProcess(evidence, "consumer-" + mode,
        (str(python), "-I", "-B", str(CONSUMER), mode, str(path)), cwd=directory,
        environment=NativeEnvironment(directory / "owned-state"), timeout=45,
        installation=installation)
    assert result.returncode == 0 and result.stderr == b"", (
        "Required genuine installed SDK consumer failed; original argv/streams/status retained."
    )
    output = json.loads(result.stdout)
    assert CanonicalNative(output) == result.stdout, "Consumer JSON must remain canonical."
    assert "/site-packages/fuzzy1337/" in output["installed_module"].replace("\\", "/") or (
        "/Lib/site-packages/fuzzy1337/" in output["installed_module"].replace("\\", "/")
    ), "The genuine consumer must import its clean wheel, never checkout/editable source."
    observed = {name: item["sha256"] for name, item in output["installed_sources"].items()}
    assert observed == installation["identity"]["wheel_modules_sha256"], (
        "Actual installed module source identities must equal the retained tested wheel identity."
    )
    evidence.Json("consumer-import-identity.json", {"installed_module": output["installed_module"],
        "installed_sources": output["installed_sources"],
        "distribution_version": output["distribution_version"], "installation": installation})

    return output


def NativeConfig(target: OwnedCrawlGraph, workspace: Path, **options: Any) -> dict[str, Any]:
    """Bind the independent seed/selection to one owned consumer workspace without remote
    control."""

    return {"workspace": str(workspace), "seed_url": target.graph.Url("/entry"),
            "selected_urls": list(target.graph.SelectedUrls()), **options}


def NativeInput(target: OwnedCrawlGraph, source_path: str) -> dict[str, Any]:
    """Handwrite the immutable worker input grammar without production input helper constants."""

    return {"schema_version": 1, "profile": "owned-loopback-content-crawl.v1",
        "workspace_id": "native-crawl-acceptance", "seed_url": target.graph.Url("/entry"),
        "source_url": target.graph.Url(source_path),
        "selected_urls": list(target.graph.SelectedUrls()), "max_body_bytes": 16384,
        "request_timeout_ms": 3000}


def NativeGet(origin: str, path: str) -> bytes:
    """Handwrite exact anonymous GET bytes independently of any production wire builder."""

    return (f"GET {path} HTTP/1.1\r\nHost: {urlsplit(origin).netloc}\r\n"
        "Connection: close\r\nAccept: text/html, text/plain, application/octet-stream\r\n"
        "Accept-Encoding: identity\r\n\r\n").encode("ascii")


def AssertNativeWireMetadata(record: dict, wire: bytes, expected: dict) -> None:
    """Compare closed metadata to original ASCII/CRLF framing and handwritten truth."""

    assert set(record) == {"schema_version", "profile", "outcome", "input_sha256",
        "selected_urls_sha256", "source", "response", "frontier"}, (
            "An admitted original record must have exactly the closed observed fields."
        )
    assert type(record["schema_version"]) is int and record["schema_version"] == 1 and (
        record["profile"] == "owned-loopback-content-crawl.v1"
    ), "Original worker schema/profile must match the independently declared contract."
    response = record["response"]
    assert set(response) == {"http_version", "status", "media_type", "header_bytes",
        "header_fields",
        "body_bytes", "body_sha256"}, "Original response shape must stay closed."
    header, body = wire.split(b"\r\n\r\n", 1)
    status_line, *field_lines = header.decode("ascii").split("\r\n")
    version, status, _reason = status_line.split(" ", 2)
    fields = [line.split(":", 1) for line in field_lines]
    headers = {name.lower(): value.strip(" \t") for name, value in fields}
    media = headers["content-type"].split(";", 1)[0].strip().lower()
    assert len(fields) == len(headers) and int(headers["content-length"]) == len(body), (
        "The independently served complete wire must have unique fields and exact body framing."
    )
    assert (int(status), media, record["outcome"]) == (
        expected["status"], expected["media_type"], expected["outcome"]
    ), "Original status/media and worker outcome must match handwritten response truth."
    assert type(response["status"]) is int and response["status"] == int(status) and (
        response["http_version"] == version and type(response["header_fields"]) is int
        and response["header_fields"] == len(field_lines)
        and response["media_type"] == media
        and type(response["header_bytes"]) is int and response["header_bytes"] == len(header) + 4
        and type(response["body_bytes"]) is int and response["body_bytes"] == len(body)
        and response["body_sha256"] == hashlib.sha256(body).hexdigest()
    ), "Every declared response fact must match the actual complete independently served wire."

    if "body" in expected:
        assert body == expected["body"].encode("ascii"), "Leaf bytes must match hand truth."

    frontier = record["frontier"]
    assert set(frontier) == {"complete", "anchor_count", "entries", "exclusion_counts"} and (
        frontier["complete"] is True and type(frontier["anchor_count"]) is int
    ), "Original frontier shape must be closed and explicitly complete, never partial."
    counters = frontier["exclusion_counts"]
    assert set(counters) == {"missing-href", "invalid-url", "fragment-only", "non-http",
        "credentials", "query", "off-origin", "unsupported-path", "source-target",
        "not-admitted"}, (
            "Original exclusion counters must have exactly the independently declared closed keys."
        )
    assert all(type(value) is int and value >= 0 for value in counters.values()), (
        "Original exclusion counts must be exact nonnegative integers."
    )
    ordinals = []

    for entry in frontier["entries"]:
        assert set(entry) == {"url", "request_reference", "endpoint_reference", "ordinals"}, (
            "Every original candidate must preserve its closed URL/reference/ordinal shape."
        )
        values = entry["ordinals"]
        assert values and values == sorted(set(values)) and all(type(value) is int and value > 0
            for value in values), "Original ordinals must be sorted distinct positive integers."
        ordinals.extend(values)

    assert len(ordinals) == len(set(ordinals)) and len(ordinals) + sum(counters.values()) == (
        frontier["anchor_count"]), "Original complete slot ownership must account for every anchor."


def AssertNativeRecord(record: dict, document: dict, contact, *, variant: str) -> None:
    """Compare actual original bytes and handwritten links/slots, never production parser output."""

    oracle = CrawlGraphOracle()
    source = urlsplit(document["source_url"])
    assert type(record["schema_version"]) is int and record["schema_version"] == 1 and (
        record["profile"] == oracle["profile"]
    ), (
        "The actual installed worker must use its declared finite record contract."
    )
    assert contact.request_bytes == NativeGet(f"http://{source.netloc}", source.path), (
        "The original GET must contain only the exact selected anonymous request grammar."
    )
    assert contact.sent_bytes == len(contact.response_bytes) and contact.completion_sequence, (
        "A completed target response must have actual full-send and completion evidence."
    )
    expected_response = oracle["leaf_responses"].get(source.path,
        {"status": 200, "media_type": "text/html", "outcome": "html"})
    AssertNativeWireMetadata(record, contact.response_bytes, expected_response)
    assert set(record["source"]) == {"url", "address", "port", "request_reference",
        "endpoint_reference", "request_size_bytes", "request_sha256"}, (
            "Original source metadata must have exactly its selected peer/request fields."
        )
    for key, prefix in (("request_reference", "request"), ("endpoint_reference", "object")):
        assert re.fullmatch(prefix + r":[0-9a-f]{64}", record["source"][key]) is not None, (
            "Original source references must preserve their existing typed identity namespaces."
        )
    assert record["input_sha256"] == hashlib.sha256(CanonicalNative(document)).hexdigest() and (
        record["selected_urls_sha256"] == hashlib.sha256(
            CanonicalNative(document["selected_urls"])).hexdigest()
    ), "The original report must bind the exact sole argv input and immutable admitted URL set."
    assert record["source"]["url"] == document["source_url"] and (
        record["source"]["request_sha256"] == hashlib.sha256(contact.request_bytes).hexdigest()
        and record["source"]["request_size_bytes"] == len(contact.request_bytes)
        and record["source"]["address"] == source.hostname
        and record["source"]["port"] == source.port
    ), "Reported request and peer observations must match this actual original contact."
    response = record["response"]
    frontier = record["frontier"]
    expected = oracle["variants"][variant].get("expected_frontiers", {}).get(source.path)

    if expected is not None:
        entries = [{"path": urlsplit(item["url"]).path, "ordinals": item["ordinals"]}
                   for item in frontier["entries"]]
        assert (frontier["anchor_count"], entries, frontier["exclusion_counts"]) == (
            expected["anchor_count"], expected["entries"], expected["exclusion_counts"]
        ), "Original candidate/slot/exclusion output differs from independently handwritten truth."

    elif source.path == "/entry":
        assert frontier["anchor_count"] == oracle["variants"][variant]["seed_anchor_count"], (
            "Changing bytes at the same seed must change its actual lexical frontier."
        )
        expected_paths = ["/redirect"] if variant == "redirect" else []
        assert [urlsplit(item["url"]).path for item in frontier["entries"]] == expected_paths, (
            "Fixed/decoy/redirect seeds must retain only their independently declared edges."
        )

    else:
        expected_leaf = oracle["leaf_responses"].get(source.path)

        if expected_leaf is not None:
            assert (record["outcome"], response["status"], response["media_type"]) == (
                expected_leaf["outcome"], expected_leaf["status"], expected_leaf["media_type"]
            ), "Terminal page observations must not become vulnerability-negative scanner results."

        assert frontier["anchor_count"] == 0 and frontier["entries"] == [] and not any(
            frontier["exclusion_counts"].values()), "Terminal frontier must be exactly empty."

    encoded = CanonicalNative(record)
    assert all(marker.encode() not in encoded for marker in oracle["transient_markers"]), (
        "Rejected transient href markers must never survive original worker output."
    )


def AssertZeroNativeContact(target: OwnedCrawlGraph) -> None:
    """Require exact accept-time counters, bounded records and overflow to prove no contact."""

    counters = target.state.Counters()
    assert counters["contacts"] == 0 and counters["retained_contacts"] == 0 and (
        counters["contact_overflow"] == 0
    ), (
        "Denied work must cause zero original accepts, including partial/refused/overflow contacts."
    )
    assert target.state.Observe() == () and target.state.Errors() == (), (
        "No target mechanism error may hide an unobserved contact."
    )


def NativeIpv6Wire() -> bytes:
    """Handwrite one complete bounded terminal response for the declared literal IPv6 profile."""

    body = b"owned-ipv6-terminal\n"

    return (f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n"
        "Content-Type: text/plain\r\nConnection: close\r\n\r\n").encode("ascii") + body


@contextmanager
def NativeIpv6Terminal(evidence: NativeCaseEvidence) -> Iterator[Any]:
    """Reuse the reviewed one-thread fixed-wire IPv6 fixture, preserving actual cleanup facts."""

    from tests.integration.test_owned_response_worker_execution import OwnedResponseListener

    listener = None

    try:
        listener = OwnedResponseListener(NativeIpv6Wire(), address="::1")

        yield listener

    finally:
        try:
            if listener is not None:
                listener.Close()

        finally:
            facts = {"schema_version": 1, "target_yielded": listener is not None,
                     "owner_state": "unobserved"}

            if listener is not None:
                facts.update(owner_state="unsettled" if listener.thread.is_alive() else "settled",
                    listener_alive=listener.thread.is_alive(), original_accepts=listener.accepted,
                    original_requests_hex=[raw.hex() for raw in listener.requests],
                    source_wire_sha256=hashlib.sha256(listener.wire).hexdigest(),
                    source_wire_size_bytes=len(listener.wire))

            evidence.Json("ipv6-target-final.json", facts)


@contextmanager
def NativeHeldCancellation(evidence: NativeCaseEvidence, readiness: Path) -> Iterator[Any]:
    """Reuse the accepted held-response readiness/peer-EOF fixture without a generic new server."""

    from tests.integration.test_owned_response_product import HeldResponseListener

    listener = None

    try:
        listener = HeldResponseListener(readiness)

        yield listener

    finally:
        try:
            if listener is not None:
                listener.Close()

        finally:
            facts = {"schema_version": 1, "target_yielded": listener is not None,
                     "owner_state": "unobserved"}

            if listener is not None:
                facts.update(owner_state="unsettled" if listener.thread.is_alive() else "settled",
                    listener_alive=listener.thread.is_alive(), original_accepts=listener.accepted,
                    original_requests_hex=[raw.hex() for raw in listener.requests],
                    peer_closed=listener.peer_closed, hold_expired=listener.hold_expired)

            evidence.Json("cancel-target-final.json", facts)
