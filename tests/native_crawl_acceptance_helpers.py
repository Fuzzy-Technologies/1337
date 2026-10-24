# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent installed-consumer lifecycle and handwritten crawl assertions; no parser truth."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

from tests.native_crawl_graph_helpers import (
    CrawlGraphOracle,
    OwnedCrawlGraph,
    OwnedNativeCrawlGraph,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONSUMER = Path(__file__).parent / "functional/native_crawl_installed_consumer.py"


def CanonicalNative(value: object) -> bytes:
    """Encode explicit independent input or retained original metadata with standard JSON only."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


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
def installed_native_crawl(tmp_path_factory) -> Path:
    """Build/install the actual current wheel offline; missing required tools fail acceptance."""

    root = tmp_path_factory.mktemp("installed-native-crawl")
    environment = NativeEnvironment(root / "owned-state")
    wheel_directory = root / "wheel"
    wheel_directory.mkdir()
    built = subprocess.run((sys.executable, "-m", "build", "--wheel", "--no-isolation",
        "--outdir", str(wheel_directory)), cwd=REPOSITORY_ROOT, env=environment,
        capture_output=True, timeout=40, check=False)
    assert built.returncode == 0, "Required native crawl wheel build failed: " + repr(built.stderr)
    wheels = tuple(wheel_directory.glob("*.whl"))
    assert len(wheels) == 1, "Acceptance requires exactly one freshly built actual package wheel."
    venv = root / "environment"
    created = subprocess.run((sys.executable, "-m", "venv", str(venv)), env=environment,
        capture_output=True, timeout=40, check=False)
    assert created.returncode == 0, "Clean interpreter creation failed: " + repr(created.stderr)
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    installed = subprocess.run((str(python), "-I", "-B", "-m", "pip", "--isolated", "install",
        "--no-index", "--no-deps", "--no-compile", "--disable-pip-version-check", str(wheels[0])),
        cwd=root, env=environment, capture_output=True, timeout=40, check=False)
    assert installed.returncode == 0, "Wheel installation failed: " + repr(installed.stderr)

    return python


@contextmanager
def NativeAcceptanceGraph() -> Iterator[OwnedCrawlGraph]:
    """Require both original owners and independently counted sentinel exclusion after cleanup."""

    with OwnedNativeCrawlGraph() as target:
        yield target

        assert target.state.WaitIdle() and target.sentinel_state.WaitIdle(), (
            "Both actual origin owners must settle before leaving the target context."
        )

    counters = target.sentinel_state.Counters()
    assert counters["contacts"] == counters["contact_overflow"] == 0 and (
        target.sentinel_state.Observe() == () and target.sentinel_state.Errors() == ()
    ), "Off-origin exclusion requires its own zero original accept-time facts after cleanup."
    assert not target.thread.is_alive() and not target.sentinel_thread.is_alive() and (
        counters["active_connections"] == counters["active_handlers"] ==
        counters["active_dispatches"] == 0
    ), "Both original listeners and all sentinel socket/handler/slot owners must settle."


def NativeConsumer(python: Path, directory: Path, mode: str, config: dict[str, Any]) -> dict:
    """Run only the fixed actual installed SDK consumer, retaining exact original process
    streams."""

    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (mode + ".json")
    path.write_bytes(CanonicalNative(config))
    result = subprocess.run((str(python), "-I", "-B", str(CONSUMER), mode, str(path)),
        cwd=directory, env=NativeEnvironment(directory / "owned-state"), stdin=subprocess.DEVNULL,
        capture_output=True, timeout=45, check=False)
    assert result.returncode == 0 and result.stderr == b"", (
        "Required genuine installed SDK consumer failed: " + repr(result.stderr)
    )
    output = json.loads(result.stdout)
    assert CanonicalNative(output) == result.stdout, "Consumer JSON must remain canonical."
    assert "/site-packages/fuzzy1337/" in output["installed_module"].replace("\\", "/") or (
        "/Lib/site-packages/fuzzy1337/" in output["installed_module"].replace("\\", "/")
    ), "The genuine consumer must import its clean wheel, never checkout/editable source."

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


def AssertNativeRecord(record: dict, document: dict, contact, *, variant: str) -> None:
    """Compare actual original bytes and handwritten links/slots, never production parser output."""

    oracle = CrawlGraphOracle()
    source = urlsplit(document["source_url"])
    assert record["schema_version"] == 1 and record["profile"] == oracle["profile"], (
        "The actual installed worker must use its declared finite record contract."
    )
    assert contact.request_bytes == NativeGet(f"http://{source.netloc}", source.path), (
        "The original GET must contain only the exact selected anonymous request grammar."
    )
    assert contact.sent_bytes == len(contact.response_bytes) and contact.completion_sequence, (
        "A completed target response must have actual full-send and completion evidence."
    )
    header, body = contact.response_bytes.split(b"\r\n\r\n", 1)
    assert record["input_sha256"] == hashlib.sha256(CanonicalNative(document)).hexdigest() and (
        record["selected_urls_sha256"] == hashlib.sha256(
            CanonicalNative(document["selected_urls"])).hexdigest()
    ), "The original report must bind the exact sole argv input and immutable admitted URL set."
    assert record["source"]["url"] == document["source_url"] and (
        record["source"]["request_sha256"] == hashlib.sha256(contact.request_bytes).hexdigest()
        and record["source"]["request_size_bytes"] == len(contact.request_bytes)
        and record["source"]["address"] == "127.0.0.1"
        and record["source"]["port"] == source.port
    ), "Reported request and peer observations must match this actual original contact."
    response = record["response"]
    assert response["body_sha256"] == hashlib.sha256(body).hexdigest() and (
        response["body_bytes"] == len(body) and response["header_bytes"] == len(header) + 4
    ), "Reported body/header attribution must match actual complete served bytes."
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
