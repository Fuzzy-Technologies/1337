# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Genuine isolated installed native crawl worker against independent mutable original bytes."""

from __future__ import annotations

import json
import subprocess

import pytest

from tests.native_crawl_acceptance_helpers import (
    AssertNativeRecord,
    AssertZeroNativeContact,
    CanonicalNative,
    NativeAcceptanceGraph,
    NativeEnvironment,
    NativeInput,
)
from tests.native_crawl_acceptance_helpers import installed_native_crawl as installed_native_crawl


@pytest.mark.integration
@pytest.mark.parametrize("variant,source", [
    ("positive", "/entry"), ("fixed", "/entry"), ("decoy", "/entry"),
    ("redirect", "/entry"), ("positive", "/branch-a"), ("positive", "/branch-b"),
    ("positive", "/shared"), ("positive", "/leaf/.git/HEAD"),
    ("positive", "/fixed/.git/HEAD"), ("positive", "/html/.git/HEAD"),
])
def test_InstalledWorkerBindsActualGetBodyAndHandwrittenFrontier(
    installed_native_crawl, tmp_path, variant, source,
) -> None:
    """Run the fixed packaged worker with one exact argv object and closed stdin, without mocks."""

    with NativeAcceptanceGraph() as target:
        target.state.SetVariant(variant)
        document = NativeInput(target, source)
        argument = CanonicalNative(document).decode("ascii")
        argv = (str(installed_native_crawl), "-I", "-m", "fuzzy1337.native_crawl_worker", argument)
        result = subprocess.run(argv, cwd=tmp_path,
            env=NativeEnvironment(tmp_path / "owned-state"), stdin=subprocess.DEVNULL,
            capture_output=True, timeout=8, check=False)
        assert target.state.WaitIdle(), "Worker left original target owners active."
        assert result.returncode == 0 and result.stderr == b"", (
            "Required actual worker acquisition failed: " + repr(result.stderr)
        )
        record = json.loads(result.stdout)
        assert CanonicalNative(record) == result.stdout, (
            "The actual original stdout must be canonical ASCII JSON without a newline."
        )
        assert len(target.state.Observe()) == target.state.Counters()["contacts"] == 1, (
            "One packaged worker may make exactly one original selected GET, without followups."
        )
        AssertNativeRecord(record, document, target.state.Observe()[0], variant=variant)
        assert not target.state.Errors(), "The genuine owned target mechanism reported a failure."


@pytest.mark.integration
@pytest.mark.parametrize("arguments", [(), ("{}",), ("--help",), ("{}", "{}")])
def test_InstalledWorkerInputRefusalMakesZeroOriginalContact(
    installed_native_crawl, tmp_path, arguments,
) -> None:
    """Missing, malformed or alternate argv fails closed rather than selecting a fallback target."""

    with NativeAcceptanceGraph() as target:
        result = subprocess.run((str(installed_native_crawl), "-I", "-m",
            "fuzzy1337.native_crawl_worker", *arguments), cwd=tmp_path,
            env=NativeEnvironment(tmp_path / "owned-state"), stdin=subprocess.DEVNULL,
            capture_output=True, timeout=8, check=False)
        assert (result.returncode, result.stderr, result.stdout) == (2, b"", CanonicalNative({
            "schema_version": 1, "profile": "owned-loopback-content-crawl.v1",
            "outcome": "refused", "error": "input"})), (
                "The actual installed worker must emit only its exact closed input refusal."
            )
        AssertZeroNativeContact(target)


@pytest.mark.integration
def test_InstalledWorkerRedirectRefusesWithoutDestinationContact(
    installed_native_crawl, tmp_path,
) -> None:
    """A selected redirect returns a truthful refusal with no body digest or follow-up request."""

    with NativeAcceptanceGraph() as target:
        argument = CanonicalNative(NativeInput(target, "/redirect")).decode("ascii")
        result = subprocess.run((str(installed_native_crawl), "-I", "-m",
            "fuzzy1337.native_crawl_worker", argument), cwd=tmp_path,
            env=NativeEnvironment(tmp_path / "owned-state"), stdin=subprocess.DEVNULL,
            capture_output=True, timeout=8, check=False)
        assert target.state.WaitIdle(), "Redirect refusal left original target ownership active."
        assert (result.returncode, result.stderr, result.stdout) == (2, b"", CanonicalNative({
            "schema_version": 1, "profile": "owned-loopback-content-crawl.v1",
            "outcome": "refused", "error": "response-policy"})), (
                "Redirect work must remain failed/unassessed with no partial body/frontier fields."
            )
        assert [item.target for item in target.state.Observe()] == ["/redirect"] and (
            target.state.Counters()["contacts"] == 1 and not target.state.Errors()
        ), "A redirect Location must cause exactly zero original destination contacts."
