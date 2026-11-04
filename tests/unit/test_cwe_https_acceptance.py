# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise the hosted CWE acceptance wrapper with owned inputs and local stores."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import replace
from io import StringIO
from pathlib import Path
from zipfile import ZipFile

import pytest
import yaml

from fuzzy1337 import intelligence_cwe_remote as remote
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.intelligence_commands import RunIntelCommands
from fuzzy1337.intelligence_cwe_selection import ParseCweSelection
from tests.unit.test_intelligence_cwe_selection import Archive, Catalog, Entry
from tools import cwe_https_acceptance as acceptance

ROOT = Path(__file__).resolve().parents[2]


def OwnedPins():
    """Derive explicit test pins from the repository's owned ZIP fixture builders."""

    payloads = {}
    pins = []

    for pin in acceptance.PINS:
        inner = (b"<Weaknesses>" + Entry() + Entry("89") + b"</Weaknesses><Views>"
                 + Entry("1000", kind="View") + b"</Views>")
        raw = Archive(Catalog(inner, pin.version), pin.version)
        selected = ParseCweSelection(raw, acceptance.IDS, catalog_version=pin.version)
        payloads[pin.version] = raw
        pins.append(replace(pin, raw_sha256=hashlib.sha256(raw).hexdigest(), size=len(raw),
                            decoded_sha256=selected.decoded_sha256,
                            decoded_size=selected.decoded_size,
                            decoded_crc32=selected.decoded_crc32, counts=(2, 0, 0, 1)))

    return tuple(pins), payloads


@pytest.fixture
def owned_processes(monkeypatch):
    """Use real product routing and stores beneath deterministic receiver/process seams."""

    pins, payloads = OwnedPins()
    monkeypatch.setattr(acceptance, "PINS", pins)
    observed = {"calls": [], "mutation": None}

    def Receive(url, max_bytes, timeout_seconds, *, accept_kind):
        """Serve only the selected test archive with the actual finite product options."""

        pin = next(p for p in pins if remote.CweHttpsSource(p.version, p.raw_sha256).SourceUrl
                   == url)
        assert (max_bytes, timeout_seconds, accept_kind) == (pin.size, 15.0, "zip"), (
            "Product fetch lost exact finite pin controls."
        )
        observed["calls"].append(pin.version)

        return payloads[pin.version], "succeeded", 200

    def Run(command, *, stdin, stdout, stderr, timeout, check):
        """Observe exact installed argv then call the real router with a synthetic receiver."""

        assert command[:8] == [
            acceptance.sys.executable, "-I", "-m", "fuzzy1337", "intel", "cwe", "https", "fetch",
        ], "The harness bypassed the installed CLI entry point."
        assert (stdin, timeout, check) == (subprocess.DEVNULL, 30, False), (
            "The installed process lost bounded controls."
        )
        terminal = StringIO()
        arguments = command[5:]
        arguments.remove("--json")
        status = RunIntelCommands(arguments, terminal, json_output=True)
        assert status == 0, "Owned ZIP did not traverse the actual installed fetch route."
        payload = terminal.getvalue()

        if observed["calls"] == ["5.0"]:
            document = json.loads(payload)
            mutation = observed["mutation"]

            if mutation == "duplicate":
                payload = '{"status":"failed",' + payload[1:]

            elif mutation == "nonfinite":
                document["http_status"] = float("nan")
                payload = json.dumps(document)

            elif mutation == "forged":
                document["selection"]["records"][0]["name"] = "Substituted original fact"
                payload = json.dumps(document)

            elif mutation == "wrong-pin":
                document["source_sha256"] = "0" * 64
                payload = json.dumps(document)

            elif mutation == "mixed-root":
                document["receipt_id"] = "sha256:" + "0" * 64
                payload = json.dumps(document)

            elif mutation == "duplicate-handle":
                document["receipt_id"] = document["selection_id"]
                payload = json.dumps(document)

            elif mutation == "corrupt":
                workspace = Path(command[8])
                store = LocalEvidenceStore(workspace / "evidence")
                raw = store.Get(document["raw_id"])
                (workspace / "evidence" / raw.reference.locator).write_bytes(b"wrong bytes")

            elif mutation == "timeout":
                stdout.write(b"owned partial terminal")
                raise subprocess.TimeoutExpired(command, timeout)

        stdout.write(payload.encode("utf-8"))

        return subprocess.CompletedProcess(command, status)

    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", Receive)
    monkeypatch.setattr(acceptance.subprocess, "run", Run)

    return observed


@pytest.fixture
def owned_identity(tmp_path, monkeypatch):
    """Keep only the separate verified wheel identity boundary synthetic in Main tests."""

    wheel = tmp_path / "owned.whl"

    def Verify(root, selected_wheel):
        """Assert that the entry point forwards the exact checkout and wheel selection."""

        assert (root, selected_wheel) == (ROOT, wheel), "Main substituted source or wheel identity."

        return {"source_sha": "owned"}

    monkeypatch.setattr(acceptance, "VerifyInstallation", Verify)

    return wheel


def test_BothPinsPassThroughRealOriginalCustodyAndRelocation(
    tmp_path, owned_processes, owned_identity, capsys,
):
    """Verify separate original workspaces and a byte-preserving offline replay."""

    output = tmp_path / "out"
    assert acceptance.Main(["--output", str(output), "--wheel", str(owned_identity)]) == 0, (
        "Owned sources failed the actual acceptance route."
    )
    assert json.loads(capsys.readouterr().out)["status"] == "passed", (
        "The wrapper did not report both completed source checks."
    )
    assert owned_processes["calls"] == ["5.0", "4.21"], "Unexpected receiver count or ordering."
    overall = json.loads((output / "acceptance.json").read_bytes())
    assert [outcome["status"] for outcome in overall["outcomes"]] == ["passed", "passed"], (
        "Overall acceptance lacked two independent per-pin passes."
    )

    for version in owned_processes["calls"]:
        retained = output / version
        original = json.loads((retained / "fetch.stdout").read_bytes())
        inspected = json.loads((retained / "inspect.stdout").read_bytes())
        assert original["ack_basis"] == "sdk-returned", "Fetch acknowledgements were relabelled."
        assert inspected["ack_basis"] == "verified-present", "Replay invented returned ACKs."
        assert (retained / "relocated-before.json").read_bytes() == (
            retained / "relocated-after.json"
        ).read_bytes(), "Replay changed original workspace bytes."


@pytest.mark.parametrize("mutation", [
    "duplicate", "nonfinite", "forged", "wrong-pin", "mixed-root", "duplicate-handle",
    "corrupt", "timeout",
])
def test_FailedPinRetainsOriginalEvidenceAndDoesNotStopSecondPin(
    tmp_path, owned_processes, mutation, owned_identity, capsys,
):
    """Refuse terminal, custody and timeout errors without manufacturing overall acceptance."""

    output = tmp_path / "out"
    owned_processes["mutation"] = mutation
    assert acceptance.Main(["--output", str(output), "--wheel", str(owned_identity)]) == 1, (
        "A failed pin became overall acceptance."
    )
    assert json.loads(capsys.readouterr().out)["status"] == "failed", (
        "The wrapper reported success after a source refusal."
    )
    assert owned_processes["calls"] == ["5.0", "4.21"], "A failed pin hid the second attempt."
    assert not (output / "acceptance.json").exists(), "Partial success wrote an acceptance file."
    overall = json.loads((output / "acceptance-failed.json").read_bytes())
    assert [item["status"] for item in overall["outcomes"]] == ["failed", "passed"], (
        "The artifact lost independent per-pin outcomes."
    )
    assert (output / "5.0" / "fetch.stdout").stat().st_size > 0, "Original output was lost."
    assert (output / "5.0" / "fetch-invocation.json").is_file(), "Invocation evidence was lost."


def test_MainRefusesExistingOutputBeforeInstallationOrFetch(tmp_path, monkeypatch):
    """Preserve a pre-existing operator directory and its evidence bytes."""

    output = tmp_path / "prior"
    output.mkdir()
    sentinel = output / "acceptance-failed.json"
    sentinel.write_bytes(b"owned existing evidence")

    def Refuse(*args, **kwargs):
        """Make any attempt to install or fetch with an existing output fail the test."""

        pytest.fail("Existing output crossed the admission boundary.")

    monkeypatch.setattr(acceptance, "VerifyInstallation", Refuse)
    monkeypatch.setattr(acceptance, "RunAcceptance", Refuse)
    status = acceptance.Main(["--output", str(output), "--wheel", str(tmp_path / "owned.whl")])
    assert status == 1, "An existing output was accepted."
    assert list(output.iterdir()) == [sentinel], "Admission changed the existing output inventory."
    assert sentinel.read_bytes() == b"owned existing evidence", "Existing evidence was overwritten."


def test_MainRecordsInstallationFailureWithoutFetching(tmp_path, monkeypatch, capsys):
    """Retain an honest entry-point failure when package identity cannot be established."""

    output = tmp_path / "out"

    def Refuse(*args, **kwargs):
        """Supply an owned installation identity mismatch."""

        raise ValueError("Owned mismatching package identity")

    def Unexpected(*args, **kwargs):
        """Fail the test if acquisition follows a rejected package identity."""

        pytest.fail("A rejected identity reached source acquisition.")

    monkeypatch.setattr(acceptance, "VerifyInstallation", Refuse)
    monkeypatch.setattr(acceptance, "RunAcceptance", Unexpected)
    status = acceptance.Main(["--output", str(output), "--wheel", str(tmp_path / "owned.whl")])
    assert status == 1 and json.loads(capsys.readouterr().out)["status"] == "failed", (
        "An installation failure became successful source acceptance."
    )
    assert json.loads((output / "acceptance-failed.json").read_bytes()) == {
        "profile": acceptance.PROFILE, "status": "failed", "phase": "installation-or-execution",
        "error_type": "ValueError",
    }, "Installation refusal lost its bounded failure evidence."
    assert not (output / "acceptance.json").exists(), "Installation refusal published success."


def test_MainLosesConcurrentOutputOwnershipWithoutAddingEvidence(tmp_path, monkeypatch, capsys):
    """A directory created during verification belongs to another run."""

    output = tmp_path / "concurrent"
    sentinel = output / "other-run.json"

    def Verify(*args, **kwargs):
        """Create competing evidence after the first admission check."""

        output.mkdir()
        sentinel.write_bytes(b"owned concurrent evidence")

        return {"source_sha": "owned"}

    monkeypatch.setattr(acceptance, "VerifyInstallation", Verify)
    status = acceptance.Main(["--output", str(output), "--wheel", str(tmp_path / "owned.whl")])
    assert status == 1 and json.loads(capsys.readouterr().out)["status"] == "failed", (
        "An output ownership race did not fail closed."
    )
    assert list(output.iterdir()) == [sentinel], "Failure evidence entered another run's directory."
    assert sentinel.read_bytes() == b"owned concurrent evidence", "Concurrent evidence changed."


def test_ReplayWriteTripwireRejectsBothPins(tmp_path, owned_processes, monkeypatch):
    """Exercise the installed dispatcher tripwire without writing any extra custody."""

    original = acceptance.RunIntelCommands

    def Inspect(arguments, output, *, json_output):
        """Attempt a forbidden evidence-store publication only during the replay call."""

        LocalEvidenceStore(Path(arguments[3]) / "evidence").Put(None, None, None, None)

        return original(arguments, output, json_output=json_output)

    monkeypatch.setattr(acceptance, "RunIntelCommands", Inspect)
    output = tmp_path / "out"
    assert not acceptance.RunAcceptance(output, {}), "Replay writes bypassed the tripwire."
    overall = json.loads((output / "acceptance-failed.json").read_bytes())
    assert [item["phase"] for item in overall["outcomes"]] == ["offline-replay"] * 2, (
        "Tripwire failures did not retain their actual phase."
    )


def test_InstalledSourceAndWheelIdentityRequireExactPackageBytes(tmp_path, monkeypatch):
    """Verify committed, wheel and installed file equality with an owned package fixture."""

    root = tmp_path / "checkout"
    package = tmp_path / "venv" / "site-packages" / "fuzzy1337"
    package.mkdir(parents=True)
    body = b'"""Owned package fixture."""\n'
    installed = package / "__init__.py"
    installed.write_bytes(body)
    monkeypatch.setattr(acceptance.fuzzy1337, "__file__", str(installed))
    monkeypatch.setattr(acceptance.sys, "prefix", str(tmp_path / "venv"))

    def Git(path, *arguments):
        """Supply an owned commit tree, exact committed package body and fixed identities."""

        assert path == root, "Identity verification changed the checked-out source root."

        if arguments[0] == "ls-tree":
            return b"100644 blob 0123\tsrc/fuzzy1337/__init__.py\0"

        if arguments[0] == "cat-file":
            return body

        return b"owned-identity\n"

    monkeypatch.setattr(acceptance, "_Git", Git)
    wheel = tmp_path / "owned.whl"

    with ZipFile(wheel, "w") as archive:
        archive.writestr("fuzzy1337/__init__.py", body)

    identity = acceptance.VerifyInstallation(root, wheel)
    assert identity["installed_package_hashes"] == {
        "fuzzy1337/__init__.py": hashlib.sha256(body).hexdigest(),
    }, "Identity proof omitted the exact original package hash."
    installed.write_bytes(body + b"# Changed")
    with pytest.raises(ValueError, match="differ from committed source"):
        acceptance.VerifyInstallation(root, wheel)


def test_HostedLaneRequiresExactDraftSourceAndScopedArtifacts():
    """Protect the same-repository Draft guard and narrow checkout/artifact boundary."""

    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/intel-source-acceptance.yml").read_text(encoding="utf-8")
    )
    marker = "[cwe-https-source-acceptance-checkpoint]"
    jobs = [job for job in workflow["jobs"].values() if marker in job.get("if", "")]
    assert len(jobs) == 1, "The fixed CWE source marker admitted unexpected jobs."
    job = jobs[0]
    assert " ".join(job["if"].split()) == (
        "github.event.pull_request.draft && "
        "github.event.pull_request.head.repo.full_name == github.repository && "
        "contains(github.event.pull_request.body, '[cwe-https-source-acceptance-checkpoint]')"
    ), "The hosted fetch lost its exact same-repository Draft guard."
    assert workflow["permissions"] == {"contents": "read"}, "Source acceptance gained authority."
    assert job["steps"][0]["with"] == {
        "ref": "${{ github.event.pull_request.head.sha }}", "persist-credentials": False,
    }, "Hosted acquisition changed checkout identity or retained credentials."
    build = next(step["run"] for step in job["steps"]
                 if "uv export --locked" in step.get("run", ""))
    assert "--require-hashes" in build and "--no-deps" in build and "uv pip check" in build, (
        "Hosted wheel installation lost the locked dependency and integrity boundary."
    )
    artifact = job["steps"][-1]
    assert artifact["if"] == "always()" and artifact["with"]["path"].split() == [
        "functional-evidence/cwe-https-source/", "functional-evidence/cwe-https-wheel/*.whl",
        "functional-evidence/cwe-https-source-wrapper.xml",
    ], "Artifact upload lost its narrow source evidence scope."
