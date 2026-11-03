# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pinned public-source acceptance cannot turn partial or mismatched CLI facts into success."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
import subprocess
from dataclasses import replace
from io import StringIO
from pathlib import Path

import pytest
import yaml

from fuzzy1337 import intelligence_epss_remote as remote
from fuzzy1337.evidence import EvidenceError, LocalEvidenceStore
from fuzzy1337.intelligence_epss_https_commands import RunEpssHttpsCommands
from fuzzy1337.intelligence_epss_remote import EpssHttpsSource
from fuzzy1337.model import LocalModelStore

SPEC = importlib.util.spec_from_file_location("epss_https_acceptance",
    Path(__file__).resolve().parents[2] / "tools/epss_https_acceptance.py")
assert SPEC is not None and SPEC.loader is not None, "Acceptance source specification is missing"
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


def Document():
    """Make only controlled terminal facts; original-store verification remains separate."""

    source = EpssHttpsSource(acceptance.SOURCE_COMMIT, acceptance.SOURCE_DAY,
                            acceptance.SOURCE_MODEL, acceptance.EXPECTED_SHA256)

    return {"profile": "epss-https-selected-cli", "command": "intel.epss.https.fetch",
        "status": "succeeded", "acquisition_state": "succeeded", "receive_state": "succeeded",
        "transport": "https", "http_status": 200, "body_complete": True,
        "received_bytes": acceptance.EXPECTED_BYTES, "source_sha256": acceptance.EXPECTED_SHA256,
        "source": source.ToDict(), "raw_ack": "confirmed", "selection_ack": "confirmed",
        "receipt_ack": "confirmed", "model_commit": "not-attempted",
        "publisher_authentication": "not-assessed", "raw_id": "sha256:" + "a" * 64,
        "selection_id": "sha256:" + "b" * 64, "receipt_id": "sha256:" + "c" * 64}


def test_ExactPinnedTerminalStillRequiresLaterOriginalCustodyVerification():
    """The finite preflight accepts only exact expected terminal metadata."""

    document = Document()
    assert acceptance.VerifyFetch(document) is document, "Pinned terminal preflight changed facts"


@pytest.mark.parametrize("field,value", [
    ("profile", "local"), ("command", "intel.epss.import"), ("status", "failed"),
    ("acquisition_state", "timed-out"), ("receive_state", "transport-failed"),
    ("transport", "local-bytes"), ("http_status", True), ("http_status", 302),
    ("body_complete", 1), ("body_complete", False), ("received_bytes", True),
    ("received_bytes", 0), ("source_sha256", "0" * 64), ("source", {}),
    ("raw_ack", "unknown"), ("selection_ack", "not-attempted"), ("receipt_ack", "unknown"),
    ("model_commit", "confirmed"), ("publisher_authentication", "verified"),
    ("raw_id", None), ("selection_id", "epss-selection:" + "b" * 64),
    ("receipt_id", "sha256:" + "b" * 64),
])
def test_PartialMisattributedOrUnacknowledgedTerminalFactsCannotPass(field, value):
    """Malformed or independently failed source facts refuse before original reads."""

    document = Document()
    document[field] = value

    with pytest.raises(ValueError):
        acceptance.VerifyFetch(document)


@pytest.mark.parametrize("document", [None, [], "succeeded"])
def test_NonObjectTerminalRefuses(document):
    """A textual success marker is not structured original acquisition evidence."""

    with pytest.raises(ValueError):
        acceptance.VerifyFetch(document)


def test_ExistingAcceptanceOutputIsNeverRewritten(tmp_path):
    """A repeated invocation refuses before fetch and preserves earlier evidence exactly."""

    output = tmp_path / "original"
    output.mkdir()
    original = output / "acceptance.json"
    original.write_text('{"status":"passed"}\n', encoding="utf-8")
    before = {p.name: p.read_bytes() for p in output.iterdir()}
    status = acceptance.Main(["--output", str(output)])
    assert status == 1 and {p.name: p.read_bytes() for p in output.iterdir()} == before, (
        "Repeated acceptance overwrote original evidence or attempted another fetch"
    )


def test_ActualStoredSourceCannotBeReplacedByPinnedTerminalSource(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Valid same-byte custody under another commit cannot inherit the terminal's source pin.

    Args:
        tmp_path: Disposable owning workspace and acceptance evidence directory.
        monkeypatch: Scoped owned receiver, expected corpus and terminal substitutions.
    """

    csv = (f"#model_version:{acceptance.SOURCE_MODEL},"
           f"score_date:{acceptance.SOURCE_DAY}T12:00:30Z\n"
           "cve,epss,percentile\nCVE-1999-0001,0.1,0.2\n"
           "CVE-2023-20914,0.2,6e-05\n").encode("utf-8")
    payload = gzip.compress(csv, mtime=0)

    for name, value in {
        "EXPECTED_SHA256": hashlib.sha256(payload).hexdigest(),
        "EXPECTED_DECODED_SHA256": hashlib.sha256(csv).hexdigest(),
        "EXPECTED_BYTES": len(payload), "EXPECTED_DECODED_BYTES": len(csv), "EXPECTED_ROWS": 2,
    }.items():
        monkeypatch.setattr(acceptance, name, value)

    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", lambda *args, **kwargs:
                        (payload, "succeeded", 200))
    observed_sources = []

    def Run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        """Publish genuine fixture custody, then spoof only the terminal's declared source.

        Args:
            command: Actual pinned product invocation selecting the created owning workspace.
            kwargs: Unchanged subprocess controls; no real process is launched by this fixture.

        Returns:
            Controlled successful terminal with genuine artifacts and inconsistent source facts.
        """

        root = Path(command[command.index("fetch") + 1])
        alternate = EpssHttpsSource("b" * 40, acceptance.SOURCE_DAY, acceptance.SOURCE_MODEL,
                                   acceptance.EXPECTED_SHA256)
        acquired = remote.AcquireHttpsEpssSelection(
            root, remote.EpssHttpsRequest(alternate, acceptance.SELECTED_IDS),
            scope_reference="scope:owned-acceptance-fixture",
        )
        assert acquired.state is remote.EpssHttpsState.SUCCEEDED and acquired.envelope, (
            "The alternate-source fixture must retain valid actual original custody"
        )
        assert remote.LoadHttpsEpssSelection(
            root, acquired.selection_record.evidence_id, acquired.receipt.evidence_id,
        ) == acquired.envelope, "The alternate-source fixture must independently reopen"
        observed_sources.append(acquired.envelope.source.commit)
        document = Document()
        document.update({
            "raw_id": acquired.raw.evidence_id,
            "selection_id": acquired.selection_record.evidence_id,
            "receipt_id": acquired.receipt.evidence_id,
            "selection": acquired.envelope.selection.ToDict(),
            "selection_reference": acquired.envelope.Reference(),
        })

        return subprocess.CompletedProcess(command, 0, json.dumps(document), "")

    monkeypatch.setattr(acceptance.subprocess, "run", Run)

    with pytest.raises(ValueError):
        acceptance.RunAcceptance(tmp_path / "acceptance")

    assert observed_sources == ["b" * 40], "The refusal must follow actual alternate custody"
    assert not (tmp_path / "acceptance" / "acceptance.json").exists(), (
        "A spoofed terminal source published a successful acceptance marker"
    )


def OwnedBoundary(monkeypatch: pytest.MonkeyPatch, mutation: str | None = None) -> dict:
    """Run the actual CLI and SDK with one synthetic receiver and real owning stores.

    Args:
        monkeypatch: Scoped substitution of expected fixture facts and process/receiver seams.
        mutation: Optional inconsistency introduced after actual acquisition or relocation.

    Returns:
        Observed original bytes, receive calls and actual CLI terminal for test assertions.
    """

    csv = (f"#model_version:{acceptance.SOURCE_MODEL},"
           f"score_date:{acceptance.SOURCE_DAY}T12:00:30Z\n"
           "cve,epss,percentile\nCVE-1999-0001,0.1,0.2\n"
           "CVE-2023-20914,0.2,6e-05\n").encode("utf-8")
    payload = gzip.compress(csv, mtime=0)
    observed = {"payload": payload, "receives": [], "commands": []}

    for name, value in {
        "EXPECTED_SHA256": hashlib.sha256(payload).hexdigest(),
        "EXPECTED_DECODED_SHA256": hashlib.sha256(csv).hexdigest(),
        "EXPECTED_BYTES": len(payload), "EXPECTED_DECODED_BYTES": len(csv), "EXPECTED_ROWS": 2,
    }.items():
        monkeypatch.setattr(acceptance, name, value)

    def Receive(url: str, max_bytes: int, timeout_seconds: float, *,
                accept_kind: str = "json") -> tuple[bytes, str, int]:
        """Supply owned bytes only after the actual CLI admits an explicit pinned request.

        Args:
            url: Sole generated immutable source locator selected by the typed SDK.
            max_bytes: Actual compressed bound requested by the wrapper.
            timeout_seconds: Actual total receive budget requested by the wrapper.
            accept_kind: Fixed resource preference; no decompression occurs here.

        Returns:
            Complete synthetic original body and explicit controlled HTTP facts.
        """

        source = EpssHttpsSource(acceptance.SOURCE_COMMIT, acceptance.SOURCE_DAY,
                                acceptance.SOURCE_MODEL, acceptance.EXPECTED_SHA256)
        assert (url, max_bytes, timeout_seconds, accept_kind) == (
            source.SourceUrl, len(payload), 30, "gzip",
        ), "The wrapper changed the explicit bounded pinned HTTPS invocation"
        observed["receives"].append(url)

        return payload, "succeeded", 200

    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", Receive)
    observed["receiver"] = Receive

    def Run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        """Replace only process launching while real product code publishes original custody.

        Args:
            command: Installed CLI invocation assembled by the wrapper under test.
            kwargs: Bounded subprocess controls, retained without starting a real child.

        Returns:
            Actual CLI status/JSON, optionally changed at an explicitly adversarial terminal seam.
        """

        assert command[:8] == [acceptance.sys.executable, "-I", "-m", "fuzzy1337",
                              "intel", "epss", "https", "fetch"], (
            "The wrapper bypassed the installed explicit HTTPS product namespace"
        )
        assert kwargs == {"capture_output": True, "text": True, "timeout": 60, "check": False}, (
            "The wrapper lost bounded subprocess execution or controlled output capture"
        )
        observed["commands"].append(command)
        root = Path(command[8])
        arguments = command[7:].copy()
        arguments.remove("--json")
        output = StringIO()
        status = RunEpssHttpsCommands(arguments, output, json_output=True)
        document = json.loads(output.getvalue())
        assert status == 0 and document["status"] == "succeeded", (
            "The owned fixture must complete actual CLI acquisition before adversarial changes"
        )
        observed["document"] = document
        observed["workspace"] = root

        if mutation == "raw-manifest":
            store = LocalEvidenceStore(root / "evidence")
            original = store.Get(document["raw_id"])
            replacement = store.Put(payload, "owned-unrelated-artifact", "application/gzip",
                                    original.provenance)
            document["raw_id"] = replacement.evidence_id

        elif mutation == "selection":
            document["selection"] = {}

        elif mutation == "reference":
            document["selection_reference"] = "epss-https-selection:" + "0" * 64

        elif mutation == "model":
            model = LocalModelStore(root)
            before = model.Open()
            model.Save(replace(before, revision=before.revision + 1),
                       expected_revision=before.revision)

        elif mutation == "original-corruption":
            store = LocalEvidenceStore(root / "evidence")
            original = store.Get(document["raw_id"])
            (root / "evidence" / original.reference.locator).write_bytes(b"x" * len(payload))

        return subprocess.CompletedProcess(command, 9 if mutation == "exit" else status,
            "not-json" if mutation == "json" else json.dumps(document),
            "owned diagnostic" if mutation == "stderr" else "")

    monkeypatch.setattr(acceptance.subprocess, "run", Run)

    if mutation in ("relocated-model", "relocated-corruption"):
        original_move = acceptance.shutil.move

        def Move(source: str, destination: Path) -> str:
            """Move the complete real workspace, then introduce an owned offline inconsistency.

            Args:
                source: Actual original owning workspace path.
                destination: Wrapper-selected relocated owning workspace path.

            Returns:
                The actual filesystem move result after the controlled mutation.
            """

            result = original_move(source, destination)

            if mutation == "relocated-model":
                model = LocalModelStore(destination)
                before = model.Open()
                model.Save(replace(before, revision=before.revision + 1),
                           expected_revision=before.revision)

            else:
                store = LocalEvidenceStore(destination / "evidence")
                original = store.Get(observed["document"]["raw_id"])
                (destination / "evidence" / original.reference.locator).write_bytes(
                    b"x" * len(payload),
                )

            return result

        monkeypatch.setattr(acceptance.shutil, "move", Move)

    return observed


def test_ActualCliCustodyReopensAfterRelocationWithoutAnotherReceive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Traverse the real CLI, original manifests and offline decoder before publishing success.

    Args:
        tmp_path: Disposable acceptance output and original owning workspace root.
        monkeypatch: Owned receiver/process seam and finite synthetic expected source pins.
    """

    observed = OwnedBoundary(monkeypatch)
    output = tmp_path / "accepted"
    facts = acceptance.RunAcceptance(output)
    document = observed["document"]
    moved = output / "relocated-workspace"
    reopened = remote.LoadHttpsEpssSelection(moved, facts["selection_id"], facts["receipt_id"])
    store = LocalEvidenceStore(moved / "evidence")
    assert facts == json.loads((output / "acceptance.json").read_bytes()), (
        "Saved acceptance must match returned facts only after original offline verification"
    )
    assert facts["status"] == "passed" and facts["received_rows"] == 2 and (
        facts["offline_relocated_reopen"] is True and facts["canonical_model_unchanged"] is True
        and facts["publisher_authentication"] == "not-assessed"
    ), "Synthetic original-source acceptance invented trust or omitted actual custody checks"
    assert not (output / "workspace").exists() and moved.is_dir(), (
        "The accepted original owning workspace did not actually relocate"
    )
    assert store.Read(reopened.raw.reference) == observed["payload"], (
        "Relocated original bytes differ from the actual SDK receiver body"
    )
    assert reopened.selection.ToDict() == document["selection"] and (
        reopened.selection.unmatched_ids == ("CVE-9999-9999",)
        and reopened.selection.records[1].percentile == "6e-05"
        and LocalModelStore(moved).Open().revision == 0
    ), "Original selected assertions, unmatched scope, decimal spelling or model changed"
    assert len(observed["receives"]) == len(observed["commands"]) == 1 and (
        remote.ReceiveIsolatedHttps is observed["receiver"]
    ), "Offline replay retried network acquisition or failed to restore the receiver seam"

    for name, digest in facts["production_hashes"].items():
        assert hashlib.sha256(Path(remote.__file__).with_name(name).read_bytes()).hexdigest() == (
            digest
        ), "Accepted production hashes must identify the exact exercised source files"


@pytest.mark.parametrize("mutation,diagnostic", [
    ("raw-manifest", "Original raw manifest"), ("selection", "CLI selected facts"),
    ("reference", "CLI selected facts"), ("model", "CLI selected facts"),
    ("relocated-model", "Relocated original-source"),
])
def test_ValidOriginalCustodyCannotHideTerminalOrModelDrift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str, diagnostic: str,
) -> None:
    """Independent real artifacts and model state cannot inherit a changed terminal assertion.

    Args:
        tmp_path: Disposable original acquisition and acceptance output root.
        monkeypatch: Actual-owner fixture seams without external networking.
        mutation: Deliberately inconsistent terminal manifest, selected facts or model state.
        diagnostic: Specific verification boundary that must reject the inconsistency.
    """

    observed = OwnedBoundary(monkeypatch, mutation)
    output = tmp_path / "refused"

    with pytest.raises(ValueError, match=diagnostic):
        acceptance.RunAcceptance(output)

    assert len(observed["receives"]) == 1 and not (output / "acceptance.json").exists(), (
        "A terminal/model drift published acceptance or caused another receiver call"
    )
    assert remote.ReceiveIsolatedHttps is observed["receiver"], (
        "Failed original-source reopening did not restore the original receiver seam"
    )


@pytest.mark.parametrize("field,value", [
    ("EXPECTED_DECODED_SHA256", "0" * 64), ("EXPECTED_DECODED_BYTES", 1),
    ("EXPECTED_ROWS", 3),
])
def test_ActualDecodedCorpusMustMatchAllPinnedDecodeFacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object,
) -> None:
    """Successful exact gzip custody cannot substitute expected expanded-corpus facts.

    Args:
        tmp_path: Disposable original acquisition and acceptance output root.
        monkeypatch: Owned actual receiver/CLI fixture and expected decode-fact substitution.
        field: Independent expanded digest, byte count or row count changed for this case.
        value: Deliberately inconsistent finite expected decode fact.
    """

    observed = OwnedBoundary(monkeypatch)
    monkeypatch.setattr(acceptance, field, value)
    output = tmp_path / "refused"

    with pytest.raises(ValueError, match="expected decode facts"):
        acceptance.RunAcceptance(output)

    assert len(observed["receives"]) == 1 and not (output / "acceptance.json").exists(), (
        "A decoder-fact mismatch became a successful acceptance marker"
    )


@pytest.mark.parametrize("mutation", ["original-corruption", "relocated-corruption"])
def test_OriginalBodyCorruptionRefusesAndRestoresOfflineReceiver(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    """Actual immutable-store verification refuses corruption before or after relocation.

    Args:
        tmp_path: Disposable acceptance output containing actual original evidence records.
        monkeypatch: Owned receiver/process seam and controlled on-disk corruption.
        mutation: Phase at which the original retained body is corrupted.
    """

    observed = OwnedBoundary(monkeypatch, mutation)
    output = tmp_path / "refused"

    with pytest.raises(EvidenceError):
        acceptance.RunAcceptance(output)

    assert len(observed["receives"]) == 1 and not (output / "acceptance.json").exists(), (
        "Corrupt original bytes were accepted or triggered another receive"
    )
    assert remote.ReceiveIsolatedHttps is observed["receiver"], (
        "An offline reparse failure leaked the temporary NoReceive tripwire"
    )


@pytest.mark.parametrize("mutation", ["exit", "stderr", "json"])
def test_MainPreservesFailedProcessFactsWithoutSuccessfulAcceptance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    """A nonzero process, unexpected diagnostic or malformed JSON yields an honest failure.

    Args:
        tmp_path: Disposable acceptance evidence and failure marker root.
        monkeypatch: Owned actual CLI/SDK fixture and explicit process-result inconsistency.
        mutation: Controlled process-result field that must prevent acceptance.
    """

    observed = OwnedBoundary(monkeypatch, mutation)
    output = tmp_path / "failed"
    status = acceptance.Main(["--output", str(output)])
    assert status == 1 and json.loads((output / "acceptance-failed.json").read_bytes()) == {
        "status": "failed", "profile": "pinned-epss-https-acceptance",
    }, "The entry point failed to retain an honest controlled failure marker"
    assert (output / "fetch.json").is_file() and (output / "fetch-stderr.txt").is_file() and (
        not (output / "acceptance.json").exists() and len(observed["receives"]) == 1
    ), "Failed process evidence was lost, retried or mislabeled successful"


def test_MainPrintsSuccessOnlyAfterActualOriginalCustodyAcceptance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """The public entry point emits finite success facts after real owned offline reparse.

    Args:
        tmp_path: Disposable accepted evidence root.
        monkeypatch: Owned receiver/process boundaries; actual SDK, stores and loader remain real.
        capsys: Captured concise terminal facts for comparison with saved acceptance.
    """

    OwnedBoundary(monkeypatch)
    output = tmp_path / "accepted"
    assert acceptance.Main(["--output", str(output)]) == 0, (
        "The entry point rejected complete actual-owner acceptance"
    )
    summary = json.loads(capsys.readouterr().out)
    facts = json.loads((output / "acceptance.json").read_bytes())
    assert summary == {"status": "passed", "received_bytes": acceptance.EXPECTED_BYTES,
                       "received_rows": 2, "source_sha256": acceptance.EXPECTED_SHA256}, (
        "Success output disagreed with exact accepted original-source facts"
    )
    assert facts["offline_relocated_reopen"] is True, (
        "Main reported success before actual relocated original-source reopening"
    )


def test_OfflineTripwireRefusesEveryReceiverInvocation() -> None:
    """The offline verifier cannot silently reacquire a replacement original source."""

    with pytest.raises(AssertionError, match="attempted another receiver"):
        acceptance.NoReceive("https://example.invalid/owned", 1, timeout_seconds=1)


def test_DocumentationLaneIncludesAcceptanceTestsInPerToolCoverage() -> None:
    """The explicit hosted documentation selection exercises the new audited tool owner."""

    workflow = yaml.safe_load((Path(__file__).resolve().parents[2]
                              / ".github/workflows/documentation.yml").read_text())
    steps = workflow["jobs"]["deterministic-documentation"]["steps"]
    step_name = "Exercise documentation boundaries and enforce per-tool branch coverage"
    selected = [step["run"] for step in steps if step.get("name") == step_name]
    assert len(selected) == 1 and "tests/unit/test_epss_https_acceptance.py" in selected[0], (
        "The explicit documentation suite omitted the EPSS HTTPS acceptance tool's tests"
    )
    assert "--cov=tools --cov-branch --cov-config=/dev/null" in selected[0] and (
        "fuzzy1337.coverage_gate _build/docs/tool-coverage.json tools" in selected[0]
    ), "The documentation lane weakened per-tool statement/branch coverage enforcement"
