# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned original-custody oracles for pinned CVE acquisition and offline CLI acceptance."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import replace
from io import StringIO
from pathlib import Path

import pytest
import yaml

from fuzzy1337 import intelligence_cve_remote as remote
from fuzzy1337.evidence import EvidenceError, LocalEvidenceStore
from fuzzy1337.intelligence_cve_https_commands import RunCveHttpsCommands
from fuzzy1337.model import LocalModelStore
from tools import cve_https_acceptance as acceptance


def Document() -> dict:
    """Describe fixed terminal pins without claiming that fabricated handles prove custody.

    Returns:
        Exact preflight metadata; original-store verification must still run separately.
    """

    source = remote.CveHttpsSource(acceptance.SOURCE_COMMIT, acceptance.SOURCE_IDENTIFIER,
                                  acceptance.EXPECTED_SHA256)

    return {"profile": "cve-https-selected-cli", "command": "intel.cve.https.fetch",
        "status": "succeeded", "acquisition_state": "succeeded", "receive_state": "succeeded",
        "transport": "https", "http_status": 200, "body_complete": True,
        "received_bytes": acceptance.EXPECTED_BYTES, "source_sha256": acceptance.EXPECTED_SHA256,
        "source": source.ToDict(), "raw_ack": "confirmed", "selection_ack": "confirmed",
        "receipt_ack": "confirmed", "model_commit": "not-attempted",
        "publisher_authentication": "not-assessed", "raw_id": "sha256:" + "a" * 64,
        "selection_id": "sha256:" + "b" * 64, "receipt_id": "sha256:" + "c" * 64}


def test_TerminalPreflightRequiresSubsequentOriginalCustodyVerification() -> None:
    """Preflight accepts the exact object without turning terminal handles into evidence."""

    document = Document()
    assert acceptance.VerifyFetch(document) is document, "Preflight changed exact terminal facts"


@pytest.mark.parametrize("field,value", [
    ("profile", "local"), ("command", "intel.import"), ("status", "failed"),
    ("acquisition_state", "timed-out"), ("receive_state", "transport-failed"),
    ("transport", "local-bytes"), ("http_status", True), ("http_status", 302),
    ("body_complete", 1), ("body_complete", False), ("received_bytes", True),
    ("received_bytes", 0), ("source_sha256", "0" * 64), ("source", {}),
    ("raw_ack", "unknown"), ("selection_ack", "not-attempted"), ("receipt_ack", "unknown"),
    ("model_commit", "confirmed"), ("publisher_authentication", "verified"),
    ("raw_id", None), ("selection_id", "cve-selection:" + "b" * 64),
    ("receipt_id", "sha256:" + "b" * 64),
])
def test_UncertainMisattributedOrMalformedFetchFactsRefuse(field: str, value: object) -> None:
    """Every network, source and independent custody field must match before original reads.

    Args:
        field: Terminal field changed independently of original source verification.
        value: Deliberately inconsistent typed value or malformed handle.
    """

    document = Document()
    document[field] = value

    with pytest.raises(ValueError):
        acceptance.VerifyFetch(document)


@pytest.mark.parametrize("document", [None, [], "succeeded"])
def test_NonObjectFetchFactsRefuse(document: object) -> None:
    """An unstructured status cannot establish pinned original-source custody.

    Args:
        document: Non-object replacement for the required terminal profile.
    """

    with pytest.raises(ValueError):
        acceptance.VerifyFetch(document)


def OwnedBoundary(monkeypatch: pytest.MonkeyPatch, mutation: str | None = None) -> dict:
    """Keep the CLI, SDK, source loader and evidence owners real beneath controlled seams.

    Args:
        monkeypatch: Scoped expected synthetic source pins and process/receiver substitutions.
        mutation: Optional adversarial terminal, original-storage or inspection inconsistency.

    Returns:
        Original synthetic bytes, actual terminal documents and observed receiver/process calls.
    """

    source = {"dataType": "CVE_RECORD", "dataVersion": "5.2",
        "cveMetadata": {"cveId": "CVE-1900-9999", "state": "PUBLISHED",
                        "dateUpdated": "2026-10-12T10:00:00Z"},
        "containers": {"cna": {"providerMetadata": {"orgId": "owned-acceptance"},
            "descriptions": [{"lang": "en", "value": "Explicitly fictional acceptance fixture"}],
            "problemTypes": [{"descriptions": [{"cweId": "CWE-79"}]}]}}}
    payload = json.dumps(source, indent=2).encode("utf-8")

    for name, value in {"SOURCE_COMMIT": "a" * 40, "SOURCE_IDENTIFIER": "CVE-1900-9999",
        "EXPECTED_SHA256": hashlib.sha256(payload).hexdigest(), "EXPECTED_BYTES": len(payload),
    }.items():
        monkeypatch.setattr(acceptance, name, value)

    observed = {"payload": payload, "receives": [], "commands": [], "inspections": []}

    def Receive(url: str, max_bytes: int, timeout_seconds: float, *,
                accept_kind: str = "json") -> tuple[bytes, str, int]:
        """Supply owned original bytes only at the actual SDK's isolated receiver boundary.

        Args:
            url: Immutable selected locator derived by the typed source.
            max_bytes: Actual compressed-free original JSON budget requested by the wrapper.
            timeout_seconds: Actual finite total receive lifetime.
            accept_kind: Existing JSON resource preference, without HTTP decompression.

        Returns:
            Complete synthetic original JSON and controlled observed HTTP success facts.
        """

        commit = "b" * 40 if mutation == "alternate-source" else acceptance.SOURCE_COMMIT
        selected = remote.CveHttpsSource(commit, acceptance.SOURCE_IDENTIFIER,
                                        acceptance.EXPECTED_SHA256)
        expectedBytes = len(payload) + 1 if mutation == "different-byte-limit" else len(payload)
        expectedTimeout = 31 if mutation == "different-timeout" else 30
        assert (url, max_bytes, timeout_seconds, accept_kind) == (
            selected.SourceUrl, expectedBytes, expectedTimeout, "json",
        ), "The wrapper bypassed explicit immutable source admission or finite JSON limits"
        observed["receives"].append(url)

        return payload, "succeeded", 200

    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", Receive)
    observed["receiver"] = Receive

    def Run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        """Replace process launch while executing the actual fetch handler, SDK and stores.

        Args:
            command: Installed product invocation assembled by the acceptance wrapper.
            kwargs: Controlled bounded subprocess options that must remain unchanged.

        Returns:
            Actual fetch status and JSON, optionally changed at the adversarial terminal seam.
        """

        assert command[:8] == [acceptance.sys.executable, "-I", "-m", "fuzzy1337",
                              "intel", "cve", "https", "fetch"], (
            "Source acceptance bypassed the installed explicit HTTPS product namespace"
        )
        assert kwargs == {"capture_output": True, "text": True, "timeout": 60, "check": False}, (
            "Source acceptance lost bounded process execution or controlled output capture"
        )
        observed["commands"].append(command)
        arguments = command[7:].copy()
        arguments.remove("--json")

        if mutation == "alternate-source":
            arguments[arguments.index("--commit") + 1] = "b" * 40

        elif mutation == "different-byte-limit":
            arguments[arguments.index("--max-bytes") + 1] = str(len(payload) + 1)

        elif mutation == "different-timeout":
            arguments[arguments.index("--timeout-seconds") + 1] = "31"

        root = Path(command[8])
        output = StringIO()
        status = RunCveHttpsCommands(arguments, output, json_output=True)
        document = json.loads(output.getvalue())
        assert status == 0 and document["status"] == "succeeded", (
            "The owned fixture must acquire actual original custody before adversarial changes"
        )
        received = remote.LoadHttpsCveSelection(root, document["selection_id"],
                                               document["receipt_id"])
        observed.update({"document": document, "workspace": root, "original": received})

        if mutation == "alternate-source":
            document["source"] = remote.CveHttpsSource(
                acceptance.SOURCE_COMMIT, acceptance.SOURCE_IDENTIFIER,
                acceptance.EXPECTED_SHA256,
            ).ToDict()

        elif mutation == "raw-manifest":
            store = LocalEvidenceStore(root / "evidence")
            replacement = store.Put(payload, "owned-unrelated-source", "application/json",
                                    received.raw.provenance)
            document["raw_id"] = replacement.evidence_id

        elif mutation == "snapshot":
            document["snapshot"] = {}

        elif mutation == "reference":
            document["selection_reference"] = "cve-https-selection:" + "0" * 64

        elif mutation == "model":
            model = LocalModelStore(root)
            before = model.Open()
            model.Save(replace(before, revision=before.revision + 1),
                       expected_revision=before.revision)

        elif mutation == "original-corruption":
            (root / "evidence" / received.raw.reference.locator).write_bytes(b"x" * len(payload))

        return subprocess.CompletedProcess(command, 9 if mutation == "exit" else status,
            "not-json" if mutation == "json" else json.dumps(document),
            "owned diagnostic" if mutation == "stderr" else "")

    monkeypatch.setattr(acceptance.subprocess, "run", Run)

    if mutation == "relocated-corruption":
        originalMove = acceptance.shutil.move

        def Move(source: str, destination: Path) -> str:
            """Relocate actual original owners, then corrupt the retained original source blob.

            Args:
                source: Wrapper-selected original workspace directory.
                destination: Wrapper-selected new owning workspace directory.

            Returns:
                Actual filesystem move result after controlled original-body corruption.
            """

            result = originalMove(source, destination)
            locator = observed["original"].raw.reference.locator
            (destination / "evidence" / locator).write_bytes(b"x" * len(payload))

            return result

        monkeypatch.setattr(acceptance.shutil, "move", Move)

    def Inspect(arguments: list[str], output: StringIO, *, json_output: bool = False) -> int:
        """Call actual offline inspection before optionally corrupting only its terminal facts.

        Args:
            arguments: Exact relocated original selection and receipt roots from the wrapper.
            output: Caller-owned JSON stream for actual inspection facts.
            json_output: Explicit machine-readable result request.

        Returns:
            Actual successful status, or an explicit controlled failure for its negative oracle.
        """

        assert remote.ReceiveIsolatedHttps is acceptance.NoReceive, (
            "Relocated product inspection was not protected by the no-receive tripwire"
        )
        actual = StringIO()
        status = RunCveHttpsCommands(arguments, actual, json_output=json_output)
        document = json.loads(actual.getvalue())
        assert status == 0, "Owned original evidence must independently pass actual CLI inspection"
        observed["inspections"].append(document)

        if mutation == "inspect-ack":
            document["receipt_ack"] = "unknown"

        elif mutation == "inspect-source":
            document["source"] = {}

        elif mutation == "inspect-snapshot":
            document["snapshot"] = {}

        elif mutation == "inspect-reference":
            document["selection_reference"] = "cve-https-selection:" + "0" * 64

        elif mutation == "inspect-handle":
            document["receipt_id"] = "sha256:" + "0" * 64

        elif mutation == "inspect-model":
            model = LocalModelStore(Path(arguments[1]))
            before = model.Open()
            model.Save(replace(before, revision=before.revision + 1),
                       expected_revision=before.revision)

        output.write(json.dumps([] if mutation == "inspect-object" else document))

        return 4 if mutation == "inspect-status" else status

    monkeypatch.setattr(acceptance, "RunCveHttpsCommands", Inspect)

    return observed


def test_ActualOriginalCustodyAndCliInspectionSurviveRelocationWithoutReceive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Accept only after actual source publication, original reparse and relocated CLI inspection.

    Args:
        tmp_path: Disposable acceptance output and owning original evidence directory.
        monkeypatch: Controlled synthetic source facts and receiver/process seams.
    """

    observed = OwnedBoundary(monkeypatch)
    output = tmp_path / "accepted"
    facts = acceptance.RunAcceptance(output)
    moved = output / "relocated-workspace"
    actual = remote.LoadHttpsCveSelection(moved, facts["selection_id"], facts["receipt_id"])
    assert facts == json.loads((output / "acceptance.json").read_bytes()), (
        "Saved acceptance differs from verified original-custody facts"
    )
    assert facts["status"] == "passed" and facts["record_count"] == 1 and (
        facts["source_state"] == "PUBLISHED" and facts["source_data_version"] == "5.2"
        and facts["offline_relocated_reopen"] is True and facts["installed_offline_inspect"] is True
        and facts["canonical_model_unchanged"] is True
        and facts["publisher_authentication"] == facts["legal_rights"] == "not-assessed"
    ), "Acceptance invented source trust, lost the finite profile or skipped actual offline proof"
    assert not (output / "workspace").exists() and moved.is_dir() and (
        LocalModelStore(moved).Open().revision == 0
    ), "The original owning workspace did not relocate or its canonical model changed"
    store = LocalEvidenceStore(moved / "evidence")
    assert store.Read(actual.raw.reference) == observed["payload"] and (
        hashlib.sha256(observed["payload"]).hexdigest() == facts["source_sha256"]
    ), "Accepted original bytes differ from the actual owned SDK receive"
    assert len(observed["receives"]) == len(observed["commands"]) == len(
        observed["inspections"]
    ) == 1 and remote.ReceiveIsolatedHttps is observed["receiver"], (
        "Offline source verification retried acquisition or leaked its no-receive tripwire"
    )
    assert json.loads((output / "inspect.json").read_bytes()) == observed["inspections"][0], (
        "Actual relocated inspection evidence was not retained"
    )

    for name, digest in facts["production_hashes"].items():
        assert hashlib.sha256(Path(remote.__file__).with_name(name).read_bytes()).hexdigest() == (
            digest
        ), "Accepted source hashes do not identify the actual exercised implementation"


@pytest.mark.parametrize("mutation,diagnostic", [
    ("alternate-source", "Original CVE source"), ("raw-manifest", "Original CVE manifest"),
    ("different-byte-limit", "Original CVE source"), ("different-timeout", "Original CVE source"),
    ("snapshot", "CLI selected facts"), ("reference", "CLI selected facts"),
    ("model", "CLI selected facts"),
])
def test_ActualCustodyCannotInheritSpoofedTerminalSourceOrSelectedFacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str, diagnostic: str,
) -> None:
    """Real independently verified artifacts remain bound to their original source and model.

    Args:
        tmp_path: Disposable actual acquisition and refused acceptance output root.
        monkeypatch: Owned source/process boundaries and adversarial terminal substitution.
        mutation: Source commit, raw manifest, selected content, reference or saved model drift.
        diagnostic: Original-custody boundary that must refuse the inconsistency.
    """

    observed = OwnedBoundary(monkeypatch, mutation)
    output = tmp_path / "refused"

    with pytest.raises(ValueError, match=diagnostic):
        acceptance.RunAcceptance(output)

    assert len(observed["receives"]) == 1 and not (output / "acceptance.json").exists(), (
        "A terminal/custody inconsistency became acceptance or caused another receive"
    )

    if mutation == "alternate-source":
        assert observed["original"].source.commit == "b" * 40 and (
            observed["document"]["source"]["commit"] == "a" * 40
        ), "The regression did not establish genuine alternate-source custody and a spoofed pin"

    elif mutation == "different-byte-limit":
        assert observed["original"].max_bytes == len(observed["payload"]) + 1, (
            "The refusal did not follow actual custody under a different valid byte limit"
        )

    elif mutation == "different-timeout":
        assert observed["original"].timeout_seconds == 31, (
            "The refusal did not follow actual custody under a different valid total deadline"
        )


@pytest.mark.parametrize("mutation", ["original-corruption", "relocated-corruption"])
def test_OriginalBodyCorruptionRefusesAndRestoresReceiver(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    """Original evidence corruption cannot be hidden by a successful fetch or a prior reparse.

    Args:
        tmp_path: Disposable original evidence and acceptance output root.
        monkeypatch: Actual-owner fixture with controlled on-disk original-body corruption.
        mutation: Corruption before the first load or after actual workspace relocation.
    """

    observed = OwnedBoundary(monkeypatch, mutation)
    output = tmp_path / "refused"

    with pytest.raises(EvidenceError):
        acceptance.RunAcceptance(output)

    assert remote.ReceiveIsolatedHttps is observed["receiver"] and (
        len(observed["receives"]) == 1 and not (output / "acceptance.json").exists()
    ), "A corrupt source passed acceptance, triggered a receive or leaked the offline tripwire"


@pytest.mark.parametrize("mutation", ["inspect-ack", "inspect-source", "inspect-snapshot",
    "inspect-reference", "inspect-handle", "inspect-model", "inspect-object", "inspect-status"])
def test_ActualOfflineInspectionCannotInheritChangedTerminalFacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    """Original replay does not excuse uncertain, foreign or failed product inspection facts.

    Args:
        tmp_path: Disposable relocated original evidence and refused acceptance output root.
        monkeypatch: Owned fixture and actual CLI inspection followed by terminal inconsistency.
        mutation: Explicit inspection acknowledgement, identity, content, model or status drift.
    """

    observed = OwnedBoundary(monkeypatch, mutation)
    output = tmp_path / "refused"

    with pytest.raises(ValueError, match="Relocated original CVE inspection"):
        acceptance.RunAcceptance(output)

    assert len(observed["inspections"]) == 1 and len(observed["receives"]) == 1 and (
        remote.ReceiveIsolatedHttps is observed["receiver"]
        and not (output / "acceptance.json").exists()
    ), "Failed offline inspection published acceptance or altered receiver ownership"


@pytest.mark.parametrize("mutation", ["exit", "stderr", "json"])
def test_MainRetainsProcessFailureEvidenceWithoutSuccessfulMarker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    """Actual acquisition cannot turn an unsuccessful process result into acceptance.

    Args:
        tmp_path: Disposable original evidence and failure-marker output root.
        monkeypatch: Owned actual CLI/SDK and adversarial captured process result.
        mutation: Nonzero exit, unexpected stderr or malformed terminal JSON.
    """

    observed = OwnedBoundary(monkeypatch, mutation)
    output = tmp_path / "failed"
    assert acceptance.Main(["--output", str(output)]) == 1, (
        "The entry point accepted a failed or malformed process result"
    )
    assert json.loads((output / "acceptance-failed.json").read_bytes()) == {
        "status": "failed", "profile": "pinned-cve-https-acceptance",
    }, "A controlled failure lost its explicit honest failure marker"
    assert (output / "fetch.json").is_file() and (output / "fetch-stderr.txt").is_file() and (
        not (output / "acceptance.json").exists() and len(observed["receives"]) == 1
    ), "Failed process facts were erased, retried or labeled successful"


def test_MainEmitsSuccessAfterRealOriginalAndOfflineInspectionProof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """The entry point emits finite success only after actual original-owner verification.

    Args:
        tmp_path: Disposable accepted evidence output root.
        monkeypatch: Owned original source fixture and process/receiver seams.
        capsys: Captured terminal facts to compare with retained acceptance.
    """

    OwnedBoundary(monkeypatch)
    output = tmp_path / "accepted"
    assert acceptance.Main(["--output", str(output)]) == 0, (
        "Complete actual source and offline inspection proof did not reach the entry point"
    )
    assert json.loads(capsys.readouterr().out) == {
        "status": "passed", "received_bytes": acceptance.EXPECTED_BYTES,
        "identifier": acceptance.SOURCE_IDENTIFIER, "source_sha256": acceptance.EXPECTED_SHA256,
    }, "Terminal success disagrees with the exact accepted source pins"
    assert json.loads((output / "acceptance.json").read_bytes())["installed_offline_inspect"], (
        "The entry point claimed success before actual relocated CLI inspection"
    )


def test_ExistingAcceptanceOutputIsPreservedBeforeAnyProcess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Repeated invocation preserves original artifacts and never launches another acquisition.

    Args:
        tmp_path: Disposable output directory representing earlier retained acceptance.
        monkeypatch: Process-launch tripwire for the pre-existing output refusal.
    """

    output = tmp_path / "original"
    output.mkdir()
    original = output / "acceptance.json"
    original.write_bytes(b'{"status":"passed"}\n')

    def Refuse(*args: object, **kwargs: object) -> None:
        """Trip on an attempted process launch after observing existing acceptance output.

        Args:
            args: Forbidden process launch arguments.
            kwargs: Forbidden process launch options.
        """

        raise AssertionError("Existing original output triggered another process")

    monkeypatch.setattr(acceptance.subprocess, "run", Refuse)
    assert acceptance.Main(["--output", str(output)]) == 1 and (
        {p.name: p.read_bytes() for p in output.iterdir()} == {
            "acceptance.json": b'{"status":"passed"}\n',
        }
    ), "Repeated invocation rewrote retained original acceptance evidence"


def test_OfflineTripwireCannotAcquireReplacementBytes() -> None:
    """A receive request during offline inspection fails without replacing original evidence."""

    with pytest.raises(AssertionError, match="attempted another receiver"):
        acceptance.NoReceive("https://example.invalid/owned", 1, timeout_seconds=1)


def test_DocumentationLaneExercisesCveAcceptanceWithoutWeakeningCoverage() -> None:
    """The explicit hosted test selection must exercise this audited tool's actual owner tests."""

    workflow = yaml.safe_load((Path(__file__).resolve().parents[2]
                              / ".github/workflows/documentation.yml").read_text())
    steps = workflow["jobs"]["deterministic-documentation"]["steps"]
    stepName = "Exercise documentation boundaries and enforce per-tool branch coverage"
    selected = [step["run"] for step in steps if step.get("name") == stepName]
    assert len(selected) == 1 and "tests/unit/test_cve_https_acceptance.py" in selected[0], (
        "The explicit documentation selection omitted CVE HTTPS acceptance tool tests"
    )
    assert "--cov=tools --cov-branch --cov-config=/dev/null" in selected[0] and (
        "fuzzy1337.coverage_gate _build/docs/tool-coverage.json tools" in selected[0]
    ), "The documentation lane weakened original per-tool statement/branch coverage enforcement"


def test_CveSourceLaneRequiresExplicitDraftSameRepositoryReadOnlyAuthority() -> None:
    """One explicit CVE checkpoint cannot grant broader or automatic public-source retrieval."""

    root = Path(__file__).resolve().parents[2]
    workflow = yaml.load((root / ".github/workflows/intel-source-acceptance.yml").read_text(),
                         Loader=yaml.BaseLoader)
    assert workflow["on"] == {"pull_request": {
        "branches": ["develop"], "types": ["opened", "synchronize", "reopened"],
    }}, "The explicit CVE checkpoint gained an unrequested trigger or schedule"
    assert workflow["permissions"] == {"contents": "read"}, (
        "Original-source acceptance gained repository mutation authority"
    )
    job = workflow["jobs"]["pinned-cve"]
    assert all(condition in job["if"] for condition in (
        "github.event.pull_request.draft",
        "github.event.pull_request.head.repo.full_name == github.repository",
        "contains(github.event.pull_request.body, '[cve-source-acceptance-checkpoint]')",
    )), "The CVE source checkpoint lost its same-repository explicit Draft admission"
    assert "[intel-source-acceptance-checkpoint]" not in job["if"] and (
        job["timeout-minutes"] == "8" and job.get("permissions", {"contents": "read"}) == {
            "contents": "read",
        }
    ), "The CVE lane reused another source checkpoint or gained time/permission authority"
    checkout = [step for step in job["steps"] if
                step.get("uses", "").startswith("actions/checkout@")]
    assert len(checkout) == 1 and checkout[0]["with"]["persist-credentials"] == "false", (
        "The public-source lane retained repository credentials in its checkout"
    )
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    assert "tests/unit/test_cve_https_acceptance.py" in commands and (
        ".tmp/cve-installed/bin/python -I tools/cve_https_acceptance.py" in commands
        and "--require-hashes" in commands
    ), "The source checkpoint bypassed deterministic tests or the exact installed product"
