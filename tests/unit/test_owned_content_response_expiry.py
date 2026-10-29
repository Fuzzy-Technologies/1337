# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Inert expiry controls and synthetic evidence attacks; no SDK, target or genuine acceptance."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import SimpleNamespace

import pytest

from tests.contract import owned_content_response_ci_expiry_evidence as checker
from tests.contract import owned_content_response_expiry_entrypoint as child
from tests.contract import owned_content_response_expiry_pipeline as pipeline
from tests.contract.owned_content_response_sdk_oracle import Canonical
from tests.unit.test_owned_content_response_ci_revision import Fixture as RevisionFixture
from tests.unit.test_owned_content_response_header_v2_oracle import Fixture as HeaderFixture
from tests.unit.test_owned_content_response_sdk_pipeline import Guard


def Partial() -> tuple:
    """Build marked synthetic partial documents, never original runtime or Save evidence.

    Returns:
        Synthetic acquired/partial state, summary, Save rows, original options and control trace.
    """

    before, after, summary, saves, options = HeaderFixture()
    after["workspace"] = copy.deepcopy(before["workspace"])
    fact = next(row for row in after["model"]["observations"] if row["kind"] == checker.ASSESSMENT)
    basis = fact["attributes"]["authority_basis"]
    basis["issued_at"] = basis["checked_at"]
    basis["expires_at"] = (datetime.fromisoformat(basis["issued_at"]) + timedelta(
        seconds=30)).isoformat()
    fact["reference"] = checker.Reference("observation", {
        key: value for key, value in fact.items() if key != "reference"})
    summary.update(state="partial", failure="admission-expired", workspace_commit="not-attempted",
        workspace_revision=before["workspace"]["revision"], assessment_reference=fact["reference"],
        workflow="owned-response-header-check", source_id=checker.PROVIDER,
        check_id=checker.CHECK, impact="PASSIVE", source_target_reference=basis[
            "source_target_reference"])
    saves = [{**saves[0], "proposal": copy.deepcopy(after["model"]),
        "returned": copy.deepcopy(after["model"])}]
    options["authority"]["analysis_reference"] = options["analysis"]
    guard = Guard()
    guard["saves"] = saves
    control = {"guard": guard, "clock": {"issued_at": basis["issued_at"],
        "expires_at": basis["expires_at"], "duration_seconds": 30,
        "trigger": "original-model-save-return", "elapsed_wall_clock_claimed": False,
        "readings": [{"value": basis["issued_at"], "model_ack_observed": False,
            "returned_model_revision": None}, {"value": basis["expires_at"],
                "model_ack_observed": True,
                "returned_model_revision": after["model"]["revision"]}]},
        "owner_values": [options["authority"]["owner_reference"]] * 2,
        "policy_documents": [copy.deepcopy(options["authority"]["policy"]) for _ in range(2)]}

    return before, after, summary, saves, options, control


def test_SyntheticPartialRequiresBothExactStateAndObservedAckClockBoundary() -> None:
    """A synthetic pass verifies predicates only and establishes no installed acceptance."""

    before, after, summary, saves, options, control = Partial()
    identities = checker.AssertPartialExpiry(before, after, summary, saves, **options)
    checker.AssertControls(control, before, after, options["authority"])
    assert identities["condition_observed"] is True and identities["finding_reference"], (
        "Synthetic expiry invariant differs: identities['condition_observed'] is True and "
        "identities['finding_reference']"
    )


@pytest.mark.parametrize("mutation", ["workspace-revision", "attach-finding", "original-bytes",
    "old-triage", "old-metadata", "unrelated-object", "unrelated-relation", "false-condition",
    "wrong-profile", "source-role", "provenance", "severity", "wrong-model-revision",
    "short-window", "policy-permission", "duration", "no-ack", "workspace-save", "early-expiry",
    "late-expiry", "no-trigger", "elapsed-claim", "no-owner", "changed-owner", "no-policy",
    "changed-policy", "forbidden-call", "no-probe", "completed-summary", "wrong-workflow",
    "remediation", "extra-provenance",
    "finding-outer", "assessment-outer", "provenance-outer"])
def test_SyntheticTamperingCannotHidePartialStateOrInventTheClockTrigger(mutation: str) -> None:
    """Self-consistent synthetic returned model documents still cannot conceal unrelated changes.

    Args:
        mutation: One explicit independent state, original-byte, admission, ACK or clock attack.
    """

    before, after, summary, saves, options, control = Partial()
    fact = next(row for row in after["model"]["observations"] if row["kind"] == checker.ASSESSMENT)
    finding = after["model"]["objects"][-1]

    if mutation == "workspace-revision":
        after["workspace"]["revision"] += 1

    elif mutation == "attach-finding":
        after["workspace"]["object_references"].append(summary["finding_reference"])

    elif mutation == "original-bytes":
        next(iter(after["originals"].values()))["data_hex"] = "00"

    elif mutation == "old-triage":
        after["model"]["objects"][1]["attributes"]["status"] = "closed"

    elif mutation == "old-metadata":
        after["model"]["foreign-metadata"] = "added"

    elif mutation == "unrelated-object":
        after["model"]["objects"].append({"reference": "object:unrelated"})

    elif mutation == "unrelated-relation":
        after["model"]["relations"].append({"reference": "relation:unrelated"})

    elif mutation == "false-condition":
        fact["attributes"]["condition_observed"] = False

    elif mutation == "wrong-profile":
        fact["attributes"]["profile"] = "owned-response-header-absence.v1"

    elif mutation == "source-role":
        fact["attributes"]["original_role_ids"]["stdout"] = "sha256:" + "0" * 64

    elif mutation == "provenance":
        fact["provenance"]["run_reference"] = "analysis:foreign"

    elif mutation == "severity":
        finding["attributes"]["severity"] = "critical"

    elif mutation == "wrong-model-revision":
        after["model"]["revision"] = True

    elif mutation == "short-window":
        fact["attributes"]["authority_basis"]["expires_at"] = (
            fact["attributes"]["authority_basis"]["checked_at"])

    elif mutation == "policy-permission":
        options["authority"]["policy"]["permissions"] = []

    elif mutation == "duration":
        control["clock"]["duration_seconds"] = 31

    elif mutation == "no-ack":
        saves[0]["returned"] = None

    elif mutation == "workspace-save":
        saves.append({**copy.deepcopy(saves[0]), "owner": "workspace"})

    elif mutation == "early-expiry":
        control["clock"]["readings"][0] = copy.deepcopy(control["clock"]["readings"][-1])

    elif mutation == "late-expiry":
        control["clock"]["readings"][-1]["value"] = "2026-10-24T00:00:34+00:00"

    elif mutation == "no-trigger":
        control["clock"]["readings"][-1]["model_ack_observed"] = False

    elif mutation == "elapsed-claim":
        control["clock"]["elapsed_wall_clock_claimed"] = True

    elif mutation == "no-owner":
        control["owner_values"] = []

    elif mutation == "changed-owner":
        control["owner_values"][0] = "actor:foreign"

    elif mutation == "no-policy":
        control["policy_documents"] = []

    elif mutation == "changed-policy":
        control["policy_documents"][0]["permissions"] = []

    elif mutation == "forbidden-call":
        control["guard"]["calls"]["socket.socket"] = 1

    elif mutation == "no-probe":
        control["guard"]["audit_probe_seen"] = False

    elif mutation == "completed-summary":
        summary["state"] = "completed"

    elif mutation == "wrong-workflow":
        summary["workflow"] = "another-workflow"

    elif mutation == "remediation":
        finding["attributes"]["remediation"]["steps"] = ["injected remediation"]

        for row in after["model"]["observations"]:
            if row["kind"] in ("finding-detection", "object-update"):
                row["attributes"] = copy.deepcopy(finding["attributes"])
                row["reference"] = checker.Reference("observation", {
                    key: value for key, value in row.items() if key != "reference"})

    elif mutation == "extra-provenance":
        finding["provenance"].append({"source_id": "foreign"})

    elif mutation == "finding-outer":
        finding["extra"] = "not-an-original-finding-field"

    elif mutation == "provenance-outer":
        fact["provenance"]["extra"] = "not-an-original-provenance-field"
        for row in after["model"]["observations"]:
            if row["kind"] in (checker.ASSESSMENT, "finding-detection", "object-update"):
                row["reference"] = checker.Reference("observation", {
                    key: value for key, value in row.items() if key != "reference"})
        summary["assessment_reference"] = fact["reference"]

    elif mutation == "assessment-outer":
        fact["extra"] = "not-an-original-assessment-field"
        fact["reference"] = checker.Reference("observation", {
            key: value for key, value in fact.items() if key != "reference"})
        summary["assessment_reference"] = fact["reference"]

    if mutation not in ("no-ack", "workspace-save"):
        saves[0]["returned"] = copy.deepcopy(after["model"])
        saves[0]["proposal"] = copy.deepcopy(after["model"])

    with pytest.raises((AssertionError, KeyError, TypeError, ValueError)):
        checker.AssertPartialExpiry(before, after, summary, saves, **options)
        checker.AssertControls(control, before, after, options["authority"])


@pytest.mark.parametrize("seconds", [True, 29, 31, 30.0, "30"])
def test_ControlledClockConstructorRequiresExactThirtySeconds(seconds: object) -> None:
    """Constructor attacks remain inert and cannot substitute another expiry interval.

    Args:
        seconds: Explicit malformed interval or ambiguous numeric value.
    """

    with pytest.raises(ValueError):
        child.ModelAckClock(datetime(2030, 1, 1, tzinfo=timezone.utc), seconds, Guard())


def test_ClockNeverExpiresOnCallCountAndRequiresTheOriginalReturnedModelRow() -> None:
    """Many inert samples cannot advance the clock; only a synthetic observed return arms it."""

    record = Guard()
    start = datetime(2030, 1, 1, tzinfo=timezone.utc)
    clock = child.ModelAckClock(start, 30, record)
    assert all(clock() == start for _ in range(100)), (
        'Synthetic expiry invariant differs: all((clock() == start for _ in range(100)))'
    )
    returned = SimpleNamespace(revision=5)
    record["saves"].append({"owner": "model", "expected_revision": 4,
        "proposal": returned, "returned": returned, "exception_type": None})
    assert clock() == start + timedelta(seconds=30), (
        'Synthetic expiry invariant differs: clock() == start + timedelta(seconds=30)'
    )
    assert clock.Snapshot()["readings"][-1]["model_ack_observed"] is True, (
        'Synthetic expiry invariant differs: '
        "clock.Snapshot()['readings'][-1]['model_ack_observed'] is True"
    )


@pytest.mark.parametrize("mutation", ["pending", "lost", "wrong-owner", "wrong-return",
    "wrong-revision", "bool-basis", "second-row"])
def test_ClockRejectsUnacknowledgedOrSubstitutedSyntheticSaveRows(mutation: str) -> None:
    """A fabricated, lost or additional row cannot masquerade as the original model return.

    Args:
        mutation: One specific unsupported synthetic observer state.
    """

    record = Guard()
    clock = child.ModelAckClock(datetime(2030, 1, 1, tzinfo=timezone.utc), 30, record)
    returned = SimpleNamespace(revision=5)
    row = {"owner": "model", "expected_revision": 4, "proposal": returned,
        "returned": returned, "exception_type": None}
    record["saves"].append(row)

    if mutation == "pending":
        row["returned"] = None

    elif mutation == "lost":
        row["exception_type"] = "OSError"

    elif mutation == "wrong-owner":
        row["owner"] = "workspace"

    elif mutation == "wrong-return":
        row["returned"] = SimpleNamespace(revision=6)

    elif mutation == "wrong-revision":
        returned.revision = 8

    elif mutation == "bool-basis":
        row["expected_revision"] = True

    elif mutation == "second-row":
        record["saves"].append(copy.deepcopy(row))

    with pytest.raises(ValueError):
        clock()


def Selection(tmp_path: Path) -> dict:
    """Declare only synthetic plan inputs, without setup or a source owner.

    Args:
        tmp_path: Explicit disposable unit-test filesystem root.

    Returns:
        Closed future-dated fixture inputs for pure planning tests.
    """

    return {"fixture_id": "inert-expiry-0001", "workspace": str(tmp_path / "workspace"),
        "observations": str(tmp_path / "observations"),
        "url": "http://127.0.0.1:15432/research/content",
        "consent_valid_from": "2030-01-01T00:00:00+00:00",
        "consent_valid_until": "2030-01-01T00:05:00+00:00"}


@pytest.mark.parametrize("mutation", [None, "url", "relative", "overlap", "short", "extra"])
def test_PlanHasOneFixedPartialCaseAndRejectsExpandedInputs(
    tmp_path: Path, mutation: str | None,
) -> None:
    """Pure planning grants no execution and admits no alternate source or general dispatcher.

    Args:
        tmp_path: Explicit disposable unit-test root.
        mutation: One invalid selection, or None for its inert descriptive plan.
    """

    selected = Selection(tmp_path)

    if mutation == "url":
        selected["url"] += "?private=value"

    elif mutation == "relative":
        selected["workspace"] = "relative"

    elif mutation == "overlap":
        selected["observations"] = str(tmp_path / "workspace/observations")

    elif mutation == "short":
        selected["consent_valid_until"] = "2030-01-01T00:00:30+00:00"

    elif mutation == "extra":
        selected["clock"] = "caller-dispatch"

    if mutation is not None:
        with pytest.raises(ValueError):
            pipeline.Plan(selected)

        return

    plan = pipeline.Plan(selected)
    assert plan["scenario"] == checker.SCENARIO and plan["expected_state"] == "partial", (
        "Synthetic expiry invariant differs: plan['scenario'] == checker.SCENARIO and "
        "plan['expected_state'] == 'partial'"
    )
    assert plan["owner_reference"] != plan["attester_reference"], (
        "Synthetic expiry invariant differs: plan['owner_reference'] != "
        "plan['attester_reference']"
    )


@pytest.mark.parametrize("enabled", [False, None, 1, "true"])
def test_ExecutionOptInsRefuseBeforeProductBuildOrSourceWork(enabled: object) -> None:
    """Disabled fixture calls perform no SDK, target, build or original helper dispatch.

    Args:
        enabled: Explicit invalid or absent separate fixture opt-in.
    """

    with pytest.raises(PermissionError):
        pipeline.Run(None, None, enabled=enabled)

    with pytest.raises(PermissionError):
        pipeline.RunInstalled(None, None, None, fixture_id="inert-only", enabled=enabled)

    with pytest.raises(PermissionError):
        child.Analyze(None, None, None, enabled=enabled)


def Artifact(tmp_path: Path, *, runtime_path=Path) -> tuple[Path, Path, Path, dict]:
    """Create marked synthetic CI documents and process envelopes; nothing was executed.

    Args:
        tmp_path: Explicit disposable unit-test root for mocked original JSON/XML files.
        runtime_path: Explicit lexical path flavor for inert original runtime arguments.

    Returns:
        Synthetic JUnit, retained root, case directory and mutable document mapping.
    """

    _, retained, old_case, documents = RevisionFixture(tmp_path, runtime_path=runtime_path)
    before, after, summary, _, options, control = Partial()
    setup = copy.deepcopy(documents["process-003-sdk-fresh-setup/stdout.bin"]["summary"])
    captured = documents["sdk-capture-original.json"]
    selected = copy.deepcopy(documents["stage-04-input.json"]["selection"])
    selected.pop("authority_scenario")
    selected["expected_model_revision"] = before["model"]["revision"]
    plan = documents["pipeline-plan.json"]
    plan.update(scenario=checker.SCENARIO, expected_state="partial", expected_findings=1)
    plan["selection"] = {"workspace": selected["workspace"], "url": options["url"]}
    helpers = {name: {"path": "/mock-only/tests/contract/" + name, "sha256": digest}
        for name, digest in {**checker.OLD_PINS,
            checker.EXPIRY_HELPER: checker.EXPIRY_HELPER_SHA256,
            checker.PIPELINE: checker.PIPELINE_SHA256}.items()}
    checker_name = Path(checker.__file__).name
    helpers[checker_name] = {"path": "/mock-only/tests/contract/" + checker_name,
        "sha256": hashlib.sha256(Path(checker.__file__).read_bytes()).hexdigest()}
    identity = copy.deepcopy(documents["process-003-sdk-fresh-setup/stdout.bin"][
        "installed_identity"])
    terminal_template = copy.deepcopy(documents["process-003-sdk-fresh-setup/process.json"])
    documents = {key: value for key, value in documents.items() if not key.startswith((
        "process-", "sdk-analyze-offline"))}
    identities = {key: summary[key] for key in ("original_receipt_id", "analysis_reference",
        "assessment_reference", "finding_reference", "condition_observed")}
    documents.update({"pipeline-helper-sources.json": helpers,
        "stage-04-input.json": {"selection": selected},
        "stage-02-input.json": {"selection": {"approve_safe_content_response_capture": True,
            "retain_response": True}},
        "sdk-analyze-expiry-offline-original.json": {"summary": copy.deepcopy(summary),
            "exception_type": None, "control": copy.deepcopy(control)},
        "pipeline-result.json": {"state": "checked-post-model-ack-expiry-partial",
            "expected_findings": 1, "identities": identities,
            "runtime_acceptance": "passed", "source_delivery": "normal-eof"}})
    operations = ("fresh-setup", "capture", "inspect", checker.OPERATION, "inspect")
    outputs = (setup, captured["summary"], {"original_inspection": before}, summary,
        {"original_inspection": after})

    for index, (operation, actual) in enumerate(zip(operations, outputs, strict=True), start=3):
        required = {"owned_content_response_sdk_entrypoint.py", checker.EXPIRY_HELPER,
            "owned_content_response_sdk_offline_guard.py"} if operation == checker.OPERATION else {
                "owned_content_response_sdk_entrypoint.py",
                "owned_content_response_sdk_consumer.py"}

        if operation in ("fresh-setup", "inspect"):
            required.update(("owned_content_response_sdk_controls.py",
                "owned_content_response_sdk_setup.py", "owned_response_product_runner.py"))

        output = {"operation": operation, "summary": copy.deepcopy(actual),
            "installed_identity": copy.deepcopy(identity),
            "consumer_sources": {name: copy.deepcopy(helpers[name]) for name in required}}

        if operation == checker.OPERATION:
            output.update(exception_type=None, control=copy.deepcopy(control))

        helper = checker.EXPIRY_HELPER if operation == checker.OPERATION else (
            "owned_content_response_sdk_entrypoint.py")
        terminal = copy.deepcopy(terminal_template)
        argv = [identity["python"], "-I", "-B", helpers[helper]["path"], operation,
            str(runtime_path(terminal["cwd"]) / f"stage-{index - 2:02d}-input.json"), "--execute"]
        terminal["argv"] = argv
        raw = Canonical(output)
        terminal["stdout"].update(observed_size_bytes=len(raw), retained_size_bytes=len(raw),
            observed_sha256=hashlib.sha256(raw).hexdigest())
        prefix = f"process-{index:03d}-sdk-{operation}"
        documents[prefix + "/stdout.bin"] = output
        documents[prefix + "/process.json"] = terminal
        documents[prefix + "/invocation.json"] = {"schema_version": 1, "argv": argv,
            "cwd": terminal["cwd"], "timeout_seconds": 35, "stdin": "closed-devnull",
            "state": "not-launched", "returncode": None, "terminal_return_observed": False,
            "installation": copy.deepcopy(terminal["installation"])}

    junit = tmp_path / "expiry.xml"
    junit.write_text('<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0">'
        f'<testcase classname="{checker.CASE_CLASS}" name="{checker.CASE_NAME}"/>'
        '</testsuite></testsuites>')

    return junit, retained, old_case.with_name(checker.SCENARIO), documents


@pytest.mark.parametrize("runtime_path", [PurePosixPath, PureWindowsPath], ids=["posix", "windows"])
def test_SyntheticExpiryArgumentsPreserveExactRecordedPathFlavor(
    tmp_path: Path, monkeypatch, runtime_path,
) -> None:
    """Both runtime path flavors pass unchanged strict checks; foreign separators still refuse."""

    junit, retained, case, documents = Artifact(tmp_path, runtime_path=runtime_path)
    original_path = checker.Path

    def RecordedPath(value):
        """Select the synthetic cwd flavor while retaining the actual artifact filesystem owner."""

        return runtime_path(value) if value == "/mock-only/pipeline" else original_path(value)

    monkeypatch.setattr(checker, "Path", RecordedPath)

    for name, document in documents.items():
        destination = case / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(Canonical(document))

        if destination.name == "stdout.bin":
            destination.with_name("stderr.bin").write_bytes(b"")

    assert checker.RequireOutcome(junit, retained)["state"] == (
        "checked-post-model-ack-expiry-partial"), (
        "Explicit runtime path flavor must retain exact child argv and partial-state admission")
    other_path = PureWindowsPath if runtime_path is PurePosixPath else PurePosixPath
    changed = documents["process-006-sdk-analyze-expiry-offline/process.json"]
    changed["argv"][5] = str(other_path(changed["cwd"]) / "stage-04-input.json")

    for name in ("process.json", "invocation.json"):
        key = "process-006-sdk-analyze-expiry-offline/" + name
        (case / key).write_bytes(Canonical(documents[key]))

    with pytest.raises(AssertionError, match="No timeout or absent terminal is success"):
        checker.RequireOutcome(junit, retained)


@pytest.mark.parametrize("mutation", [None, "skip", "wrong-case", "old-helper", "new-helper",
    "pipeline-hash", "child-source", "installed-source", "terminal-digest", "argv", "timeout",
    "extra-child", "capture-lost-ack", "source-bytes", "selected-approval", "selected-basis",
    "child-control", "child-summary", "bool-count", "sentinel-contact"])
def test_SyntheticOriginalArtifactNeedsExactChildrenSourcesAndPartialState(
    tmp_path: Path, mutation: str | None,
) -> None:
    """Synthetic complete envelopes cannot hide wrong source, process, custody or partial facts.

    Args:
        tmp_path: Explicit disposable unit artifact owner.
        mutation: One rejected evidence substitution, or None for an inert predicate pass.
    """

    junit, retained, case, documents = Artifact(tmp_path)
    child_output = documents["process-006-sdk-analyze-expiry-offline/stdout.bin"]

    if mutation == "skip":
        junit.write_text(junit.read_text().replace('skipped="0"', 'skipped="1"'))

    elif mutation == "wrong-case":
        junit.write_text(junit.read_text().replace(checker.CASE_NAME, "unrelated_test"))

    elif mutation == "old-helper":
        documents["pipeline-helper-sources.json"]["owned_content_response_sdk_entrypoint.py"][
            "sha256"] = "0" * 64

    elif mutation == "new-helper":
        documents["pipeline-helper-sources.json"][checker.EXPIRY_HELPER]["sha256"] = "0" * 64

    elif mutation == "pipeline-hash":
        documents["pipeline-helper-sources.json"][checker.PIPELINE]["sha256"] = "0" * 64

    elif mutation == "child-source":
        child_output["consumer_sources"][checker.EXPIRY_HELPER]["sha256"] = "0" * 64

    elif mutation == "installed-source":
        next(iter(child_output["installed_identity"]["installed_sources"].values()))[
            "sha256"] = "0" * 64

    elif mutation == "terminal-digest":
        documents["process-006-sdk-analyze-expiry-offline/process.json"]["stdout"][
            "observed_sha256"] = "0" * 64

    elif mutation == "argv":
        documents["process-006-sdk-analyze-expiry-offline/process.json"]["argv"][2] = "-E"

    elif mutation == "timeout":
        documents["process-006-sdk-analyze-expiry-offline/process.json"]["timeout_seconds"] = 350

    elif mutation == "extra-child":
        documents["process-008-sdk-inspect/stdout.bin"] = {}

    elif mutation == "capture-lost-ack":
        documents["sdk-capture-original.json"]["store_saves"][0]["returned"] = None

    elif mutation == "source-bytes":
        next(iter(documents["process-005-sdk-inspect/stdout.bin"]["summary"][
            "original_inspection"]["originals"].values()))["data_hex"] = "00"

    elif mutation == "selected-approval":
        documents["stage-04-input.json"]["selection"]["approve_passive_header_check"] = False

    elif mutation == "selected-basis":
        documents["stage-04-input.json"]["selection"]["expected_model_revision"] -= 1

    elif mutation == "child-control":
        child_output["control"]["clock"]["duration_seconds"] = 31

    elif mutation == "child-summary":
        child_output["summary"]["state"] = "completed"

    elif mutation == "bool-count":
        documents["pipeline-result.json"]["expected_findings"] = True

    elif mutation == "sentinel-contact":
        documents["sentinel-source-final.json"]["counters"]["contacts"] = 1

    for name, document in documents.items():
        destination = case / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(Canonical(document))

        if destination.name == "stdout.bin":
            destination.with_name("stderr.bin").write_bytes(b"")

    if mutation is None:
        assert checker.RequireOutcome(junit, retained)["state"] == (
            "checked-post-model-ack-expiry-partial"), (
            'Synthetic expiry invariant differs: checker.RequireOutcome(junit, '
            "retained)['state'] == 'checked-post-model-ack-expiry-partial'"
        )

    else:
        with pytest.raises((AssertionError, KeyError, TypeError, ValueError)):
            checker.RequireOutcome(junit, retained)


def test_MockedAnalysisForwardsSeparateApprovalReadersAndRetainsActualObserverOrder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Marked doubles exercise helper wiring only; no installed SDK, policy or store is invoked.

    Args:
        tmp_path: Explicit disposable observation owner.
        monkeypatch: Scoped replacements for original readers and the sole SDK call boundary.
    """

    record = Guard()
    now = datetime.now(timezone.utc)
    policy = SimpleNamespace(max_authorization_seconds=30)
    config = {"workspace": str(tmp_path / "workspace"), "scope_id": "mock-only",
        "url": "http://127.0.0.1:15432/research/content", "owner_reference": "actor:mock",
        "policy": str(tmp_path / "policy.json"), "original_receipt_id": "sha256:" + "1" * 64,
        "analysis_reference": "analysis:mock", "expected_model_revision": 4,
        "expected_workspace_revision": 2, "approve_passive_header_check": True}

    @contextmanager
    def OfflineGuard(**options: object) -> Iterator[dict]:
        """Yield marked synthetic observer data, without installing actual product tripwires.

        Args:
            options: Exact original false-historical and separate true opt-in helper flags.

        Yields:
            Synthetic empty Save observations for the mocked SDK boundary.
        """

        assert options == {"historical": False, "enabled": True}, (
            "Synthetic expiry invariant differs: options == {'historical': False, 'enabled': "
            'True}'
        )

        yield record

    def Detached(value: dict) -> dict:
        """Detach only synthetic rows after the fake callback, without a real Save observation.

        Args:
            value: Synthetic unit observer mutated by the explicit fake SDK callback below.

        Returns:
            JSON-safe marked synthetic observer documents.
        """

        return {**value, "saves": [{**row, "proposal": {"revision": row["proposal"].revision},
            "returned": {"revision": row["returned"].revision}} for row in value["saves"]]}

    def Apply(selected: dict, policy_reader: object, owner: object, clock: object) -> dict:
        """Simulate return ordering only, never call or claim a product/stored result.

        Args:
            selected: Original unchanged independent approval and current-basis selection.
            policy_reader: Actual supplied fixture reader, replaced with an inert policy source.
            owner: Supplied explicit trusted fixture actor reader.
            clock: New source-owned clock observing the marked synthetic row.

        Returns:
            Explicitly synthetic summary, without any genuine partial-state assertion.
        """

        assert selected == config and selected["approve_passive_header_check"] is True, (
            'Synthetic expiry invariant differs: selected == config and '
            "selected['approve_passive_header_check'] is True"
        )
        assert policy_reader() is policy and owner() == config["owner_reference"], (
            'Synthetic expiry invariant differs: policy_reader() is policy and owner() == '
            "config['owner_reference']"
        )
        first = clock()
        assert policy_reader() is policy and owner() == config["owner_reference"], (
            'Synthetic expiry invariant differs: policy_reader() is policy and owner() == '
            "config['owner_reference']"
        )
        returned = SimpleNamespace(revision=5)
        record["saves"].append({"owner": "model", "expected_revision": 4,
            "proposal": returned, "returned": returned, "exception_type": None})
        assert clock() == first + timedelta(seconds=30), (
            'Synthetic expiry invariant differs: clock() == first + timedelta(seconds=30)'
        )

        return {"state": "synthetic-unit-only"}

    monkeypatch.setattr(child, "ReadAuthority", lambda *_: ({"authorization": {
        "valid_from": (now - timedelta(seconds=1)).isoformat(),
        "valid_until": (now + timedelta(seconds=300)).isoformat()}}, policy))
    monkeypatch.setattr(child, "ReadPolicy", lambda _: (policy, {"synthetic_policy": True}))
    monkeypatch.setattr(child, "Apply", Apply)
    observations = tmp_path / "observations"
    result = child.Analyze(config, observations,
        SimpleNamespace(OfflineGuard=OfflineGuard, DetachedGuard=Detached), enabled=True)
    assert json.loads((observations / "expiry-analysis.json").read_bytes()) == result, (
        'Synthetic expiry invariant differs: json.loads((observations / '
        "'expiry-analysis.json').read_bytes()) == result"
    )
    assert result["exception_type"] is None and result["control"]["owner_values"] == [
        config["owner_reference"]] * 2, (
        "Synthetic expiry invariant differs: result['exception_type'] is None and "
        "result['control']['owner_values'] == [config['owner_reference']] * 2"
    )


def test_MockedFiniteSequenceSelectsCurrentBasesAndStopsAfterFiveChildren(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Marked handoffs verify orchestration only; pure state predicates are exercised separately.

    Args:
        tmp_path: Explicit disposable inert plan root.
        monkeypatch: Scoped predicate spies; no product interface is substituted in genuine code.
    """

    selected = Selection(tmp_path)
    plan = pipeline.Plan(selected)
    calls = []
    acquired = {"model": {"revision": 4}, "workspace": {"revision": 2}, "originals": {}}
    setup = {"state": {}, "scope": {"scope_id": plan["scope_id"],
        "workspace_id": plan["workspace_id"], "authorization": {"state": "granted",
            "authority_reference": plan["attester_reference"],
            "record_reference": plan["consent_reference"],
            "valid_from": selected["consent_valid_from"],
            "valid_until": selected["consent_valid_until"]}}, "policies": {
                "acquisition": {"path": "/mock-only/safe.json"},
                "analysis": {"path": "/mock-only/passive.json", "document": {}}}}

    def Handoff(operation: str, inputs: dict, observations: Path) -> dict:
        """Return marked synthetic phase values, recording only the selected finite transport.

        Args:
            operation: Fixed named stage selected by the new driver.
            inputs: Exact independent inputs and current revision bases passed to that stage.
            observations: New original observation identity selected by the driver.

        Returns:
            Explicitly synthetic child documents; no original acceptance facts.
        """

        calls.append((operation, inputs, observations))

        if operation == "fresh-setup":
            return setup

        if operation == "capture":
            return {"exception_type": None, "summary": {"original_receipt_id": "mock:receipt",
                "original_job_id": "mock:job", "source_facts": {}}, "store_saves": []}

        if operation == "inspect":
            return {"state": acquired}

        assert operation == checker.OPERATION and inputs["approve_passive_header_check"] is True, (
            'Synthetic expiry invariant differs: operation == checker.OPERATION and '
            "inputs['approve_passive_header_check'] is True"
        )
        assert inputs["expected_model_revision"] == 4 and (
            inputs["expected_workspace_revision"] == 2), (
            "Synthetic expiry invariant differs: inputs['expected_model_revision'] == 4 and "
            "inputs['expected_workspace_revision'] == 2"
        )

        return {"exception_type": None, "summary": {}, "control": {"guard": {"saves": []}}}

    monkeypatch.setattr(pipeline, "AssertSdkSaveTransition", lambda *_, **__: None)
    monkeypatch.setattr(pipeline, "AssertContentParts", lambda *_, **__: None)
    monkeypatch.setattr(pipeline, "AssertPartialExpiry", lambda *_, **__: {"synthetic_only": True})
    monkeypatch.setattr(pipeline, "AssertControls", lambda *_, **__: None)
    result = pipeline.Run(plan, Handoff, enabled=True)
    assert [row[0] for row in calls] == ["fresh-setup", "capture", "inspect", checker.OPERATION,
        "inspect"], (
        "Synthetic expiry invariant differs: [row[0] for row in calls] == ['fresh-setup', "
        "'capture', 'inspect', checker.OPERATION, 'inspect']"
    )
    assert len({row[2] for row in calls}) == 5 and "runtime_acceptance" not in result, (
        'Synthetic expiry invariant differs: len({row[2] for row in calls}) == 5 and '
        "'runtime_acceptance' not in result"
    )


def test_SourcePinsPreserveAllAcceptedHelpersAndFreezeBothNewExecutableSources() -> None:
    """Static source hashing performs no helper, SDK or installed operation execution."""

    directory = Path(checker.__file__).resolve().parent

    for name, digest in {**checker.OLD_PINS,
        checker.EXPIRY_HELPER: checker.EXPIRY_HELPER_SHA256,
        checker.PIPELINE: checker.PIPELINE_SHA256}.items():
        assert hashlib.sha256((directory / name).read_bytes()).hexdigest() == digest, (
            'Synthetic expiry invariant differs: hashlib.sha256((directory / '
            'name).read_bytes()).hexdigest() == digest'
        )
