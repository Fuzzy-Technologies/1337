# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Mocked acceptance-helper contracts only; no target, worker, build or installed runtime."""

from __future__ import annotations

import copy
import errno
import hashlib

import pytest

from tests.contract.owned_content_response_oracle import CaseMatrix
from tests.contract.owned_content_response_product_runner import (
    SOURCE_MODULES,
    AbsoluteRuntimePath,
    AssertContentInstallation,
    AssertContentLauncherEvidence,
    AssertContentSourceFacts,
    AssertContentWorkerCase,
    AssertOriginalPeerEnd,
    AssertWorkerCohort,
    WorkerCaseIdentities,
)

PYTHON = "/owned/environment/bin/python"
COMMIT = "1" * 40
TREE = "2" * 40


def Process(stdout: bytes, url: str, code: int) -> dict:
    """Author mocked terminal metadata without launching or claiming an actual process."""

    result = {"schema_version": 1, "state": "returned", "terminal_return_observed": True,
        "returncode": code, "stdin": "closed-devnull", "argv": [PYTHON, "-I", "-B", "-m",
            "fuzzy1337.owned_content_response_worker", url]}

    for role, raw in (("stdout", stdout), ("stderr", b"")):
        result[role] = {"observed": True, "complete_original": True, "timeout_prefix": False,
            "retention_overflow": False, "observed_size_bytes": len(raw),
            "retained_size_bytes": len(raw), "observed_sha256": hashlib.sha256(raw).hexdigest()}

    return result


@pytest.mark.parametrize("case", CaseMatrix(), ids=lambda case: case.name)
@pytest.mark.parametrize("authority", ["127.0.0.1:15432", "[::1]:15432"])
def test_WorkerOracleChecksAdmittedAndRefusedOriginalShapesWithoutExecution(case, authority):
    """All expected source variants exercise pure shape checks, never genuine case acceptance."""

    url = f"http://{authority}{case.path}"
    stdout = case.ExpectedStdout(url)
    process = Process(stdout, url, 0 if case.error is None else 2)
    AssertContentWorkerCase(case.name, url, process, stdout, b"", python=PYTHON)


@pytest.mark.parametrize("mutation", ["timeout", "missing-terminal", "prefix", "overflow",
    "digest", "size", "exit", "argv", "foreign-original", "stderr"])
def test_OriginalWorkerFactsRefuseControlFailuresAndSubstitutedBytes(mutation):
    """No timeout prefix, changed command, foreign wire or invented terminal can satisfy a case."""

    case = next(case for case in CaseMatrix() if case.name == "missing")
    url = f"http://127.0.0.1:15432{case.path}"
    stdout, stderr = case.ExpectedStdout(url), b""
    process = Process(stdout, url, 0)

    if mutation == "timeout":
        process["state"] = "timeout"

    elif mutation == "missing-terminal":
        process["terminal_return_observed"] = False

    elif mutation in ("prefix", "overflow"):
        process["stdout"]["timeout_prefix" if mutation == "prefix" else "retention_overflow"] = True

    elif mutation == "digest":
        process["stdout"]["observed_sha256"] = "0" * 64

    elif mutation == "size":
        process["stdout"]["retained_size_bytes"] -= 1

    elif mutation == "exit":
        process["returncode"] = 2

    elif mutation == "argv":
        process["argv"].remove("-I")

    elif mutation == "foreign-original":
        stdout = b"{}"
        process = Process(stdout, url, 0)

    else:
        stderr = b"unexpected diagnostic"

    with pytest.raises(AssertionError):
        AssertContentWorkerCase(case.name, url, process, stdout, stderr, python=PYTHON)


def Installation() -> tuple[dict, dict]:
    """Create clearly mocked source/wheel/import identities without reading any runtime."""

    modules = {name: hashlib.sha256(name.encode()).hexdigest() for name in SOURCE_MODULES}
    identity = {"schema_version": 1, "source_commit": COMMIT, "source_tree": TREE,
        "source_modules_sha256": modules, "wheel_modules_sha256": dict(modules),
        "wheel_size_bytes": 123, "wheel_sha256": "a" * 64, "distribution_version": "0.0.mock"}
    imported = {"distribution_version": "0.0.mock", "installed_sources": {name: {
        "path": "/owned/environment/lib/python3.12/site-packages/fuzzy1337/" + name,
        "sha256": digest} for name, digest in modules.items()}}

    return identity, imported


@pytest.mark.parametrize("prefix", ["/owned/lib/site-packages/fuzzy1337/",
    "C:\\owned\\Lib\\site-packages\\fuzzy1337\\", "C:/owned/Lib/site-packages/fuzzy1337/"])
def test_InstalledAbsolutePathPortabilityPreservesExactModuleBindings(prefix):
    """Real Windows drive-absolute spelling is valid without reading or running that platform."""

    identity, imported = Installation()

    for name in SOURCE_MODULES:
        suffix = name.replace("/", "\\") if "\\" in prefix else name
        imported["installed_sources"][name]["path"] = prefix + suffix

    AssertContentInstallation(identity, imported, commit=COMMIT, tree=TREE)


@pytest.mark.parametrize("python", ["/owned/bin/python", "C:\\owned\\Scripts\\python.exe",
    "C:/owned/Scripts/python.exe"])
def test_WorkerAbsoluteInterpreterPortabilityPreservesOriginalArgv(python):
    """Either installed absolute path flavor remains the exact original invocation value."""

    case = next(case for case in CaseMatrix() if case.name == "missing")
    url = f"http://127.0.0.1:15432{case.path}"
    stdout = case.ExpectedStdout(url)
    process = Process(stdout, url, 0)
    process["argv"][0] = python
    AssertContentWorkerCase(case.name, url, process, stdout, b"", python=python)


@pytest.mark.parametrize("path", ["relative/bin/python", "C:owned\\python.exe",
    "\\owned\\python.exe", "C:\\owned\\..\\python.exe", "C:/owned/../python.exe",
    "/owned/../bin/python", "C:\\owned\\.\\python.exe", "/owned/./bin/python",
    "\\\\server\\share\\python.exe", "\\\\?\\C:\\owned\\python.exe",
    "//server/share/python", "C:\\owned\\python.exe:stream", "/owned//bin/python"])
def test_RuntimePathPortabilityRefusesAmbiguousOrNonlocalSpelling(path):
    """Lexical portability never introduces normalization, implicit drives or traversal."""

    with pytest.raises(AssertionError):
        AbsoluteRuntimePath(path)


@pytest.mark.parametrize("mutation", ["drive", "root", "flavor", "suffix"])
def test_WindowsInstalledPathsRetainOneExactPackageRootAndSuffix(mutation):
    """A valid module digest alone cannot bridge foreign drives, roots or source locations."""

    identity, imported = Installation()

    for name in SOURCE_MODULES:
        imported["installed_sources"][name]["path"] = (
            "C:\\owned\\Lib\\site-packages\\fuzzy1337\\" + name.replace("/", "\\"))

    name = SOURCE_MODULES[0]
    prefix = {"drive": "D:\\owned\\Lib\\site-packages\\fuzzy1337\\",
        "root": "C:\\other\\Lib\\site-packages\\fuzzy1337\\",
        "flavor": "/owned/lib/site-packages/fuzzy1337/",
        "suffix": "C:\\owned\\Lib\\site-packages\\other-package\\"}[mutation]
    imported["installed_sources"][name]["path"] = prefix + name

    with pytest.raises(AssertionError):
        AssertContentInstallation(identity, imported, commit=COMMIT, tree=TREE)


def test_ExactPinnedSourceWheelAndInstalledModuleBinding():
    """Pure identity reconciliation requires all fixed modules from one installed package."""

    identity, imported = Installation()
    AssertContentInstallation(identity, imported, commit=COMMIT, tree=TREE)
    identities = WorkerCaseIdentities()
    assert len(identities) == 118 and len(set(identities)) == len(identities), (
        "The frozen matrix requires 59 distinct worker cases in each literal family")


@pytest.mark.parametrize("mutation", [None, "missing", "duplicate", "foreign", "skipped",
    "failed", "xfail"])
def test_WorkerCohortRequiresEachExactIdentityWithZeroSkips(mutation):
    """Reported cohort completeness never converts an omitted or nonpassing identity to green."""

    results = [{"identity": identity, "status": "passed"} for identity in WorkerCaseIdentities()]

    if mutation is None:
        AssertWorkerCohort(results)

        return

    if mutation == "missing":
        results.pop()

    elif mutation == "duplicate":
        results[-1] = dict(results[0])

    elif mutation == "foreign":
        results[0]["identity"] = "worker:foreign:not-the-matrix"

    else:
        results[0]["status"] = mutation

    with pytest.raises(AssertionError):
        AssertWorkerCohort(results)


@pytest.mark.parametrize("mutation", ["tree", "wheel", "import", "missing", "checkout",
    "mixed-root", "relative", "version"])
def test_SourceWheelImportMismatchCannotBecomeInstalledAcceptance(mutation):
    """Source drift, missing owners and import fallback remain explicit failures."""

    identity, imported = copy.deepcopy(Installation())
    name = SOURCE_MODULES[0]

    if mutation == "tree":
        identity["source_tree"] = "3" * 40

    elif mutation == "wheel":
        identity["wheel_modules_sha256"][name] = "b" * 64

    elif mutation == "import":
        imported["installed_sources"][name]["sha256"] = "c" * 64

    elif mutation == "missing":
        del imported["installed_sources"][name]

    elif mutation == "version":
        imported["distribution_version"] = "other"

    else:
        prefix = {"checkout": "/checkout/src/fuzzy1337/",
            "mixed-root": "/other/site-packages/fuzzy1337/",
            "relative": "relative/site-packages/fuzzy1337/"}[mutation]
        imported["installed_sources"][name]["path"] = prefix + name

    with pytest.raises(AssertionError):
        AssertContentInstallation(identity, imported, commit=COMMIT, tree=TREE)


def SourceFacts(name="missing", address="127.0.0.1"):
    """Author explicit mocked source/sentinel facts without any fixture or socket construction."""

    from tests.contract.owned_content_response_oracle import RequestBytes

    case = next(case for case in CaseMatrix() if case.name == name)
    host = "[::1]" if address == "::1" else address
    origin, other = f"http://{host}:15432", f"http://{host}:15433"
    url = origin + case.path
    counters = {"contacts": 1, "retained_contacts": 1, "contact_overflow": 0,
        "active_connections": 0, "active_handlers": 0, "active_dispatches": 0,
        "maximum_active_handlers": 1, "completed_responses": 1, "errors": 0, "error_overflow": 0}
    record = {"sequence": 1, "variant": name, "target": case.path,
        "request_hex": RequestBytes(url).hex(), "received_bytes": len(RequestBytes(url)),
        "request_truncated": False, "response_hex": case.Wire().hex(),
        "sent_bytes": len(case.Wire()), "accepted_at": 1.0, "deadline_at": 8.0,
        "active_at_start": 1, "completion_sequence": 1, "admission_state": (
            "sent-peer-ended" if case.eof_mode == "hold-until-peer-eof" else "completed"),
        "failure": None, "socket_closed": True, "shutdown_error": False, "shutdown_errno": None,
        "close_error": False, "close_errno": None}
    signal = {"kind": "eof", "phase": "peer-receive", "before_local_close": True,
        "within_hold": True, "error_type": None, "errno": None, "winerror": None}
    main = {"schema_version": 1, "target_yielded": True, "owner_state": "settled",
        "listener_alive": False, "listener_closed": True, "origin": origin,
        "cleanup_returned": True, "cleanup_failure": None, "idle_before_local_close": True,
        "counters": counters, "errors": [], "contacts": [record], "accepted_endpoints": {"0": {
            "local_address": address, "local_port": 15432, "peer_address": address,
            "peer_port": 26000, "peer_terminal": signal}}}
    sentinel = copy.deepcopy(main)
    sentinel.update(origin=other, contacts=[], accepted_endpoints={})
    sentinel["counters"] = {key: 0 for key in counters}

    return name, url, main, sentinel, other


@pytest.mark.parametrize("name", ["missing", "held-eof", "invalid-utf8"])
@pytest.mark.parametrize("address", ["127.0.0.1", "::1"])
def test_SourceFactsKeepNormalHeldAndRefusalDeliveryDistinct(name, address):
    """Mocked delivery can be normal EOF or held peer end, never product acceptance."""

    name, url, main, sentinel, other = SourceFacts(name, address)
    observed = AssertContentSourceFacts(name, url, main, sentinel, sentinel_origin=other)
    assert observed == ("held-peer-ended" if name == "held-eof" else "normal-eof"), (
        "Original source-delivery classification must remain distinct from worker admission")


@pytest.mark.parametrize("mutation", ["absent-sentinel", "foreign-owner", "contact-overflow",
    "bool-count", "active-handler", "listener-live", "cleanup-unreturned", "late-idle",
    "cleanup-error", "wrong-request", "truncated", "foreign-wire", "wrong-peer", "bool-port",
    "wrong-index", "reset-normal", "late-end", "local-end", "unknown-end", "bool-sequence",
    "nonfinite-clock", "renewed-clock", "sent-only", "unclosed"])
def test_SourceFactsCounterexamplesCannotPromoteSettlementOrEof(mutation):
    """Counts/bytes alone cannot replace original ownership, cleanup and actual timely EOF facts."""

    name, url, main, sentinel, other = SourceFacts()
    record = main["contacts"][0]
    endpoint = main["accepted_endpoints"]["0"]
    signal = endpoint["peer_terminal"]

    if mutation == "absent-sentinel":
        sentinel = {}

    elif mutation == "foreign-owner":
        sentinel["origin"] = main["origin"]

    elif mutation in ("contact-overflow", "bool-count", "active-handler"):
        key, value = {"contact-overflow": ("contact_overflow", 1),
            "bool-count": ("contacts", True), "active-handler": ("active_handlers", 1)}[mutation]
        main["counters"][key] = value

    elif mutation in ("listener-live", "cleanup-unreturned", "late-idle", "cleanup-error"):
        key, value = {"listener-live": ("listener_alive", True),
            "cleanup-unreturned": ("cleanup_returned", False),
            "late-idle": ("idle_before_local_close", False),
            "cleanup-error": ("cleanup_failure", "RuntimeError")}[mutation]
        main[key] = value

    elif mutation in ("wrong-request", "truncated", "foreign-wire", "bool-sequence",
        "nonfinite-clock", "renewed-clock", "sent-only", "unclosed"):
        key, value = {"wrong-request": ("request_hex", b"GET /other HTTP/1.1\r\n".hex()),
            "truncated": ("request_truncated", True), "foreign-wire": ("response_hex", "00"),
            "bool-sequence": ("sequence", True), "nonfinite-clock": ("accepted_at", float("nan")),
            "renewed-clock": ("deadline_at", 9.0), "sent-only": ("completion_sequence", None),
            "unclosed": ("socket_closed", False)}[mutation]
        record[key] = value

    elif mutation in ("wrong-peer", "bool-port"):
        endpoint["peer_address" if mutation == "wrong-peer" else "local_port"] = (
            "127.0.0.2" if mutation == "wrong-peer" else True)

    elif mutation == "wrong-index":
        main["accepted_endpoints"] = {"1": endpoint}

    else:
        key, value = {"reset-normal": ("kind", "peer-reset"), "late-end": ("within_hold", False),
            "local-end": ("before_local_close", False), "unknown-end": ("kind", "os-error")
        }[mutation]
        signal[key] = value

    with pytest.raises(AssertionError):
        AssertContentSourceFacts(name, url, main, sentinel, sentinel_origin=other)


@pytest.mark.parametrize("kind", ["recognized-reset", "unknown-reset", "source-error"])
def test_SourceFactsHeldResetAndRefusedSourceErrorAreNotNormalEof(kind):
    """Held reset needs actual known error numbers; source failure retains incomplete delivery."""

    name, url, main, sentinel, other = SourceFacts("held-eof" if kind != "source-error" else (
        "invalid-utf8"))

    if kind == "source-error":
        main["contacts"][0].update(failure="owned-content-request-failure",
            admission_state="failed", completion_sequence=None)
        main["counters"].update(completed_responses=0, errors=1)
        main["errors"] = ["owned-content-request-failure"]
        main["accepted_endpoints"]["0"]["peer_terminal"] = None
        assert AssertContentSourceFacts(name, url, main, sentinel, sentinel_origin=other) == (
            "refused-source-error"), "A retained source error is never complete delivery"

        return

    signal = main["accepted_endpoints"]["0"]["peer_terminal"]
    signal.update(kind="peer-reset", error_type="ConnectionResetError",
        errno=104 if kind == "recognized-reset" else None)

    if kind == "recognized-reset":
        assert AssertContentSourceFacts(name, url, main, sentinel, sentinel_origin=other) == (
            "held-peer-ended"), "Recognized held reset is peer end, never a normal EOF claim"

    else:
        with pytest.raises(AssertionError):
            AssertContentSourceFacts(name, url, main, sentinel, sentinel_origin=other)


@pytest.mark.parametrize("number,windows,allowed", [
    (errno.ECONNRESET, 10 ** 100, False), (10 ** 100, 10054, False),
    (errno.ECONNRESET, None, True), (None, 10054, True),
    (errno.ECONNRESET, 10053, True), (errno.ECONNREFUSED, 10054, True),
    (True, 10054, False), (errno.ECONNRESET, True, False), (None, None, False)])
def test_HeldPeerResetCompanionNumbersMustMatchOriginalSanitizedDomains(number, windows, allowed):
    """Each retained numeric domain is independent even when its companion proves peer reset."""

    signal = {"kind": "peer-reset", "phase": "peer-receive", "before_local_close": True,
        "within_hold": True, "error_type": "ConnectionResetError", "errno": number,
        "winerror": windows}

    if allowed:
        AssertOriginalPeerEnd(signal, allow_reset=True)

    else:
        with pytest.raises(AssertionError):
            AssertOriginalPeerEnd(signal, allow_reset=True)


@pytest.mark.parametrize("mutation", [None, "cwd", "timeout", "installation", "prelaunch",
    "digest-drift", "identity-drift", "digest-malformed", "digest-type", "missing-digest",
    "bool-terminal-timeout"])
def test_LauncherEvidenceKeepsIndependentPrelaunchAndTerminalBindings(mutation):
    """Only retained original launch intent may join terminal bytes and installed identities."""

    case = next(case for case in CaseMatrix() if case.name == "missing")
    url = "http://127.0.0.1:15432" + case.path
    identity, imported = Installation()
    installation = {"manifest_sha256": "d" * 64, "identity": identity}
    stdout = case.ExpectedStdout(url)
    process = Process(stdout, url, 0)
    budget = 1 if mutation == "bool-terminal-timeout" else 10
    process.update(cwd="/owned/launch", timeout_seconds=budget,
        installation=copy.deepcopy(installation))
    invocation = {key: copy.deepcopy(value) for key, value in process.items()
        if key not in ("stdout", "stderr")}
    invocation.update(state="not-launched", returncode=None, terminal_return_observed=False)

    if mutation == "cwd":
        process["cwd"] = "/other/launch"

    elif mutation == "timeout":
        process["timeout_seconds"] = 20

    elif mutation == "installation":
        process["installation"] = {"identity": {}}

    elif mutation == "prelaunch":
        invocation["terminal_return_observed"] = True

    elif mutation == "digest-drift":
        process["installation"]["manifest_sha256"] = "e" * 64

    elif mutation == "identity-drift":
        process["installation"]["identity"]["source_tree"] = "3" * 40

    elif mutation in ("digest-malformed", "digest-type", "missing-digest"):
        if mutation == "missing-digest":
            del installation["manifest_sha256"]

        else:
            installation["manifest_sha256"] = "not-a-sha256" if mutation == (
                "digest-malformed") else 123

        process["installation"] = copy.deepcopy(installation)
        invocation["installation"] = copy.deepcopy(installation)

    elif mutation == "bool-terminal-timeout":
        process["timeout_seconds"] = True

    def Check():
        """Check only supplied mocked records; this helper never launches a process."""

        AssertContentLauncherEvidence(case.name, url, installation, imported, invocation, process,
            stdout, b"", commit=COMMIT, tree=TREE, python=PYTHON, cwd="/owned/launch",
            timeout_seconds=budget)

    if mutation is None:
        Check()

    else:
        with pytest.raises(AssertionError):
            Check()
