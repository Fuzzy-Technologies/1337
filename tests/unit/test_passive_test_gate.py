# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise exact passive partitions, refused omissions and scoped production coverage."""

from __future__ import annotations

import json
import os
import subprocess
from collections import Counter
from pathlib import Path
from xml.etree import ElementTree

import pytest

from tools import passive_test_gate as gate

IDENTITY = ("tests.unit.test_owned", "test_Owned")


def Junit(path, identities=(IDENTITY,), *, kind=None, message=None):
    """Write an independently controlled complete or deliberately refused JUnit document."""

    root = ElementTree.Element("testsuite")

    for owner, name in identities:
        case = ElementTree.SubElement(root, "testcase", classname=owner, name=name)

        if kind:
            ElementTree.SubElement(case, kind, message=message or "owned refusal")

    path.parent.mkdir(parents=True, exist_ok=True)
    ElementTree.ElementTree(root).write(path)


@pytest.mark.parametrize("serial", [False, True])
def test_CollectUsesExactPytestIdentityIncludingParameterDelimiters(monkeypatch, serial):
    """The pinned pytest identity conversion preserves colons inside parameter values."""

    calls = []

    def Run(arguments, **options):
        """Return only collected identities and the usual summary line."""

        calls.append((arguments, options))
        return subprocess.CompletedProcess(arguments, 0,
            "tests/unit/test_owned.py::test_Owned[a::b]\n\n1 test collected\n", "")

    monkeypatch.setattr(gate.subprocess, "run", Run)
    expected = gate.Collect(("tests/unit",), serial=serial)
    assert expected == Counter({("tests.unit.test_owned", "test_Owned[a::b]"): 1}), (
        'Collection must preserve exact parameter identities, the selected partition '
        'and bounded no-execution arguments'
    )
    arguments, options = calls[0]
    assert arguments[-1] == ("serial" if serial else "not serial"), (
        'Collection must preserve exact parameter identities, the selected partition '
        'and bounded no-execution arguments'
    )
    assert "--no-cov" in arguments and "--collect-only" in arguments, (
        'Collection must preserve exact parameter identities, the selected partition '
        'and bounded no-execution arguments'
    )
    assert options["timeout"] == 300 and options["capture_output"], (
        'Collection must preserve exact parameter identities, the selected partition '
        'and bounded no-execution arguments'
    )


@pytest.mark.parametrize("status,output,accepted", [
    (5, "", True), (0, "", False), (2, "", False),
    (5, "tests/unit/test_owned.py::test_Owned\n", False),
    (0, "tests/unit/test_owned.py::test_Owned\n" * 2, False),
])
def test_CollectRefusesErrorsDuplicatesAndAmbiguousEmptySelection(
    monkeypatch, status, output, accepted,
):
    """Only an explicit empty status or a nonduplicated successful collection can proceed."""

    monkeypatch.setattr(gate.subprocess, "run", lambda arguments, **options:
                        subprocess.CompletedProcess(arguments, status, output, ""))

    if accepted:
        assert not gate.Collect(("tests/unit",), serial=True), (
            'Only a genuinely empty declared partition may produce an empty collection'
        )

    else:
        with pytest.raises((ValueError, RuntimeError)):
            gate.Collect(("tests/unit",), serial=False)


@pytest.mark.parametrize("kind", [None, "failure", "error", "skipped", "missing", "duplicate"])
def test_JunitRequiresEveryCaseOnceAndRejectsUnverifiedOutcomes(tmp_path, kind):
    """A process exit cannot hide omitted, duplicated, failed or unexpectedly skipped cases."""

    report = tmp_path / "cases.xml"
    identities = () if kind == "missing" else (IDENTITY,) * (2 if kind == "duplicate" else 1)
    Junit(report, identities, kind=kind if kind in {"failure", "error", "skipped"} else None)

    if kind is None:
        assert gate.CheckJunit(report, Counter({IDENTITY: 1})) == {
            "collected": 1, "passed": 1, "known_documentation_skips": 0, "units": 1,
        }, (
            'Accepted JUnit must contain every exact collected case once with truthful '
            'successful counts'
        )

    else:
        with pytest.raises(ValueError):
            gate.CheckJunit(report, Counter({IDENTITY: 1}))


def test_OnlyExactSeparatelyOwnedDocumentationSkipsAreDeclared(tmp_path):
    """The general unit job may defer only the enumerated fixtures to the locked docs job."""

    identity = ("tests.unit.test_api_reference", next(iter(gate.DOCUMENTATION_SKIPS)))
    report = tmp_path / "docs.xml"
    Junit(report, (identity,), kind="skipped",
          message="Strict rendering requires the separate docs tooling lock")
    assert gate.CheckJunit(report, Counter({identity: 1}))["known_documentation_skips"] == 1, (
        'Only the exact separately owned documentation fixture may count as a '
        'declared skip'
    )
    Junit(report, (identity,), kind="skipped", message="Different refusal")

    with pytest.raises(ValueError, match="unexpected skip"):
        gate.CheckJunit(report, Counter({identity: 1}))


@pytest.mark.parametrize("variant", ["valid", "no-changes", "bad-base", "wrong-ancestor",
                                     "framing", "removed", "alias", "non-python"])
def test_ChangedInventoryRequiresExactAncestorAndRealSurvivingModules(
    tmp_path, monkeypatch, variant,
):
    """Only actual changed first-party Python modules may enter the scoped coverage claim."""

    monkeypatch.chdir(tmp_path)
    source = Path("src/fuzzy1337/owned.py")
    source.parent.mkdir(parents=True)
    source.write_text('"""Owned source."""\nVALUE = 1\n')

    if variant == "alias":
        alias = source.with_name("actual.py")
        source.rename(alias)
        source.symlink_to(alias.name)

    status = b"D" if variant == "removed" else b"M"
    raw = (b":100644 100644 " + b"c" * 40 + b" " + b"d" * 40 + b" " + status
           + b"\0" + source.as_posix().encode() + b"\0")

    if variant == "no-changes":
        raw = b""

    elif variant == "framing":
        raw = b"M\0unterminated"

    elif variant == "non-python":
        raw = b":100644 100644 " + b"c" * 40 + b" " + b"d" * 40 + (
            b" M\0src/fuzzy1337/resource.json\0")

    def Run(arguments, **options):
        """Return separate actual-ancestor and NUL-inventory producer responses."""

        value = ("b" * 40 if variant == "wrong-ancestor" else "a" * 40) + "\n"
        output = (value if "merge-base" in arguments else
                  "b" * 40 + "\n" if "rev-parse" in arguments else
                  b"" if "--quiet" in arguments else raw)

        return subprocess.CompletedProcess(arguments, 0, output, "")

    monkeypatch.setattr(gate.subprocess, "run", Run)

    if variant in {"valid", "no-changes", "non-python"}:
        assert gate.ChangedModules("a" * 40) == ((source,) if variant == "valid" else ()), (
            'Changed coverage inventory must match the actual ancestor and surviving '
            'production modules'
        )

    else:
        with pytest.raises(ValueError):
            gate.ChangedModules("bad" if variant == "bad-base" else "a" * 40)


@pytest.mark.parametrize("variant", ["valid", "exact-eighty", "missing", "no-branch", "excluded",
                                     "no-production-changes"])
def test_ScopedCoverageReusesUnchangedStrictModuleAlgorithm(tmp_path, monkeypatch, variant):
    """Unchanged low modules cannot hide a changed-module failure or inflate its scoped claim."""

    monkeypatch.chdir(tmp_path)
    source = Path("src/fuzzy1337/owned.py")
    source.parent.mkdir(parents=True)
    source.write_text('"""Owned source."""\nVALUE = 1\n')
    summary = {"covered_lines": 9, "num_statements": 10, "covered_branches": 1,
               "num_branches": 2, "excluded_lines": 0}

    if variant == "exact-eighty":
        summary.update(covered_lines=8, covered_branches=0, num_branches=0)

    elif variant == "excluded":
        summary["excluded_lines"] = 1

    report = {"meta": {"branch_coverage": variant != "no-branch"},
              "files": {source.as_posix(): {"summary": summary},
                        "src/fuzzy1337/unchanged.py": {"summary": {}}}}

    if variant == "missing":
        del report["files"][source.as_posix()]

    if variant in {"valid", "no-production-changes"}:
        modules = () if variant == "no-production-changes" else (source,)
        assert gate.ChangedCoverage(report, modules) == (
            {} if not modules else {source.as_posix(): summary}
        ), (
            'Scoped coverage must retain original module measurements under the unchanged '
            'strict algorithm'
        )

    else:
        with pytest.raises(ValueError):
            gate.ChangedCoverage(report, (source,))


@pytest.mark.parametrize("variant", [
    "valid", "empty-serial", "missing", "overlap", "empty", "failure",
])
def test_ExecutionUsesDisjointRealSelectionsFreshMeasurementAndSerialAppend(
    tmp_path, monkeypatch, variant,
):
    """Exercise orchestration without recursively executing the entire unit suite in a unit test."""

    monkeypatch.chdir(tmp_path)
    target = Path("tests/unit")
    target.mkdir(parents=True)
    parallel = Counter({IDENTITY: 1})
    serial = Counter({("tests.unit.test_serial", "test_Serial"): 1})

    if variant == "overlap":
        serial = parallel

    elif variant in {"empty-serial", "empty"}:
        serial = Counter()

    if variant == "empty":
        parallel = Counter()

    monkeypatch.setattr(gate, "Collect", lambda selection, serial: serials[serial])
    serials = {False: parallel, True: serial}
    calls = []

    def Run(arguments, path, timeout):
        """Persist the exact selected controlled report after observing the actual argv."""

        calls.append(arguments)
        isSerial = "--cov-append" in arguments
        Junit(path, tuple(serials[isSerial]))
        assert "--cov-fail-under=0" in arguments and timeout == 900, (
            'The real selection must run disjoint bounded partitions with fresh parallel '
            'and appended serial coverage'
        )

        return (1 if variant == "failure" else 0), None

    monkeypatch.setattr(gate, "RunPytest", Run)
    selection = ("tests/absent",) if variant == "missing" else (str(target),)

    if variant in {"valid", "empty-serial"}:
        result = gate.RunSelection(selection, gate.TestOptions(suite_timeout_seconds=900))
        expected = {"parallel"} if variant == "empty-serial" else {"parallel", "serial"}
        assert set(result) == expected, (
            'The real selection must run disjoint bounded partitions with fresh parallel '
            'and appended serial coverage'
        )
        assert "--cov-append" not in calls[0], (
            'The real selection must run disjoint bounded partitions with fresh parallel '
            'and appended serial coverage'
        )

        if serial:
            assert "--cov-append" in calls[1] and calls[1][calls[1].index("-n") + 1] == "0", (
                'The real selection must run disjoint bounded partitions with fresh parallel '
                'and appended serial coverage'
            )

    else:
        with pytest.raises((ValueError, RuntimeError)):
            gate.RunSelection(selection, gate.TestOptions(suite_timeout_seconds=900))


@pytest.mark.parametrize("failure", [False, True])
def test_MainRecordsScopedTruthWithoutClaimingTheGlobalMasterGate(tmp_path, monkeypatch, failure):
    """The CLI preserves raw evidence and cannot turn an execution error into scoped success."""

    monkeypatch.chdir(tmp_path)
    Path("coverage").mkdir()
    Path("coverage/coverage.json").write_text(json.dumps({"meta": {"branch_coverage": True}}))
    monkeypatch.setattr(gate, "ChangedFiles", lambda base: ("b" * 40, ()))
    monkeypatch.setattr(gate, "ChangedModules", lambda base, **settings: ())
    monkeypatch.setattr(gate, "TestOnlySelection", lambda *values: ((), "full-fixture"))
    monkeypatch.setattr(gate, "ChangedCoverage", lambda report, modules: {})

    def Run(selection, options, **settings):
        """Keep the production CLI's complete fixed selection visible without executing it."""

        assert selection in (("tests/unit",), gate.BOUNDARIES), (
            'The passive CLI must retain complete reviewed selections and measured scoped '
            'truth without a global gate claim'
        )

        if selection == gate.BOUNDARIES:
            assert settings["append"] is True and settings["label"] == "boundaries", (
                'The passive CLI must retain complete reviewed selections and measured scoped '
                'truth without a global gate claim'
            )
            assert "patch = subprocess" in settings["configuration"].read_text(), (
                'The passive CLI must retain complete reviewed selections and measured scoped '
                'truth without a global gate claim'
            )
        assert options.fail_fast and options.suite_timeout_seconds == 900, (
            'The passive CLI must retain complete reviewed selections and measured scoped '
            'truth without a global gate claim'
        )

        if failure:
            raise RuntimeError("Owned execution refusal")

        return {"parallel": {"collected": 1, "passed": 1, "units": 1}}

    monkeypatch.setattr(gate, "RunSelection", Run)
    Path("coverage/passive-acceptance.json").write_text("stale success")
    assert gate.Main(["--base", "a" * 40]) == int(failure), (
        'The passive CLI must retain complete reviewed selections and measured scoped '
        'truth without a global gate claim'
    )
    receipt = Path("coverage/passive-acceptance.json")
    assert receipt.exists() is not failure, (
        'The passive CLI must retain complete reviewed selections and measured scoped '
        'truth without a global gate claim'
    )

    if not failure:
        assert json.loads(receipt.read_bytes())["global_module_gate"] == "not-claimed", (
            'The passive CLI must retain complete reviewed selections and measured scoped '
            'truth without a global gate claim'
        )


def GitCandidate(tmpPath, monkeypatch, *, consumer=""):
    """Create inert Git commits and original event metadata without executing test bodies."""

    monkeypatch.chdir(tmpPath)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    environment = dict(os.environ)

    def Git(*arguments):
        """Use only an owned temporary repository with inert author metadata and no remote."""

        return subprocess.run(["git", "-c", "user.name=Owned fixture",
            "-c", "user.email=fixture@example.invalid", *arguments], check=True,
            capture_output=True, text=True, timeout=30, env=environment).stdout.strip()

    Git("init", "--quiet", "--object-format=sha1")
    Path(".git/info/exclude").write_text("event.json\n", encoding="utf-8")
    path = Path("tests/unit/test_owned.py")
    path.parent.mkdir(parents=True)
    original = ('"""Owned inert test."""\n\ndef test_Owned():\n'
                '    """Check one saved value."""\n\n    cache_value = 1\n'
                '    assert cache_value == 1, "Owned value differs"\n')
    path.write_text(original, encoding="utf-8")
    Path("tests/unit/test_other.py").write_text(
        '"""Other inert test."""\n\ndef Other():\n    """Return a saved value."""\n\n'
        '    other_value = 1\n    return other_value\n\ndef test_Other():\n'
        '    """Check another saved value."""\n\n'
        '    assert Other() == 1, "Other saved value differs"\n', encoding="utf-8")
    baseline = Path("contracts/python-naming-baseline.json")
    baseline.parent.mkdir()
    row = [path.as_posix(), "local", "top.test_Owned", "cache_value"]
    external = ["tests/unit/test_other.py", "local", "top.Other", "other_value"]
    baseline.write_text("[\n  " + json.dumps(row) + ",\n  " + json.dumps(external)
                        + "\n]\n", encoding="utf-8")

    if consumer:
        Path("tests/unit/test_consumer.py").write_text(consumer, encoding="utf-8")

    Git("add", "--all")
    Git("commit", "--quiet", "-m", "Owned fixture base")
    base = Git("rev-parse", "HEAD")
    path.write_text(original.replace("cache_value", "cacheValue"), encoding="utf-8")
    baseline.write_text("[\n  " + json.dumps(external) + "\n]\n", encoding="utf-8")
    Git("add", "--all")
    Git("commit", "--quiet", "-m", "Owned fixture candidate")
    head = Git("rev-parse", "HEAD")
    event = {"pull_request": {"draft": False, "base": {"ref": "develop", "sha": base},
             "head": {"ref": "feature/passive-batch-owned", "sha": head}}}
    eventPath = tmpPath / "event.json"
    eventPath.write_text(json.dumps(event), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_BASE_REF", "develop")
    monkeypatch.setenv("GITHUB_HEAD_REF", "feature/passive-batch-owned")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(eventPath))

    return base, head, Git, eventPath


@pytest.mark.parametrize("consumer", [
    "",
    'from tests.unit.test_owned import test_Owned\n',
    'from .test_owned import test_Owned\n',
    'pytest_plugins = ["tests.unit.test_owned"]\n',
    'import importlib\nVALUE = importlib.import_module("tests.unit.test_owned")\n',
    'from pathlib import Path\nVALUE = Path("tests/unit/test_owned.py").read_text()\n',
    'VALUE = Load("tests/unit/test_owned.py")\n',
    'VALUE = "tests/unit/test_owned.py"\n',
])
def test_ActualGitLeafSelectionPreservesCompleteFilesAndRefusesVisibleConsumers(
    tmp_path, monkeypatch, consumer,
):
    """Exercise real complete raw Git inventory, bounded blob reads and consumer inspection."""

    base, head, _, _ = GitCandidate(tmp_path, monkeypatch, consumer=consumer)
    actualHead, changes = gate.ChangedFiles(base)
    selection, reason = gate.TestOnlySelection(base, actualHead, changes)
    accepted = consumer in {"", 'VALUE = "tests/unit/test_owned.py"\n'}
    assert actualHead == head and len(changes) == 2, (
        "The plan must use the exact checked-out head and complete test/baseline diff"
    )
    assert bool(selection) is accepted, "Visible shared or dynamic test-module use must stay full"

    if accepted:
        assert selection == ("tests/unit/test_owned.py", *gate.TEST_ONLY_CHECKS), (
            "Quick selection must run the whole affected file and every fixed ownership regression"
        )
        assert reason == "verified-leaf-unit-changes", "The receipt must name actual eligibility"


@pytest.mark.parametrize("variant", [
    "master", "push", "draft", "ordinary-head", "wrong-head", "wrong-base", "missing-event",
    "new-test", "deleted-test", "renamed-test", "mode", "helper", "conftest", "production",
    "tooling", "unknown",
    "extra-baseline-byte", "baseline-addition", "external-baseline-removal", "dirty-source",
])
def test_ActualGitAmbiguousOrNonTestChangesRetainTheExistingPassiveGate(
    tmp_path, monkeypatch, variant,
):
    """Every unsupported change stays in all passive units/boundaries, without active rerouting."""

    base, head, Git, eventPath = GitCandidate(tmp_path, monkeypatch)
    event = json.loads(eventPath.read_text(encoding="utf-8"))

    if variant in {"master", "push", "draft", "ordinary-head", "wrong-head", "wrong-base"}:
        if variant == "master":
            event["pull_request"]["base"]["ref"] = "master"
            monkeypatch.setenv("GITHUB_BASE_REF", "master")

        elif variant == "push":
            monkeypatch.setenv("GITHUB_EVENT_NAME", "push")

        elif variant == "draft":
            event["pull_request"]["draft"] = True

        elif variant == "ordinary-head":
            event["pull_request"]["head"]["ref"] = "feature/ordinary"
            monkeypatch.setenv("GITHUB_HEAD_REF", "feature/ordinary")

        elif variant == "wrong-head":
            event["pull_request"]["head"]["sha"] = base

        else:
            event["pull_request"]["base"]["sha"] = head

        eventPath.write_text(json.dumps(event), encoding="utf-8")

    elif variant == "missing-event":
        eventPath.unlink()

    else:
        path = Path("tests/unit/test_owned.py")

        if variant == "new-test":
            Path("tests/unit/test_new.py").write_bytes(path.read_bytes())

        elif variant == "deleted-test":
            path.unlink()

        elif variant == "renamed-test":
            path.rename(path.with_name("test_renamed.py"))

        elif variant == "mode":
            path.chmod(0o755)

        elif variant in {"helper", "conftest", "production", "tooling", "unknown"}:
            other = Path({"helper": "tests/helper.py", "conftest": "tests/unit/conftest.py",
                          "production": "src/fuzzy1337/owned.py",
                          "tooling": "tools/passive_test_gate.py", "unknown": "notes.txt"}[variant])
            other.parent.mkdir(parents=True, exist_ok=True)
            other.write_text('"""Owned inert source."""\nVALUE = 1\n', encoding="utf-8")

        elif variant == "extra-baseline-byte":
            with gate.BASELINE.open("a", encoding="utf-8") as stream:
                stream.write("\n")

        elif variant == "baseline-addition":
            rows = json.loads(gate.BASELINE.read_text(encoding="utf-8"))
            rows.append(["tests/unit/test_new.py", "local", "top.New", "new_value"])
            gate.BASELINE.write_text(json.dumps(rows), encoding="utf-8")

        elif variant == "external-baseline-removal":
            gate.BASELINE.write_text("[\n]\n", encoding="utf-8")

        elif variant == "dirty-source":
            path.write_text('"""Uncommitted inert source."""\n', encoding="utf-8")

        if variant != "dirty-source":
            Git("add", "--all")

            if variant == "mode":
                Git("update-index", "--chmod=+x", path.as_posix())

            Git("commit", "--quiet", "-m", "Owned unsupported change")
            head = Git("rev-parse", "HEAD")
            event["pull_request"]["head"]["sha"] = head
            eventPath.write_text(json.dumps(event), encoding="utf-8")

    if variant == "dirty-source":
        with pytest.raises(subprocess.CalledProcessError):
            gate.ChangedFiles(base)

    else:
        actualHead, changes = gate.ChangedFiles(base)
        selection, reason = gate.TestOnlySelection(base, actualHead, changes)
        assert not selection and reason != "verified-leaf-unit-changes", (
            "Unsupported changes must retain the existing all-unit passive acceptance"
        )


@pytest.mark.parametrize("failure", [False, True])
def test_QuickMainRunsWholeFilesAndOwnershipChecksWithoutClaimingProductCoverage(
    tmp_path, monkeypatch, failure,
):
    """Record measured quick scope only, and retire stale success before any failed execution."""

    monkeypatch.chdir(tmp_path)
    Path("coverage").mkdir()
    Path("coverage/passive-acceptance.json").write_text("stale success", encoding="utf-8")
    Path("coverage/coverage.json").write_text(
        json.dumps({"meta": {"branch_coverage": True}}), encoding="utf-8")
    selection = ("tests/unit/test_owned.py", *gate.TEST_ONLY_CHECKS)
    monkeypatch.setattr(gate, "ChangedFiles", lambda base: ("b" * 40, ()))
    monkeypatch.setattr(gate, "ChangedModules", lambda base, **settings: ())
    monkeypatch.setattr(gate, "TestOnlySelection", lambda *values:
                        (selection, "verified-leaf-unit-changes"))
    calls = []

    def Run(actual, options, **settings):
        """Observe exactly one complete-file selection without recursively running pytest."""

        calls.append((actual, settings))

        if failure:
            raise RuntimeError("Owned quick failure")

        return {"parallel": {"collected": 7, "passed": 7, "units": 7}}

    monkeypatch.setattr(gate, "RunSelection", Run)
    assert gate.Main(["--base", "a" * 40]) == int(failure), (
        "Quick execution failure must propagate instead of retaining stale acceptance"
    )
    receipt = Path("coverage/passive-acceptance.json")
    assert calls == [(selection, {"requireFiles": True})] and receipt.exists() is not failure, (
        "Quick execution must run exactly the derived complete files and no old boundary bundle"
    )

    if not failure:
        result = json.loads(receipt.read_bytes())
        assert result["scope"] == "test-only" and result["modules"] == {}, (
            "Test-only acceptance cannot manufacture measured changed production modules"
        )
        assert result["global_module_gate"] == "not-claimed" and result["selection"] == (
            list(selection)
        ), "The receipt must distinguish exact selected-file proof from the unchanged global gate"


@pytest.mark.parametrize("variant", ["failed", "framing", "identity", "syntax"])
def test_ConsumerInspectionErrorsNeverBecomeAnEmptyReferenceProof(monkeypatch, variant):
    """Refuse nonzero Git search, incomplete names and unparseable potential consumers."""

    head = "b" * 40
    output = (head + ":tests/unit/test_consumer.py\0").encode()
    code = 0

    if variant == "failed":
        code, output = 2, b""

    elif variant == "framing":
        output = output[:-1]

    elif variant == "identity":
        output = output.replace(head.encode(), b"c" * 40)

    monkeypatch.setattr(gate.subprocess, "run", lambda arguments, **options:
                        subprocess.CompletedProcess(arguments, code, output, b""))
    monkeypatch.setattr(gate, "ReadBlob", lambda reference: b"def Broken(:\n")

    with pytest.raises((ValueError, SyntaxError)):
        gate.LeafTests(("tests/unit/test_owned.py",), head)


def test_QuickCollectionCannotSubstituteMandatoryCasesForAnEmptyAffectedFile(
    tmp_path, monkeypatch,
):
    """Require actual collected ownership from every selected file before any execution."""

    monkeypatch.chdir(tmp_path)
    path = Path("tests/unit/test_empty.py")
    path.parent.mkdir(parents=True)
    path.write_text('"""Inert empty fixture."""\n', encoding="utf-8")
    monkeypatch.setattr(gate, "Collect", lambda selection, serial:
                        Counter() if serial else Counter({IDENTITY: 1}))

    def Denied(*arguments, **options):
        """Refuse execution when collection has not established every requested file."""

        raise AssertionError("Missing affected-file collection must refuse before execution")

    monkeypatch.setattr(gate, "RunPytest", Denied)

    with pytest.raises(ValueError, match="no collected cases"):
        gate.RunSelection((path.as_posix(),), gate.TestOptions(suite_timeout_seconds=900),
                          requireFiles=True)


@pytest.mark.parametrize("count", [1, 2])
def test_LeafBodyChangesNeedNoBaselineEditOrNewPerFeatureRule(tmp_path, monkeypatch, count):
    """Keep ordinary saved-test maintenance reusable across one or several existing leaf modules."""

    _, base, Git, eventPath = GitCandidate(tmp_path, monkeypatch)
    paths = ["tests/unit/test_owned.py", "tests/unit/test_other.py"][:count]

    for name in paths:
        path = Path(name)
        path.write_text(path.read_text(encoding="utf-8").replace("= 1", "= 2"),
                        encoding="utf-8")

    Git("add", "--all")
    Git("commit", "--quiet", "-m", "Owned saved test body maintenance")
    head = Git("rev-parse", "HEAD")
    event = json.loads(eventPath.read_text(encoding="utf-8"))
    event["pull_request"]["base"]["sha"] = base
    event["pull_request"]["head"]["sha"] = head
    eventPath.write_text(json.dumps(event), encoding="utf-8")
    actualHead, changes = gate.ChangedFiles(base)
    selection, reason = gate.TestOnlySelection(base, actualHead, changes)
    assert set(selection) == set((*paths, *gate.TEST_ONLY_CHECKS)), (
        "Existing leaf-file maintenance must not require a naming edit or a feature allowlist"
    )
    assert reason == "verified-leaf-unit-changes" and len(changes) == count, (
        "Several eligible leaf test changes must retain the same complete-file acceptance"
    )
