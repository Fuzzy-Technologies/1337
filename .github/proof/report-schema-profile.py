# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0
"""One-shot passive report/schema profile; no cache or product changes.

Run from the pinned checkout with its locked Python:
    python /tmp/report-schema-profile.py native-unit.xml coverage/report-schema-profile
"""
import hashlib
import importlib.metadata
import json
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

BASE = "84d1101b3de10da09f89881f523a032cd909d696"
FILES = (
    "tests/unit/test_report_commands.py",
    "tests/contract/test_report_export_formats_contract.py",
    "tests/contract/test_reporting_contract.py",
    "tests/contract/test_finding_contract.py",
)
INPUTS = {
    "tests/unit/test_report_commands.py": "d80236d66c1057f5a5d921ce3ca2c430ace4a42b",
    "tests/contract/test_report_export_formats_contract.py": "9c2d2e52a4c47782a447e49619a2a0d4694c8f77",
    "tests/contract/test_reporting_contract.py": "62e0a658e67cb82936d691b63d0aad7cda1dd760",
    "tests/contract/test_finding_contract.py": "3e86d9a24fac2f0cb95eda087ab77ce643d22846",
    "tests/contract/report_export_fixture.py": "9f222af91254ed05a87d33b35076f0f9f07d4eaa",
    "tests/contract/reporting_fixture.py": "966ae1c4d2d144828b1037820ffe32b01c854392",
    "tests/conftest.py": "ae207ececf0395c502be306b03ee1e330b7ff1d9",
    "tests/unit/conftest.py": "49a2bd6edbfa1ce6dc1a90d183be157933faf311",
    "contracts/report.schema.json": "ad5c3cf48f09108a432d213c58f88f372acf0ad8",
    "contracts/finding.schema.json": "31f09b47140310301f15a02bc4d942cdb299b3e3",
    "contracts/report-export-result.schema.json": "1a9cdb8a5fabe1580cef7d74a38bf474bdb648aa",
    "pyproject.toml": "d21bc235d89f22d788df4fff696c5cc58ef9ee17",
    "uv.lock": "1d50049b590126ddb9a9cfc02eacdd066314e5b6"
}
baselinePath, output = Path(sys.argv[1]), Path(sys.argv[2])
for path, expected in INPUTS.items():
    body = Path(path).read_bytes()
    actual = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
    if actual != expected:
        raise SystemExit("Workload drift: " + path)

baseline = {}
for case in ET.parse(baselinePath).iter("testcase"):
    if case.get("classname") == "tests.unit.test_report_commands":
        nodeid = FILES[0] + "::" + case.attrib["name"]
        if nodeid in baseline:
            raise SystemExit("Duplicate baseline case: " + nodeid)
        baseline[nodeid] = ("skipped" if case.find("skipped") is not None else
                            "failed" if any(case.find(tag) is not None
                                            for tag in ("failure", "error")) else "passed")
if not baseline:
    raise SystemExit("Missing unit report_commands baseline cases")
output.mkdir(parents=True, exist_ok=False)


class Probe:
    """Observe the actual collection and all phase outcomes without altering tests."""

    def __init__(self):
        self.collected, self.reports, self.current, self.calls = [], [], None, []

    def pytest_collection_finish(self, session):
        self.collected = [item.nodeid for item in session.items]

    def pytest_runtest_logstart(self, nodeid, location):
        self.current = nodeid

    def pytest_runtest_logfinish(self, nodeid, location):
        self.current = None

    def pytest_runtest_logreport(self, report):
        self.reports.append({"nodeid": report.nodeid, "when": report.when,
                             "outcome": report.outcome, "duration": report.duration})


probe = Probe()
descriptor = Draft202012Validator.__dict__["check_schema"]
original = descriptor.__func__


def Timed(cls, *args, **kwargs):
    """Delegate exact arguments/return/exception; measure inside the original call only."""

    frame = sys._getframe(1)
    caller = frame.f_globals.get("__name__", "") + "." + frame.f_code.co_name
    schema = args[0] if args else kwargs.get("schema")
    schemaId = schema.get("$id") if isinstance(schema, dict) else None
    error = None
    wall, cpu = time.perf_counter(), time.process_time()
    try:
        return original(cls, *args, **kwargs)
    except BaseException as caught:
        error = type(caught).__module__ + "." + type(caught).__qualname__
        raise
    finally:
        elapsedCpu, elapsedWall = time.process_time() - cpu, time.perf_counter() - wall
        probe.calls.append({"nodeid": probe.current, "caller": caller, "schema_id": schemaId,
                            "exception": error, "wall_seconds": elapsedWall,
                            "cpu_seconds": elapsedCpu})


Draft202012Validator.check_schema = classmethod(Timed)
wall, cpu = time.perf_counter(), time.process_time()
try:
    code = int(pytest.main(["-q", "-n", "0", "--no-cov",
                           "--junitxml=" + str(output / "profiled.xml"), *FILES],
                          plugins=[probe]))
finally:
    elapsedCpu, elapsedWall = time.process_time() - cpu, time.perf_counter() - wall
    Draft202012Validator.check_schema = descriptor

phases = {}
for report in probe.reports:
    phases.setdefault(report["nodeid"], []).append(report)
complete = (len(probe.collected) == len(set(probe.collected)) and
            set(probe.collected) == set(phases) and
            all(sorted(phase["when"] for phase in values) == ["call", "setup", "teardown"]
                and all(phase["outcome"] == "passed" for phase in values)
                for values in phases.values()))
actualUnit = {nodeid: next((phase["outcome"] for phase in values
                           if phase["when"] == "call"), "no-call")
              for nodeid, values in phases.items()
              if nodeid.startswith(FILES[0] + "::")}
sameBaseline = actualUnit == baseline
byFile = {}
for path in FILES:
    calls = [call for call in probe.calls
             if call["nodeid"] and call["nodeid"].startswith(path + "::")]
    reports = [report for report in probe.reports if report["nodeid"].startswith(path + "::")]
    byFile[path] = {"cases": sum(report["when"] == "call" for report in reports),
                    "phase_wall_seconds": sum(report["duration"] for report in reports),
                    "check_schema_calls": len(calls),
                    "check_schema_wall_seconds": sum(call["wall_seconds"] for call in calls),
                    "check_schema_cpu_seconds": sum(call["cpu_seconds"] for call in calls)}
measured = all(values["check_schema_calls"] > 0 for values in byFile.values())
result = {"workload_base": BASE, "python": sys.version, "pytest": pytest.__version__,
          "jsonschema": importlib.metadata.version("jsonschema"), "files": FILES,
          "pytest_exit": code, "all_four_modules_observed_check_schema": measured, "by_file": byFile,
          "collected": probe.collected, "reports": probe.reports,
          "baseline_unit_cases": baseline, "same_baseline_unit_ids_and_outcomes": sameBaseline,
          "all_collected_cases_passed_all_three_phases": complete,
          "instrumented_pytest_wall_seconds": elapsedWall,
          "instrumented_pytest_cpu_seconds": elapsedCpu, "check_schema_calls": probe.calls,
          "check_schema_wall_seconds": sum(call["wall_seconds"] for call in probe.calls),
          "check_schema_cpu_seconds": sum(call["cpu_seconds"] for call in probe.calls)}
(output / "profile.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps({key: value for key, value in result.items()
                  if key not in {"collected", "reports", "baseline_unit_cases",
                                 "check_schema_calls"}}, indent=2))
raise SystemExit(code or (0 if complete and sameBaseline and measured else 1))
