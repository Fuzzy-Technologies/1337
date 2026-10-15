# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Reviewed first-party web checks retain the existing exact-GET adapter contract."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest
import yaml

import fuzzy1337
from fuzzy1337.adapters import AdapterRequest, ImpactLevel
from fuzzy1337.adapters.nuclei import NucleiAdapter, NucleiProfile, NucleiTemplate
from fuzzy1337.functional_metrics import (
    BuildReport,
    RawEvidence,
    RenderHtml,
    RenderMarkdown,
    RunStatus,
    SerializeReport,
)
from tests.functional.nuclei_web_metrics import Scenario, WebCheckRun
from tests.web_vulnerability_helpers import Oracle

PACK = Path(fuzzy1337.__file__).parent / "data/nuclei"
MANIFEST = json.loads((PACK / "manifest.v1.json").read_text(encoding="utf-8"))


def test_ActualWebCheckMetadataBuildsAllReportViewsWithoutNativeExecution():
    """Catch consumer metadata incompatibility using the exact shared factory and target oracle."""

    metadata = Oracle()
    scenarios = tuple(Scenario(metadata, case) for case in metadata["cases"])
    evidence = (
        RawEvidence("stdout", "application/json", ""),
        RawEvidence("stderr", "text/plain", "contract metadata only; no scanner executed\n"),
        RawEvidence("invocation", "application/json", '{"contract_only":true}'),
    )
    runs = tuple(WebCheckRun(case["id"], "3.4.10", MANIFEST["version"],
        RunStatus.COMPLETED, 0.0, detected_checks=(), evidence=evidence)
        for case in metadata["cases"])
    report = BuildReport(scenarios, runs)
    document = json.loads(SerializeReport(report))
    assert len(document["runs"]) == len(metadata["cases"]), (
        "Every real acceptance case must admit the actual consumer's metadata."
    )
    assert all(item["run"]["scanner_id"] == "fuzzy1337.nuclei.web-checks"
               and item["run"]["release_id"] == "nuclei-3.4.10+checks-1"
               for item in document["runs"]), (
        "Scanner identifiers and the observed provider/pack versions must survive serialization."
    )
    metrics = [item["metrics"] for item in document["runs"]]
    assert sum(item["tp"] for item in metrics) == 0 and (
        sum(item["fn"] for item in metrics)
        == sum(case["expected_match"] for case in metadata["cases"])
    ), "Metadata construction must not convert oracle positives into invented detections."
    assert all(item["run"]["evidence"][1]["content"] == evidence[1].content
               for item in document["runs"]), "Report construction changed supplied raw evidence."
    assert "fuzzy1337.nuclei.web-checks" in RenderMarkdown(report), (
        "The actual scanner identifier must be accepted by the Markdown report consumer."
    )
    assert "fuzzy1337.nuclei.web-checks" in RenderHtml(report), (
        "The actual scanner identifier must be accepted by the HTML report consumer."
    )


@pytest.mark.parametrize("status", [RunStatus.CRASHED, RunStatus.TIMED_OUT])
def test_ActualWebCheckMetadataPreservesIncompleteRunTruth(status):
    """Failed consumer outcomes retain partial evidence without receiving accuracy scores."""

    metadata = Oracle()
    case = metadata["cases"][0]
    evidence = (RawEvidence("stderr", "text/plain", "contract-only partial output\n"),)
    run = WebCheckRun(case["id"], "3.4.10", MANIFEST["version"], status, 0.25,
                      detected_checks=(case["id"],), evidence=evidence)
    report = BuildReport((Scenario(metadata, case),), (run,))
    measured = report["runs"][0]
    assert run.status is status and run.evidence == evidence, (
        "Consumer metadata cannot promote failed work or discard partial output."
    )
    assert measured["metrics"]["accuracy"] is None, (
        "A partial native result must not be scored as a completed detector assessment."
    )
    assert report["matrix"]["rows"][0]["cells"][0]["state"] == status.value, (
        "The matrix must retain actual crash/timeout state despite partial detections."
    )


def test_PackPinsThreeIndependentlyNamedReviewedArtifacts():
    """The shipped pack identifies actual reviewed bytes without implying runtime authority."""

    assert set(MANIFEST) == {"schema_version", "pack_id", "version", "templates"}, (
        "Reviewed pack metadata must retain its finite schema."
    )
    assert MANIFEST["schema_version"] == 1 and MANIFEST["version"] == "1", (
        "The initial reviewed pack must have an explicit immutable version."
    )
    assert {item["family"]: item["template_id"] for item in MANIFEST["templates"]} == {
        "git": "fuzzy1337-git-head-exposure",
        "sql": "fuzzy1337-owned-sql-canary-disclosure",
        "reflection": "fuzzy1337-unsafe-html-reflection",
    }, "Selected response checks must not masquerade as general injection or browser detectors."
    assert len(MANIFEST["templates"]) == 3, "Each reviewed family must occur exactly once."

    for record in MANIFEST["templates"]:
        assert Path(record["filename"]).name == record["filename"], (
            "Pack artifacts must remain immediate local files without traversal."
        )
        raw = (PACK / record["filename"]).read_bytes()
        assert len(raw) == record["size_bytes"], "Reviewed template size drifted."
        assert hashlib.sha256(raw).hexdigest() == record["sha256"], (
            "Template changes require a new exact reviewed artifact identity."
        )
        assert record["reviewed_profile"] == "single-get-exact-url", (
            "Pack review must retain the existing adapter's one-request boundary."
        )


@pytest.mark.parametrize("record", MANIFEST["templates"], ids=lambda item: item["family"])
def test_ReviewedTemplateHasOnlyOneExactGetAndNonExecutableMatchers(record):
    """Finite status/header/body comparisons cannot expand requests or execute template code."""

    template = yaml.safe_load((PACK / record["filename"]).read_text(encoding="utf-8"))
    assert set(template) == {"id", "info", "http"}, (
        "Reviewed templates cannot acquire workflow, code, headless, variable or payload fields."
    )
    assert template["id"] == record["template_id"], "Template identity differs from its review."
    assert len(template["http"]) == 1, "Each selected template must issue exactly one request."
    request = template["http"][0]
    assert set(request) == {"method", "path", "redirects", "matchers-condition", "matchers"}, (
        "The reviewed request shape excludes credentials, arbitrary headers and expansions."
    )
    assert request["method"] == "GET" and request["path"] == ["{{BaseURL}}"], (
        "A check must use the exact operator-selected URL without appending a probe path."
    )
    assert request["redirects"] is False and request["matchers-condition"] == "and", (
        "Redirect containment and joint response conditions are required."
    )
    assert len(request["matchers"]) == 3, "Status, media type and response body must all match."
    assert request["matchers"][0] == {"type": "status", "status": [200]}, (
        "Denied, redirected and failed responses must not become successful detections."
    )
    assert request["matchers"][1]["type"] == "regex", (
        "The selected response media type must be tested explicitly."
    )
    assert request["matchers"][1]["part"] == "header", (
        "Response body text cannot impersonate a Content-Type header."
    )

    for matcher in request["matchers"][1:]:
        expected = {
            "type", "part", "regex" if matcher["type"] == "regex" else "words",
        }
        assert set(matcher) == expected and matcher["type"] in {"word", "regex"}, (
            "Reviewed matchers must remain non-executable word or regex comparisons."
        )


@pytest.mark.parametrize("record", MANIFEST["templates"], ids=lambda item: item["family"])
def test_RealAdapterPreparationBindsReviewAndRetainsGovernedExecution(record, tmp_path):
    """Real adapter preparation preserves STANDARD impact, exact URLs and bounded no-retry flags."""

    configuration = tmp_path / "empty.yaml"
    configuration.write_bytes(b"{}\n")
    selected = NucleiTemplate(
        record["template_id"], str((PACK / record["filename"]).absolute()), record["sha256"],
        record["size_bytes"], record["source_reference"], record["source_revision"],
        record["review_reference"], record["reviewed_profile"],
    )
    profile = NucleiProfile("reviewed-" + record["family"], (selected,), str(configuration))
    url = "http://127.0.0.1:8080/explicitly-selected"
    request = AdapterRequest("web.http-template-check", "target:owned", ImpactLevel.STANDARD,
        {"url": url, "profile_sha256": profile.Digest, "timeout_seconds": 10, "rate_limit": 1})
    adapter = NucleiAdapter(lambda reference: b"", profile, provider_version="3.4.10")
    invocation = adapter.PrepareInvocation(request)
    arguments = invocation.argv
    assert arguments[arguments.index("-u") + 1] == url, "Preparation changed the selected URL."
    assert arguments.count("-t") == 1, "One selected check must not expand into a template pack."
    assert arguments[arguments.index("-t") + 1] == selected.path, (
        "The prepared provider must execute the exact reviewed local artifact."
    )
    assert arguments[arguments.index("-retries") + 1] == "0", "Automatic retry was enabled."
    assert {"-dr", "-ni", "-duc", "-omit-raw", "-omit-template"}.issubset(arguments), (
        "Reviewed checks must preserve existing redirect, callback, update and output controls."
    )
    assert invocation.request.impact is ImpactLevel.STANDARD, (
        "A source-controlled template cannot lower required impact or provide scan approval."
    )


def test_PackDescriptionsKeepResponseEvidenceAndExploitClaimsSeparate():
    """Narrow evidence labels avoid presenting selected lab responses as broad exploit proof."""

    templates = {
        item["family"]: yaml.safe_load((PACK / item["filename"]).read_text(encoding="utf-8"))
        for item in MANIFEST["templates"]
    }
    assert "not successful source recovery" in templates["git"]["info"]["description"], (
        "Git metadata exposure must not claim source recovery."
    )
    assert "not a general SQL injection detector" in templates["sql"]["info"]["description"], (
        "One canary response cannot claim general differential SQL injection detection."
    )
    assert "proven XSS" in templates["reflection"]["info"]["description"], (
        "Inert raw reflection must retain its explicit browser-execution limitation."
    )


@pytest.mark.parametrize("body,expected", [
    ("ref: refs/heads/owned-fixture\n", True),
    ("ref: refs/heads/team/release_1\r\n", True),
    ("ref: refs/heads/main..backup\n", False),
    ("ref: refs/heads/main//sub\n", False),
    ("ref: refs/heads/main/\n", False),
    ("ref: refs/heads/main.\n", False),
    ("ref: refs/heads/main.lock\n", False),
    ("ref: refs/heads/.hidden\n", False),
    ("<html>ref: refs/heads/owned-fixture</html>", False),
    ("0" * 40 + "\n", False),
])
def test_GitMatcherHasAnExplicitFiniteSymbolicReferenceSubset(body, expected):
    """A local regex smoke guards malformed/unsupported refs; genuine Nuclei remains separate."""

    template = yaml.safe_load((PACK / "git-head-exposure.yaml").read_text(encoding="utf-8"))
    pattern = template["http"][0]["matchers"][2]["regex"][0]
    assert bool(re.search(pattern, body)) is expected, (
        "The symbolic HEAD grammar admitted a malformed or unsupported reference."
    )
