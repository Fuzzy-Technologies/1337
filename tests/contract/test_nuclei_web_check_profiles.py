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

PACK = Path(fuzzy1337.__file__).parent / "data/nuclei"
MANIFEST = json.loads((PACK / "manifest.v1.json").read_text(encoding="utf-8"))


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
