# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Conserve reviewed historical identities without manufacturing scanner acceptance."""

from __future__ import annotations

import ast
import json
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest

from fuzzy1337.functional_metrics import (
    BuildReport,
    OracleCheck,
    RenderHtml,
    RenderMarkdown,
    ScenarioOracle,
    SerializeReport,
)
from tools.markdown_tables import AlignMarkdown

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures/legacy_preservation"
AUTOTEST_READY_ROWS = {1, 2, 3, 4, 6, 7, 8, 9, 11, 12, 13, 14, 16, 17, 19, 21, 22, 26, 27, 28, 29}
ALLOWED_OWNERS = {47, 53, 57, 58, 59, 92, 95, 96, 97, 98, 146, 147, 155, 157, 207, *range(409, 418)}


def Ledger():
    """Read only the bounded repository fixture, never either historical archive."""

    raw = (FIXTURES / "ledger.v1.json").read_bytes()
    assert len(raw) <= 128 * 1024, (
        "The finite source snapshot unexpectedly exceeded its byte budget."
    )

    return json.loads(raw)


def ValidateLedger(value):
    """Check immutable counts, identity joins, source coordinates and truthful runtime gaps."""

    schema = json.loads((FIXTURES / "ledger.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(value)
    input_ids = {record["id"] for record in value["input_sources"]}
    source_ids = {record["id"] for record in value["qa_sources"]}
    assert len(input_ids) == 2 and len(source_ids) == 10, "Source identities must be unique."
    records = [*value["families"], *value["xss_cases"], *value["xss_refinements"],
               *value["qa_requirements"]]
    assert len({record["id"] for record in records}) == len(records), (
        "Preservation identities must not alias another family, case or design requirement."
    )

    for record in value["families"]:
        assert record["source"]["input_id"] in input_ids, "A family lost its original archive."
        assert set(record["owner_issues"]) <= ALLOWED_OWNERS, "A family has no reviewed task owner."

        for relative in record["current_source_paths"]:
            assert relative.startswith("src/fuzzy1337/") and ".." not in relative.split("/"), (
                "A current source reference must stay in the first-party package."
            )
            assert (ROOT / relative).is_file(), "A current source reference became orphaned."

        for reference in record["current_test_refs"]:
            relative, test_name = reference.split("::")
            assert relative.startswith("tests/") and ".." not in relative.split("/"), (
                "A current test reference must stay in the repository test tree."
            )
            tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
            assert any(isinstance(node, ast.FunctionDef) and node.name == test_name
                       for node in tree.body), "A named current test was renamed or removed."

    rows = value["xss_cases"]
    assert [row["source_row"] for row in rows] == list(range(1, 61)), (
        "Every original numbered XSS row must remain present in original order."
    )
    assert [row["id"] for row in rows] == [f"legacy.xss.{number:03d}" for number in range(1, 61)], (
        "Stable case IDs must retain the historical row coordinate."
    )
    assert len({row["historical_label_sha256"] for row in rows}) == 60, (
        "Distinct historical case labels must not collapse to one digest."
    )
    assert {row["source_row"] for row in rows if row["historical_autotest_ready"]} == (
        AUTOTEST_READY_ROWS
    ), "The exact 21 historical readiness annotations changed."
    assert all(row["historical_target_ready"] for row in rows), (
        "The source marks all 60 target designs ready, without proving execution."
    )

    for record in [*value["qa_sources"], *rows, *value["xss_refinements"],
                   *value["qa_requirements"]]:
        if "source_id" in record:
            assert record["source_id"] in source_ids, "A design requirement lost its source page."

        if "owner_issues" in record:
            assert set(record["owner_issues"]) <= ALLOWED_OWNERS, (
                "A design requirement has no reviewed task owner."
            )


def test_ReviewedFamiliesCasesAndOriginalSourcesStayBoundToOwningContracts():
    """Conserve all inventoried families and exact row-level readiness with live test references."""

    value = Ledger()
    ValidateLedger(value)
    owners = {owner for record in value["families"] for owner in record["owner_issues"]}
    assert set(range(410, 418)) <= owners, "Every new detector direction needs a concrete owner."
    assert {207, 146, 155, 157, 97} <= owners, "Existing preservation additions must retain owners."
    assert {source["sha256"] for source in value["input_sources"]} == {
        "e6fb46b7ec0a98532c046ca8cd5f27e51bf1c24ea77d12eeee524be9f6a47171",
        "8deb85adeac6c60b3f601c676bb859b63ed863081adc8fac4f9449c0d9d0ecb1",
    }, "Reviewed archive content identities must not silently drift."
    sources = {source["id"]: source for source in value["qa_sources"]}
    assert sources["qa-xss-design"]["sha256"] == (
        "e608344746f0b73d2eeb286f41a38b64f1fd60c9dc98dc3dcd51c0e8bbacebb0"
    ), "The 60 numbered cases must retain their exact original source page identity."
    assert sources["qa-xss-mindmap"]["sha256"] == (
        "fbc0b0fc85981f11b931a14ded5c86d88b223993c24df09f92e3e912bf943dea"
    ), "Mindmap refinements must remain attributable to the reviewed original image."


def test_ExactHistoricalMatrixCoordinatesRemainDistinctFromFutureProfiles():
    """Verify actual archived row ordering instead of inventing new protected/browser cases."""

    rows = Ledger()["xss_cases"]
    contexts = ["html-text", "html-attribute", "html-tag", "ajax", "redirect", "script"]
    deliveries = ["get", "post", "cookie", "header", "url"]
    expected = [(kind, context, delivery) for kind in ("reflected", "stored")
                for context in contexts for delivery in deliveries]
    assert [(row["kind"], row["context"], row["delivery"]) for row in rows] == expected, (
        "The recovered 60 source rows must keep their original context/delivery sequence."
    )
    assert all(row["protection"] == "none" for row in rows), (
        "Protected-level designs are refinements, not additional executed source cases."
    )


@pytest.mark.parametrize("mutation", [
    "drop-family", "drop-case", "duplicate-id", "orphan-source", "unowned-family",
    "false-runtime-credit", "false-historical-credit", "extra-secret-field",
])
def test_IncompleteAliasedOrFalselyCreditedPreservationCannotValidate(mutation):
    """Reject conservation failures and attempts to promote old annotations to modern results."""

    value = deepcopy(Ledger())

    if mutation == "drop-family":
        value["families"].pop()

    elif mutation == "drop-case":
        value["xss_cases"].pop()

    elif mutation == "duplicate-id":
        value["families"][1]["id"] = value["families"][0]["id"]

    elif mutation == "orphan-source":
        value["qa_requirements"][0]["source_id"] = "unreviewed-source"

    elif mutation == "unowned-family":
        value["families"][0]["owner_issues"] = [999999]

    elif mutation == "false-runtime-credit":
        value["xss_cases"][0]["current_state"] = "passed"

    elif mutation == "false-historical-credit":
        value["xss_cases"][4]["historical_autotest_ready"] = True

    else:
        value["xss_cases"][0]["payload"] = "inert-unreviewed-field"

    with pytest.raises((AssertionError, jsonschema.ValidationError)):
        ValidateLedger(value)


def test_ExistingMetricsOwnerRendersHistoricalRowsAsNotRunWithoutAccuracy(tmp_path):
    """Exercise real shared report projections while supplying no fictional native scan run."""

    value = Ledger()
    source = next(source for source in value["qa_sources"] if source["id"] == "qa-xss-design")
    oracles = tuple(ScenarioOracle(
        identifier=row["id"], target_pack="historical-xss-design",
        target_version=source["sha256"], provenance="archived-design:" + source["path"],
        complete=False, checks=(OracleCheck(row["id"], "native.xss." + row["context"], None),),
    ) for row in value["xss_cases"])
    report = BuildReport(oracles, ())
    encoded = SerializeReport(report)
    payload = json.loads(encoded)
    markdown = RenderMarkdown(report)
    html = RenderHtml(report)
    (tmp_path / "preservation-matrix.json").write_text(encoded, encoding="utf-8")
    (tmp_path / "preservation-matrix.md").write_text(markdown, encoding="utf-8")
    (tmp_path / "preservation-matrix.html").write_text(html, encoding="utf-8")

    assert payload["runs"] == [], "An archival design cannot introduce a scanner execution."
    assert len(payload["matrix"]["columns"]) == 60, "Each source case needs its own absent run."
    assert "not-run" in markdown and "not-run" in html, (
        "Both readable projections must explicitly retain the missing assessment state."
    )
    assert all(column["scanner_id"] is None for column in payload["matrix"]["columns"]), (
        "A historical ready annotation cannot invent a modern native/provider scanner identity."
    )


def test_ReadableFamilyTableComesFromTheCheckedManifest():
    """Prevent human preservation status from drifting into a disconnected coverage claim."""

    rows = ["| Family | Disposition | Owning work |", "| --- | --- | --- |"]

    for family in Ledger()["families"]:
        owners = ", ".join(
            f"[#{owner}](https://github.com/Fuzzy-Technologies/1337/issues/{owner})"
            for owner in family["owner_issues"]
        )
        rows.append(f"| {family['title']} | {family['disposition']} | {owners} |")

    document = (ROOT / "docs/LEGACY_PRESERVATION.md").read_text(encoding="utf-8")
    actual = document.split("<!-- preservation-families:start -->\n", 1)[1].split(
        "\n<!-- preservation-families:end -->", 1
    )[0]
    assert actual == AlignMarkdown("\n".join(rows) + "\n").rstrip("\n"), (
        "Readable family status must derive from the same ledger."
    )
