# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Versioned report JSON, canonical model binding, and golden artifact compatibility contracts."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from fuzzy1337.model import ModelState
from fuzzy1337.report_formats import RenderHtml, SerializeJson, SerializeJunit, SerializeSarif
from tests.contract.reporting_fixture import Fixture

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests" / "contract" / "fixtures" / "reporting"


def Validator():
    """Resolve the public Finding schema offline while checking the report's own strict fields."""

    schema = json.loads((ROOT / "contracts" / "report.schema.json").read_text("utf-8"))
    finding = json.loads((ROOT / "contracts" / "finding.schema.json").read_text("utf-8"))
    Draft202012Validator.check_schema(schema)
    registry = Registry().with_resource(finding["$id"], Resource.from_contents(finding))

    return Draft202012Validator(schema, registry=registry)


def test_ActualProducerMatchesVersionedReportSchemaWithoutBecomingCanonicalState():
    """A projection remains distinct from the model document it faithfully embeds."""

    report = Fixture()
    document = json.loads(SerializeJson(report))
    Validator().validate(document)

    assert ModelState.FromDict(document["model"]) == report.state, (
        "Embedded model lost strict producer/consumer compatibility"
    )

    with pytest.raises(ValueError):
        ModelState.FromDict(document)


@pytest.mark.parametrize("field,value", [
    ("schema_version", 2), ("schema_version", True), ("scan_completeness", "clean"),
    ("snapshot_sha256", "bad"), ("model_revision", -1), ("findings", {}),
    ("summary", {}), ("evidence_integrity", {"verified": True}),
])
def test_SchemaRejectsUnsupportedVersionsAndInventedStateClaims(field, value):
    """Portable consumers reject unsupported versions and success interpretations."""

    document = json.loads(SerializeJson(Fixture()))
    document[field] = value

    assert not Validator().is_valid(document), "Report schema accepted an unsupported field"


def test_SchemaRejectsUnknownFieldsAndNonCanonicalReferenceUrls():
    """Schema consumers reject unknown authority flags and arbitrary hyperlinks."""

    document = json.loads(SerializeJson(Fixture()))
    document["authorization"] = "granted"

    assert not Validator().is_valid(document), "Projection accepted an invented authorization field"
    document.pop("authorization")
    document["reference_bindings"][0]["references"][0]["url"] = "https://evil.invalid/"

    assert not Validator().is_valid(document), "Reference schema accepted a nonpublisher hyperlink"


@pytest.mark.parametrize("filename,exporter", [
    ("snapshot.json", SerializeJson), ("snapshot.sarif.json", SerializeSarif),
    ("snapshot.junit.xml", SerializeJunit), ("snapshot.html", RenderHtml),
], ids=lambda value: value if isinstance(value, str) else value.__name__)
def test_GoldenArtifactsPinExactVersionOneOutput(filename, exporter):
    """Synthetic snapshots pin deterministic bytes and require explicit format-diff review."""

    assert exporter(Fixture()) == (GOLDEN / filename).read_bytes(), (
        "Report artifact bytes changed; inspect and review the compatibility/golden diff"
    )
