import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

CONTRACTS = Path(__file__).resolve().parents[2] / "contracts"


def test_published_schema_and_example():
    schema = json.loads(
        (CONTRACTS / "extension-manifest.schema.json").read_text(encoding="utf-8")
    )
    example = json.loads(
        (CONTRACTS / "examples/extension-manifest.example.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate(example)

    for field, value in [("schema_version", 2), ("unexpected", True)]:
        invalid = copy.deepcopy(example)
        invalid[field] = value
        with pytest.raises(ValidationError):
            validator.validate(invalid)
