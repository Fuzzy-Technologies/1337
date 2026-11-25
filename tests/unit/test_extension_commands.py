# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Compare offline validation with the real v1 schema and prohibit locator interpretation."""

from __future__ import annotations

import builtins
import copy
import hashlib
import json
from io import StringIO
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from fuzzy1337 import extension_commands as commands
from fuzzy1337.cli import Main
from fuzzy1337.shell import InteractiveShell

ROOT = Path(__file__).resolve().parents[2]


def Example():
    """Read the canonical example without creating another maintained manifest fixture."""

    return json.loads((ROOT / "contracts/examples/extension-manifest.example.json").read_bytes())


def Schema():
    """Use the original Stable v1 schema as the independent validation oracle."""

    return json.loads((ROOT / "contracts/extension-manifest.schema.json").read_bytes())


def Run(root, payload, *, human=False):
    """Use actual local file dispatch and capture only the declared terminal result."""

    source = root / "private-manifest.json"
    source.write_bytes(payload if isinstance(payload, bytes) else json.dumps(payload).encode())
    before = source.read_bytes()
    output = StringIO()
    status = commands.RunExtensionCommands(["validate", str(source)], output, jsonOutput=not human)
    assert source.read_bytes() == before, "Validation mutated the input on success or refusal."

    return status, output.getvalue() if human else json.loads(output.getvalue())


@pytest.mark.parametrize("version", [
    "0.0.0", "1.2.3", "1.2.3-alpha.1", "1.2.3-01", "1.2.3-alpha..1", "1.2.3--",
    "1.2.3+001", "1.2.3+foo..bar", "1.2.3\n", "01.2.3", "v1.2.3", "1.2.3-", "broken",
])
def test_CommandPreservesActualV1VersionAcceptanceWithoutAddingSemverPolicy(tmp_path, version):
    """The packaged structural contract decides acceptance, including its legacy loose grammar."""

    instance = Example()
    instance["extension"]["version"] = version
    expected = Draft202012Validator(Schema()).is_valid(instance)
    status, result = Run(tmp_path, instance)
    assert (status == 0) is expected and result["status"] == ("valid" if expected else "invalid"), (
        "The consumer reinterpreted Stable v1 version acceptance instead of using its real schema."
    )
    assert result["core_compatibility"] == "not-evaluated" and result[
        "extension_activation"
    ] == "not-attempted", "Structural metadata validation became compatibility or activation."


@pytest.mark.parametrize("field,value", [
    ("schema_version", 2), ("schema_version", True), ("schema_version", 1.0),
    ("extension", None), ("entry_points", []), ("unexpected", "private-invalid-value"),
    ("capabilities", ["same", "same"]), ("capabilities", ["BAD"]),
])
def test_RealSchemaRulesAndFixedDiagnosticsRemainAuthoritative(tmp_path, field, value):
    """Type, integer-number semantics, closed objects and uniqueness use the original validator."""

    instance = Example()
    instance[field] = value
    expected = Draft202012Validator(Schema()).is_valid(instance)
    status, result = Run(tmp_path, instance)
    assert (status == 0) is expected, "Schema acceptance changed at an independently checked field."
    assert all(set(item) == {"code", "path"} for item in result["diagnostics"]), (
        "Diagnostics exposed source values or implementation-specific exception text."
    )
    assert "private-invalid-value" not in json.dumps(result), "A rejected source value leaked."


def test_UserSchemaAndImplementationLocatorsRemainInertAndRangeIsNotEvaluated(
    tmp_path, monkeypatch,
):
    """Schema-looking instance data cannot retrieve another schema or import extension code."""

    instance = Example()
    instance["$schema"] = "https://example.invalid/do-not-fetch.json"
    instance["compatibility"]["core"] = "not-a-core-range"
    instance["entry_points"]["tool_adapters"][0]["target"] = "untrusted_extension:Activate"
    original = builtins.__import__

    def Import(name, *args, **kwargs):
        """Refuse any attempt to resolve the source-declared extension implementation."""

        assert not name.startswith("untrusted_extension"), "Validation imported source code."

        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", Import)
    before = copy.deepcopy(instance)
    status, result = Run(tmp_path, instance)
    assert status == 0 and result["status"] == "valid" and instance == before, (
        "Structural validation interpreted a schema/implementation locator or Core range."
    )
    assert result["schema_sha256"] == hashlib.sha256(
        (ROOT / "contracts/extension-manifest.schema.json").read_bytes()
    ).hexdigest(), "The caller-selected schema URI replaced the installed canonical contract."
    instance["$ref"] = "file:///must-not-read"
    status, result = Run(tmp_path, instance)
    assert status == 1 and result["diagnostics"] == [
        {"code": "additionalProperties", "path": ""}
    ], (
        "A schema-like source member was resolved instead of validated as instance data."
    )


@pytest.mark.parametrize("payload,failure", [
    (b"", "input-limit"), (b"x" * (commands.MAX_MANIFEST_BYTES + 1), "input-limit"),
    (b"{", "input-json"), (b"\xff", "input-json"), (b'{"x":1,"x":2}', "input-json"),
    (b'{"x":NaN}', "input-json"), (b'{"x":Infinity}', "input-json"),
    (b'{"x":1e999}', "input-limit"), (b"[" * 2000 + b"]" * 2000, "input-limit"),
    (b"[" * 34 + b"0" + b"]" * 34, "input-limit"),
    (b"[" + b"0," * 4096 + b"0]", "input-limit"),
])
def test_InputResourceAndEncodingRefusalsDoNotClaimSchemaInvalidity(tmp_path, payload, failure):
    """Operational parser bounds are explicit refusals, not changes to the Stable schema."""

    status, result = Run(tmp_path, payload)
    assert status == 2 and result["status"] == "failed" and result["failure"] == failure, (
        "An incomplete, ambiguous or excessive input became a schema acceptance result."
    )
    assert result["diagnostics"] == [] and result["manifest_sha256"] is None, (
        "Rejected input published a partial document or a verified-complete digest."
    )


def test_DiagnosticCeilingAndHumanPathsRemainExplicitAndSafe(tmp_path, monkeypatch):
    """Truncation and root/field locations remain visible without printing invalid values."""

    monkeypatch.setattr(commands, "MAX_DIAGNOSTICS", 1)
    status, result = Run(tmp_path, {})
    assert status == 1 and len(result["diagnostics"]) == 1 and result["diagnostics_truncated"], (
        "Excess diagnostics silently disappeared or produced a false valid result."
    )
    status, human = Run(tmp_path, {}, human=True)
    assert status == 1 and 'required: ""' in human and "diagnostics-truncated" in human, (
        "Human validation hid the root path or diagnostic ceiling."
    )


def test_MissingExtraAndMissingSchemaAreDistinctFixedRefusals(tmp_path, monkeypatch):
    """Base installs can show help, while actual validation requires the explicit optional extra."""

    original = builtins.__import__

    def Import(name, *args, **kwargs):
        """Model the genuine base-runtime absence of the optional validator."""

        if name == "jsonschema":
            raise ImportError("unretained dependency diagnostic")

        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", Import)
    status, result = Run(tmp_path, Example())
    assert status == 2 and result["failure"] == "validator-unavailable", (
        "An unavailable optional validator looked like an invalid extension or a traceback."
    )
    status, human = Run(tmp_path, Example(), human=True)
    assert status == 2 and "1337[validate]" in human, (
        "Missing-extra setup lacked an actionable hint."
    )

    def Missing():
        """Refuse absent installed data without falling back to checkout or HTTP."""

        raise FileNotFoundError("unretained physical path")

    monkeypatch.setattr(commands, "ReadSchema", Missing)
    status, result = Run(tmp_path, Example())
    assert status == 4 and result["failure"] == "schema-unavailable", (
        "Missing packaged data triggered a different resource selection or leaked its filename."
    )


@pytest.mark.parametrize("arguments", [[], ["unknown"], ["validate"], ["validate", "x", "--bad"]])
def test_InvalidGrammarNeverEchoesInputSelections(arguments):
    """One fixed JSON configuration refusal precedes every local input read."""

    output = StringIO()
    assert commands.RunExtensionCommands(arguments, output, jsonOutput=True) == 2, (
        "Invalid validation arguments must return the configuration exit code."
    )
    result = json.loads(output.getvalue())
    assert result["failure"] == "configuration" and result["diagnostics"] == [], (
        "Invalid grammar escaped the fixed diagnostic boundary."
    )


def test_CliAndShellUseTheSameReadOnlyCommandAndProtectArguments(tmp_path, capsys):
    """Normal product dispatch preserves validation output, exit and private filename history."""

    source = tmp_path / "private manifest.json"
    source.write_text(json.dumps(Example()))
    before = source.read_bytes()
    assert Main(["extension", "validate", str(source), "--json"]) == 0, (
        "The public CLI must accept the packaged example before comparing its shell output."
    )
    expected = json.loads(capsys.readouterr().out)
    output = StringIO()
    shell = InteractiveShell(stdout=output)
    shell.onecmd('extension validate "' + str(source) + '" --json')
    assert json.loads(output.getvalue()) == expected and list(shell._history) == ["extension"], (
        "Shell dispatch changed the validator result or retained private input arguments."
    )
    assert source.read_bytes() == before, "Metadata validation changed its original source bytes."


@pytest.mark.parametrize("arguments", [["--help"], ["validate", "--help"]])
def test_HelpRequiresNeitherManifestNorOptionalDependency(arguments):
    """Help remains an ordinary base-runtime operation without opening a workspace or document."""

    output = StringIO()
    assert (commands.RunExtensionCommands(arguments, output) == 0
            and "manifest" in output.getvalue()), (
        "Base-install help must succeed and describe the selected manifest."
    )


def test_TrustedSchemaCannotRetrieveExternalReferences():
    """Even a damaged packaged reference is withheld through the closed in-memory registry."""

    with pytest.raises(commands.ManifestFailure, match="schema-unavailable"):
        commands.StructuralDiagnostics({}, {"$ref": "https://example.invalid/must-not-contact"})


def test_ExactOperationalInputBoundariesRemainAdmitted():
    """Boundary JSON reaches the real schema; the adjacent overflow is an operational refusal."""

    payload = b"0" + b" " * (commands.MAX_MANIFEST_BYTES - 1)
    assert commands.DecodeManifest(payload) == 0, "The exact byte ceiling was refused."
    depth = commands.MAX_MANIFEST_DEPTH
    assert isinstance(commands.DecodeManifest(b"[" * depth + b"0" + b"]" * depth), list), (
        "The exact supported nesting depth was refused."
    )
    payload = b"[" + b"0," * (commands.MAX_MANIFEST_NODES - 2) + b"0]"
    assert len(commands.DecodeManifest(payload)) == commands.MAX_MANIFEST_NODES - 1, (
        "The root node was miscounted at the exact value-node ceiling."
    )


def test_FileAndPackagedSchemaFailuresRemainDistinctAndDoNotLeakPaths(tmp_path, monkeypatch):
    """Absent/directory input and damaged installed schema produce fixed operational outcomes."""

    for source in (tmp_path / "absent-private-file", tmp_path):
        output = StringIO()
        assert commands.RunExtensionCommands(["validate", str(source)], output,
                                             jsonOutput=True) == 2, (
            "An absent or non-file input must return the input selection exit code."
        )
        result = json.loads(output.getvalue())
        assert result["failure"] == "input-file" and str(source) not in output.getvalue(), (
            "A local file refusal leaked its selected private path or changed failure class."
        )

    def BrokenSchema():
        """Model installed contract corruption without creating an input-selected schema."""

        return b'{"type": "not-a-json-schema-type"}'

    monkeypatch.setattr(commands, "ReadSchema", BrokenSchema)
    status, result = Run(tmp_path, Example())
    assert status == 4 and result["failure"] == "schema-unavailable", (
        "A damaged installed contract was reported as invalid caller metadata."
    )


def test_InterruptedInputDoesNotProducePartialValidation(tmp_path, monkeypatch):
    """An operator interruption has its distinct exit and never claims a completed digest."""

    def Interrupted(path):
        """Interrupt at the local read boundary before admitting any complete source bytes."""

        raise KeyboardInterrupt

    monkeypatch.setattr(commands, "ReadManifest", Interrupted)
    status, result = Run(tmp_path, Example())
    assert status == 130 and result["failure"] == "interrupted", (
        "Interruption was swallowed or misreported as schema invalidity."
    )
    assert result["manifest_sha256"] is None and result["diagnostics"] == [], (
        "An interrupted read must leave the digest and validation diagnostics unreported."
    )
