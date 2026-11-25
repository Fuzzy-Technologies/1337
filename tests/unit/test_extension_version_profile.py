# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Opt-in SemVer version-string checks preserve the Stable v1 manifest consumer."""

import builtins
import json
from io import StringIO

import pytest
from jsonschema import Draft202012Validator

from fuzzy1337 import extension_commands as commands
from tests.contract.report_export_fixture import DenyExecution
from tests.unit.test_extension_commands import Example, Schema


def Validate(root, instance, *, strict=True, human=False):
    """Validate actual file bytes through the existing handler and optional explicit profile."""

    path = root / "owned manifest.json"
    payload = json.dumps(instance).encode("utf-8")
    path.write_bytes(payload)
    arguments = ["validate", str(path)]

    if strict:
        arguments.extend(("--version-profile", "semver-2.0.0"))

    output = StringIO()
    status = commands.RunExtensionCommands(arguments, output, jsonOutput=not human)
    assert path.read_bytes() == payload, "Version validation must not rewrite the selected manifest"

    return status, output.getvalue() if human else json.loads(output.getvalue())


@pytest.mark.parametrize("version", [
    "0.0.0", "1.2.3", "1.2.3-alpha.1", "1.2.3-0", "1.2.3--",
    "1.2.3-01a", "1.2.3-01-", "1.2.3-00-", "1.2.3-0-", "1.2.3-a01",
    "1.2.3+001", "1.2.3+01a", "1.2.3+0-", "1.2.3+000.001",
    "1.2.3-rc.0+build.001", "1.2.3+-", "9" * 5000 + ".0.0",
])
def test_StrictProfileAcceptsSemverGrammarWithoutChangingDefaultFacts(tmp_path, version):
    """Prerelease hyphens/non-numeric IDs and numeric build metadata retain their distinct rules."""

    instance = Example()
    instance["extension"]["version"] = version
    assert Draft202012Validator(Schema()).is_valid(instance), (
        "Positive profile controls must also satisfy the unchanged canonical schema"
    )
    status, default = Validate(tmp_path, instance, strict=False)
    assert status == 0 and "version_profile" not in default, "Preserve original default acceptance"
    status, result = Validate(tmp_path, instance)
    assert status == 0 and result["status"] == "valid" and result["diagnostics"] == [], (
        "The explicit profile refused a valid SemVer version-string control"
    )
    assert result["version_profile"] == "semver-2.0.0", "Record the selected metadata profile"
    originalFacts = dict(result)
    del originalFacts["version_profile"]
    assert originalFacts == default, "Valid opt-in checks must preserve every outcome field"


@pytest.mark.parametrize("version", [
    "1.2.3-01", "1.2.3-00", "1.2.3-alpha..1", "1.2.3-alpha.01",
    "1.2.3-alpha.", "1.2.3+foo..bar", "1.2.3+.", "1.2.3\n",
])
def test_StrictProfileRejectsLegacyVersionHolesWithoutTighteningV1(tmp_path, version):
    """The explicit supplement may refuse metadata that the preserved Stable reader admits."""

    instance = Example()
    instance["extension"]["version"] = version
    assert Draft202012Validator(Schema()).is_valid(instance), (
        "The negative differential controls must prove an actual legacy schema acceptance hole"
    )
    status, default = Validate(tmp_path, instance, strict=False)
    assert status == 0 and default["status"] == "valid", "Do not silently tighten the Stable schema"
    status, result = Validate(tmp_path, instance)
    assert status == 1 and result["status"] == "invalid" and result["failure"] is None, (
        "Invalid version syntax must remain metadata invalidity"
    )
    assert result["diagnostics"] == [{"code": "semver-2.0.0", "path": "/extension/version"}], (
        "Identify the exact fixed version profile and instance path without echoing rejected values"
    )
    assert result["manifest_sha256"] == default["manifest_sha256"] and result[
        "schema_sha256"
    ] == default["schema_sha256"], "Retain original input and canonical schema pins"
    assert result["core_compatibility"] == "not-evaluated" and result[
        "extension_activation"
    ] == "not-attempted", "A version-string decision must not establish compatibility or authority"


@pytest.mark.parametrize("version", [
    None, True, 123, b"1.2.3", "", "v1.2.3", "01.2.3", "1.2", "1.2.3-",
    "1.2.3+", "1.2.3+abc+def", "1.2.3-alpha_beta", "1.2.3\u0000",
    "1.2.3\r", "1.2.3\r\n", "\u0661.2.3",
])
def test_GrammarNeverCoercesNonstringNonasciiOrMalformedMetadata(version):
    """The Internal grammar checker rejects data types and delimiters outside SemVer 2.0.0."""

    assert commands.IsSemVer200(version) is False, "Do not coerce or trim invalid version metadata"


def test_UnknownProfileFailsBeforeReadingAndNeverEchoesTheSelection(tmp_path, monkeypatch):
    """An unknown profile cannot fall back to the default or cause source-directed file reads."""

    def Denied(*arguments, **options):
        """Expose any premature file read after a rejected profile selection."""

        raise AssertionError("Unknown version profiles must fail before reading a manifest")

    monkeypatch.setattr(commands, "ReadManifest", Denied)
    output = StringIO()
    status = commands.RunExtensionCommands([
        "validate", str(tmp_path / "absent.json"), "--version-profile", "private-unknown-profile",
    ], output, jsonOutput=True)
    result = json.loads(output.getvalue())
    assert status == 2 and result["failure"] == "configuration", "Refuse unknown profile grammar"
    assert "private-unknown-profile" not in output.getvalue(), "Do not echo the rejected profile"
    assert result["manifest_sha256"] is None and result["diagnostics"] == [], (
        "Configuration refusal must not claim input admission or partial metadata validation"
    )


def test_CanonicalStructuralFailurePrecedesSupplementalVersionChecking(tmp_path, monkeypatch):
    """Canonical schema diagnostics remain authoritative before the optional string supplement."""

    instance = Example()
    instance["extension"]["version"] = None
    expected = Draft202012Validator(Schema()).is_valid(instance)
    assert expected is False, "The control must fail the actual canonical schema"

    def Denied(*arguments, **options):
        """Reject any supplemental check before the mandatory structural validation has passed."""

        raise AssertionError("Strict version checking must follow canonical structural acceptance")

    monkeypatch.setattr(commands, "IsSemVer200", Denied)
    status, result = Validate(tmp_path, instance)
    assert status == 1 and result["diagnostics"], "Preserve canonical schema-invalid status"
    assert all(item["code"] != "semver-2.0.0" for item in result["diagnostics"]), (
        "Do not replace canonical diagnostics with a fabricated version-only decision"
    )


def test_OptInStillRequiresTheOptionalCanonicalValidator(tmp_path, monkeypatch):
    """The supplementary grammar never bypasses missing optional structural validation tooling."""

    original = builtins.__import__

    def Missing(name, *arguments, **options):
        """Simulate the base installation without the optional validation dependency."""

        if name == "jsonschema" or name.startswith("jsonschema."):
            raise ImportError("Owned missing optional validator")

        return original(name, *arguments, **options)

    monkeypatch.setattr(builtins, "__import__", Missing)
    status, result = Validate(tmp_path, Example())
    assert status == 2 and result["failure"] == "validator-unavailable", (
        "Version syntax alone must not make an unvalidated manifest valid"
    )
    assert result["diagnostics"] == [], "Missing tooling must not emit a partial validation list"


def test_StrictProfileLeavesLocatorsAndCoreRangesInert(tmp_path, monkeypatch):
    """Version metadata grants no source lookup, extension import or Core interpretation."""

    instance = Example()
    instance["$schema"] = "https://example.invalid/do-not-fetch"
    instance["compatibility"]["core"] = "not-a-range"
    instance["entry_points"]["tool_adapters"][0]["target"] = "untrusted_extension:Activate"
    original = builtins.__import__

    def RefuseExtension(name, *arguments, **options):
        """Expose any attempt to import the manifest-declared implementation."""

        if name.startswith("untrusted_extension"):
            raise AssertionError("Metadata validation must not import extension implementations")

        return original(name, *arguments, **options)

    monkeypatch.setattr(builtins, "__import__", RefuseExtension)
    DenyExecution(monkeypatch)
    status, result = Validate(tmp_path, instance)
    assert status == 0 and result["version_profile"] == "semver-2.0.0", (
        "A declared locator or opaque Core range must not become an activation or resolver input"
    )
    assert result["core_compatibility"] == "not-evaluated" and result[
        "extension_activation"
    ] == "not-attempted", "A strict string profile must preserve the existing authority boundary"


def test_HumanResultNamesTheSelectedProfileWithoutRevealingVersionData(tmp_path):
    """Human diagnostics identify the selected policy and exact pointer without source values."""

    instance = Example()
    instance["extension"]["version"] = "1.2.3-private..invalid"
    status, output = Validate(tmp_path, instance, human=True)
    assert status == 1 and "Version profile: semver-2.0.0" in output, (
        "Human validation must make its explicit profile visible"
    )
    assert 'semver-2.0.0: "/extension/version"' in output, "Locate the invalid version precisely"
    assert "1.2.3-private..invalid" not in output, "Do not echo original invalid metadata"
