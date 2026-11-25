# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Installed module version-profile checks preserve the default Stable manifest reader."""

import json
import subprocess
import sys

import pytest

from tests.unit.test_extension_commands import Example


@pytest.mark.parametrize("version,expected", [
    ("1.2.3-01", 1), ("1.2.3-alpha..1", 1), ("1.2.3--", 0), ("1.2.3+001", 0),
])
def test_InstalledModuleProvidesExplicitSemverProfileWithoutChangingDefault(
    tmp_path, version, expected,
):
    """An actual installed entry point exposes differential invalidity and both valid controls."""

    instance = Example()
    instance["extension"]["version"] = version
    source = tmp_path / "selected manifest.json"
    payload = json.dumps(instance).encode("utf-8")
    source.write_bytes(payload)
    command = [sys.executable, "-I", "-m", "fuzzy1337", "extension", "validate", str(source)]

    def Invoke(arguments):
        """Invoke only the local installed module outside the checkout with bounded transport."""

        process = subprocess.run([*command, *arguments, "--json"], cwd=tmp_path,
            capture_output=True, text=True, timeout=15, check=False)
        assert not process.stderr, "Installed metadata validation must produce no traceback"

        return process.returncode, json.loads(process.stdout)

    status, default = Invoke([])
    assert status == 0 and "version_profile" not in default, (
        "The published v1 reader must preserve these already accepted legacy version controls"
    )
    status, selected = Invoke(["--version-profile", "semver-2.0.0"])
    assert status == expected and selected["status"] == ("valid" if expected == 0 else "invalid"), (
        "The installed profile must implement the declared version-string grammar"
    )
    assert selected["version_profile"] == "semver-2.0.0", "Record the explicit selected profile"

    if expected == 1:
        assert selected["diagnostics"] == [
            {"code": "semver-2.0.0", "path": "/extension/version"},
        ], "The installed refusal must expose only the fixed version diagnostic and pointer"

    else:
        comparable = dict(selected)
        del comparable["version_profile"]
        assert comparable == default, "A valid supplement must not change prior result fields"

    assert selected["core_compatibility"] == "not-evaluated" and selected[
        "extension_activation"
    ] == "not-attempted", "Metadata validation must not become an execution or compatibility grant"
    assert source.read_bytes() == payload, "The installed consumer must not rewrite the manifest"
