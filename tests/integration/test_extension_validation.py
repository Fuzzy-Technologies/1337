# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise optional offline validation through clean installed module and console entry points."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import venv
from pathlib import Path

import pytest
from packaging.requirements import Requirement

from tools.release_delivery import Invoke as Prepare
from tools.release_delivery import ProvisionLocalWheelRuntime

ROOT = Path(__file__).resolve().parents[2]


def Invoke(arguments, directory, expected=0):
    """Capture the real subprocess outcome while preserving its original nonzero result."""

    result = subprocess.run(arguments, cwd=directory, capture_output=True, text=True,
                            timeout=120, check=False)
    assert result.returncode == expected, result.stdout + result.stderr

    return result.stdout


@pytest.mark.integration
def test_CleanWheelRequiresOptionalExtraAndValidatesWithoutExternalActions(tmp_path):
    """A base install refuses honestly; the real extra enables only local schema checks."""

    output = tmp_path / "dist"
    Invoke([sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(output)],
           ROOT)
    wheel = next(output.glob("*.whl"))
    environment = tmp_path / "installed"
    venv.EnvBuilder(with_pip=True).create(environment)
    scripts = environment / ("Scripts" if sys.platform == "win32" else "bin")
    python = scripts / ("python.exe" if sys.platform == "win32" else "python")
    consumer = tmp_path / "consumer"
    consumer.mkdir()
    Invoke([str(python), "-m", "pip", "--isolated", "install", "--no-index", "--no-deps",
            str(wheel)], consumer)
    ProvisionLocalWheelRuntime(wheel, python, consumer)
    Invoke([str(python), "-m", "pip", "--isolated", "check"], consumer)
    requirements = [Requirement(item) for item in json.loads(Invoke([
        str(python), "-I", "-c", "import json; from importlib.metadata import requires; "
        "print(json.dumps(requires('1337')))"
    ], consumer))]
    assert [str(item) for item in requirements if item.marker is None] == [
        "fuzzyroutines==2.1.0"
    ], (
        "The optional validator became a mandatory dependency of the built wheel."
    )
    selected = {item.name: str(item.specifier) for item in requirements
                if item.marker is None or item.marker.evaluate({"extra": "validate"})}
    assert selected == {"fuzzyroutines": "==2.1.0", "jsonschema": "==4.26.0"}, (
        "The installed wheel lost its declared optional validation dependency."
    )
    example = ROOT / "contracts/examples/extension-manifest.example.json"
    instance = json.loads(example.read_bytes())
    source = consumer / "selected manifest.json"
    source.write_text(json.dumps(instance))
    module = [str(python), "-I", "-m", "fuzzy1337", "extension", "validate"]
    console = [str(scripts / ("1337.exe" if sys.platform == "win32" else "1337")),
               "extension", "validate"]
    assert "manifest" in Invoke([*module, "--help"], consumer), (
        "The base-runtime command cannot explain its optional setup without importing a validator."
    )
    refused = json.loads(Invoke([*module, str(source), "--json"], consumer, expected=2))
    assert refused["failure"] == "validator-unavailable" and refused["diagnostics"] == [], (
        "Base runtime attempted hidden installation or treated a missing extra as invalid metadata."
    )
    uv = shutil.which("uv")
    assert uv is not None, "The packaging acceptance requires the existing pinned uv tool."
    Prepare((uv, "--offline", "--no-config", "--no-python-downloads", "sync", "--project",
             str(ROOT), "--locked", "--no-dev", "--extra", "validate", "--no-install-project",
             "--inexact"), consumer, project_environment=environment)
    Invoke([str(python), "-m", "pip", "--isolated", "check"], consumer)
    before = source.read_bytes()
    outcome = json.loads(Invoke([*module, str(source), "--json"], consumer))
    assert json.loads(Invoke([*console, str(source), "--json"], consumer)) == outcome, (
        "Installed console and isolated module entry points expose different validation semantics."
    )
    assert outcome["status"] == "valid" and outcome["manifest_sha256"] == hashlib.sha256(
        before
    ).hexdigest(), "The actual installed validator lost its complete original input identity."
    schemaRaw = (ROOT / "contracts/extension-manifest.schema.json").read_bytes()
    assert outcome["schema_sha256"] == hashlib.sha256(schemaRaw).hexdigest(), (
        "Installed validation selected a different schema than the packaged canonical source."
    )
    guarded = '''
"""Run the installed operator interface with networking and extension execution denied."""

import json
import sys


def Guard(event, arguments):
    """Refuse source-directed I/O, plugin imports and child process creation."""

    if event in {"socket.connect", "socket.connect_ex", "socket.getaddrinfo", "subprocess.Popen",
                 "os.system", "os.exec"}:
        raise AssertionError("Offline metadata validation attempted an external action.")

    if event == "import" and arguments[0].startswith("untrusted_extension"):
        raise AssertionError("The validator imported the declared extension implementation.")

    if event == "open" and "must-not-read" in str(arguments[0]):
        raise AssertionError("The validator followed a source-declared local reference.")


sys.addaudithook(Guard)
import fuzzy1337
from fuzzy1337.cli import Main
assert "/src/" not in fuzzy1337.__file__.replace("\\\\", "/")
raise SystemExit(Main(sys.argv[1:]))
'''
    instance["$schema"] = "file:///must-not-read"
    instance["extension"]["version"] = "1.2.3-01"
    instance["compatibility"]["core"] = "not-a-core-range"
    instance["entry_points"]["tool_adapters"][0]["target"] = "untrusted_extension:Activate"
    source.write_text(json.dumps(instance))
    audited = [str(python), "-I", "-c", guarded, "extension", "validate", str(source), "--json"]
    result = json.loads(Invoke(audited, consumer))
    assert result["status"] == "valid" and result["core_compatibility"] == "not-evaluated", (
        "The installed consumer tightened legacy v1 or interpreted range/implementation locators."
    )
    instance["$schema"] = "https://example.invalid/must-not-contact"
    source.write_text(json.dumps(instance))
    assert json.loads(Invoke(audited, consumer))["status"] == "valid", (
        "A source-declared schema URI was interpreted instead of remaining ordinary instance data."
    )
    instance["extension"]["version"] = "PRIVATE_INVALID_VALUE"
    source.write_text(json.dumps(instance))
    invalid = Invoke(audited, consumer, expected=1)
    result = json.loads(invalid)
    assert result["status"] == "invalid" and result["diagnostics"] == [
        {"code": "pattern", "path": "/extension/version"}
    ] and "PRIVATE_INVALID_VALUE" not in invalid, (
        "Installed invalid metadata lost its exact safe code/path diagnostic."
    )
    assert not (consumer / "__pycache__").exists(), "Validation imported candidate extension files."
