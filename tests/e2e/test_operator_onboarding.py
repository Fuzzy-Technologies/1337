# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise the copyable CI recipe through a clean installed wheel and real owned target."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[2]
RECIPE = ROOT / "docs/examples/ci/run_demo.py"


@pytest.fixture(scope="module")
def installed_onboarding(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build once, install offline in a clean environment and return its isolated interpreter."""

    parent = tmp_path_factory.mktemp("installed-onboarding")
    wheel_directory = parent / "wheel"
    build = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir",
         str(wheel_directory)], cwd=ROOT, capture_output=True, text=True, timeout=90, check=False,
    )
    assert build.returncode == 0, build.stderr
    wheel, = wheel_directory.glob("*.whl")
    created = subprocess.run([sys.executable, "-m", "venv", str(parent / "venv")],
                             capture_output=True, text=True, timeout=60, check=False)
    assert created.returncode == 0, created.stderr
    python = parent / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    installed = subprocess.run(
        [str(python), "-m", "pip", "install", "--no-index", "--no-deps", "--no-compile",
         "--disable-pip-version-check", str(wheel)],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert installed.returncode == 0, installed.stderr
    provenance = subprocess.run(
        [str(python), "-I", "-c", "import fuzzy1337; print(fuzzy1337.__file__)"],
        cwd=parent, capture_output=True, text=True, timeout=10, check=False,
    )
    assert provenance.returncode == 0, provenance.stderr
    assert Path(provenance.stdout.strip()).is_relative_to(parent / "venv"), (
        "Recipe execution must resolve the installed wheel, never checkout source"
    )
    return python


@pytest.mark.parametrize("approved", [False, True])
def test_InstalledRecipePreservesRealApprovalAndEvidence(
    installed_onboarding: Path, tmp_path: Path, approved: bool,
) -> None:
    """Prove actual approval refusal, execution, offline export and unchanged-root rejection."""

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    environment = os.environ.copy()
    environment.pop("F1337_APPROVED_LOCAL_DEMO", None)

    if approved:
        environment["F1337_APPROVED_LOCAL_DEMO"] = "1"

    result = subprocess.run(
        [str(installed_onboarding), "-I", str(RECIPE), str(artifacts)],
        cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=90, check=False,
    )
    summary = json.loads((artifacts / "ci-result.json").read_bytes())
    jsonschema.validate(summary, json.loads((RECIPE.parent / "ci-result.schema.json").read_bytes()))
    assert result.returncode == (0 if approved else 3), (result.stdout, result.stderr, summary)
    assert summary["state"] == ("completed" if approved else "denied")
    runtime = json.loads((artifacts / "runtime.json").read_bytes())
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    assert runtime["package_version"] == f"1337 {version}"
    assert runtime["python_executable"] == str(installed_onboarding)
    diagnostics = json.loads((artifacts / "doctor-process.json").read_bytes())
    assert diagnostics["exit_status"] == 0 and diagnostics["stdout"]
    assert (artifacts / "demo").exists() is approved
    plan = json.loads((artifacts / "plan.json").read_bytes())
    assert plan["exit_status"] == 3 and plan["failure"] == "approval_required"
    assert plan["plan"]["bind_host"] == "127.0.0.1" and plan["plan"]["max_requests"] == 3

    if not approved:
        assert not (artifacts / "approved-process.json").exists()
        return

    export = json.loads((artifacts / "export.json").read_bytes())
    schema = json.loads((ROOT / "contracts/report-export-result.schema.json").read_bytes())
    jsonschema.validate(export, schema)
    assert export["snapshot_sha256"] == summary["snapshot_sha256"]
    assert summary["no_clobber_verified"] is True
    assert summary["target_teardown_completed"] is True
    assert summary["object_counts"] == {
        "host": 1, "port": 1, "service": 1, "endpoint": 3, "finding": 0,
    }
    for name, status in (("approved", 0), ("reopen", 0), ("export", 0), ("no-clobber", 2)):
        process = json.loads((artifacts / f"{name}-process.json").read_bytes())
        assert process["exit_status"] == status

    spec = importlib.util.spec_from_file_location("onboarding_recipe", RECIPE)
    assert spec is not None and spec.loader is not None
    recipe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(recipe)
    index = recipe.Read(artifacts / "demo/evidence-index.json")
    material = artifacts / "demo" / index["records"][0]["material_path"]
    material.write_bytes(b"changed retained acquisition")

    with pytest.raises(ValueError, match="Original evidence bytes"):
        recipe.Verify(artifacts, recipe.Read(artifacts / "approved.json"),
                      recipe.Read(artifacts / "reopen.json"), export)
