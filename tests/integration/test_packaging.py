"""Tests for packaging behavior."""

import json
import subprocess
import sys
import tomllib
import venv
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def Invoke(arguments, cwd):
    """Provide deterministic test support for invoke."""

    result = subprocess.run(
        arguments,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


@pytest.mark.integration
def test_SdistWheelAndCleanInstallation(tmp_path):
    """Verify sdist wheel and clean installation."""

    metadata = tomllib.loads(
        (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    output = tmp_path / "dist"
    Invoke(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(output)],
        ROOT,
    )
    assert len(list(output.glob("*.tar.gz"))) == 1, (
        "sdist wheel and clean installation invariant failed."
    )
    wheels = list(output.glob("*.whl"))
    assert len(wheels) == 1, "sdist wheel and clean installation invariant failed."
    with zipfile.ZipFile(wheels[0]) as archive:
        members = archive.namelist()
        assert "fuzzy1337/cli.py" in members, "sdist wheel and clean installation invariant failed."
        assert "fuzzy1337/adapters/contracts.py" in members, (
            "sdist wheel and clean installation invariant failed."
        )
        assert "fuzzy1337/executors/contracts.py" in members, (
            "sdist wheel and clean installation invariant failed."
        )
        assert "fuzzy1337/executors/local.py" in members, (
            "sdist wheel and clean installation invariant failed."
        )
        assert all(name.startswith(("fuzzy1337/", "1337-")) for name in members), (
            "sdist wheel and clean installation invariant failed."
        )
        assert not any(name.endswith(".pyc") for name in members), (
            "sdist wheel and clean installation invariant failed."
        )

    environment = tmp_path / "installed"
    venv.EnvBuilder(with_pip=True).create(environment)
    scripts = environment / ("Scripts" if sys.platform == "win32" else "bin")
    executable = scripts / ("python.exe" if sys.platform == "win32" else "python")
    Invoke(
        [
            str(executable),
            "-m",
            "pip",
            "--isolated",
            "install",
            "--no-index",
            "--no-deps",
            str(wheels[0]),
        ],
        tmp_path,
    )
    expected = f"1337 {metadata['version']}"
    assert (
        Invoke([str(executable), "-I", "-m", "fuzzy1337", "--version"], tmp_path).strip()
        == expected
    ), "sdist wheel and clean installation invariant failed."
    suffix = ".exe" if sys.platform == "win32" else ""
    assert Invoke([str(scripts / f"1337{suffix}"), "--version"], tmp_path).strip() == expected, (
        "sdist wheel and clean installation invariant failed."
    )
    assert "1337 repository quality gates" in Invoke(
        [str(scripts / f"1337-dev{suffix}"), "--help"],
        tmp_path,
    ), "sdist wheel and clean installation invariant failed."
    assert Invoke(
        [
            str(executable),
            "-I",
            "-c",
            "from fuzzy1337.adapters import ADAPTERCONTRACTVERSION; "
            "print(ADAPTERCONTRACTVERSION)",
        ],
        tmp_path,
    ).strip() == "1", "sdist wheel and clean installation invariant failed."
    assert Invoke(
        [
            str(executable),
            "-I",
            "-c",
            "from fuzzy1337.executors import EXECUTORCONTRACTVERSION; "
            "print(EXECUTORCONTRACTVERSION)",
        ],
        tmp_path,
    ).strip() == "1", "sdist wheel and clean installation invariant failed."
    location = Invoke(
        [
            str(executable),
            "-I",
            "-c",
            "import fuzzy1337,json; print(json.dumps(fuzzy1337.__file__))",
        ],
        tmp_path,
    )
    assert Path(json.loads(location)).is_relative_to(environment), (
        "sdist wheel and clean installation invariant failed."
    )
