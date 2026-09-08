import json
import subprocess
import sys
import tomllib
import venv
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def invoke(arguments, cwd):
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
def test_sdist_wheel_and_clean_installation(tmp_path):
    metadata = tomllib.loads(
        (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    output = tmp_path / "dist"
    invoke(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(output)],
        ROOT,
    )
    assert len(list(output.glob("*.tar.gz"))) == 1
    wheels = list(output.glob("*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as archive:
        members = archive.namelist()
        assert "fuzzy1337/cli.py" in members
        assert all(name.startswith(("fuzzy1337/", "1337-")) for name in members)
        assert not any(name.endswith(".pyc") for name in members)

    environment = tmp_path / "installed"
    venv.EnvBuilder(with_pip=True).create(environment)
    scripts = environment / ("Scripts" if sys.platform == "win32" else "bin")
    executable = scripts / ("python.exe" if sys.platform == "win32" else "python")
    invoke(
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
        invoke([str(executable), "-I", "-m", "fuzzy1337", "--version"], tmp_path).strip()
        == expected
    )
    suffix = ".exe" if sys.platform == "win32" else ""
    assert invoke([str(scripts / f"1337{suffix}"), "--version"], tmp_path).strip() == expected
    assert "1337 repository quality gates" in invoke(
        [str(scripts / f"1337-dev{suffix}"), "--help"],
        tmp_path,
    )
    location = invoke(
        [
            str(executable),
            "-I",
            "-c",
            "import fuzzy1337,json; print(json.dumps(fuzzy1337.__file__))",
        ],
        tmp_path,
    )
    assert Path(json.loads(location)).is_relative_to(environment)
