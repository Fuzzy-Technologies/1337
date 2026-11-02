# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Tests for package behavior."""

from pathlib import Path

import pytest


def test_PackageImports():
    """Verify package imports."""

    import fuzzy1337

    assert fuzzy1337.__all__ == [], "package imports invariant failed."


@pytest.mark.parametrize("recipe", ["native-runner.Dockerfile", "nuclei-runner.Dockerfile"])
def test_BenchmarkRuntimeInstallsPinnedDependenciesOnlyAfterImagePreparation(recipe):
    """Cache-free benchmark children consume the prepared wheelhouse with runtime networking off."""

    root = Path(__file__).resolve().parents[2]
    base = (root / "Dockerfile").read_text()
    child = (root / "labs/external/benchmark" / recipe).read_text()
    assert "UV_NO_CACHE=1" in base and (
        "FUZZY1337_RUNTIME_WHEELHOUSE=/opt/1337/runtime-wheels" in base
    ), "No-cache containers must declare their finite dependency prerequisite directory"
    assert "uv export --locked --no-dev --no-emit-project --format requirements.txt" in base and (
        "pip download --only-binary=:all: --require-hashes" in base
    ), "Only the permitted image preparation phase may fetch source-lock checked runtime wheels"
    assert "RUN --network=none /opt/1337/.venv/bin/python -m build" in child and (
        "--no-index --no-deps --require-hashes --find-links=/opt/1337/runtime-wheels" in child
    ), "Benchmark child preparation must keep builds and dependency installation without networking"
    assert child.index("--require-hashes") < child.index("/opt/benchmark-wheel/*.whl") and (
        "-m pip --isolated check" in child
    ), "Dependency preparation must precede the isolated app wheel and consistency check"
