"""Repository-wide pytest execution configuration."""

from __future__ import annotations

import os

import pytest

MAXPARALLELWORKERS = 12


def pytest_xdist_auto_num_workers(config: pytest.Config) -> int:
    """Cap automatic xdist workers so CI hosts do not oversubscribe CPUs."""

    del config
    return min(os.cpu_count() or 1, MAXPARALLELWORKERS)
