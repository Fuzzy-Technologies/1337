# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Repository-wide pytest execution configuration and shared fixture namespace."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

MAX_PARALLEL_WORKERS = 12

# The package lives in src, so adding the checkout root only exposes test/tooling namespaces.
REPOSITORY_ROOT = str(Path(__file__).resolve().parents[1])

if REPOSITORY_ROOT not in sys.path:
    sys.path.insert(0, REPOSITORY_ROOT)


def pytest_xdist_auto_num_workers(config: pytest.Config) -> int:
    """Cap automatic xdist workers so CI hosts do not oversubscribe CPUs."""

    del config
    return min(os.cpu_count() or 1, MAX_PARALLEL_WORKERS)
