# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Reuse immutable workflow parses while preserving independent mutable documents per caller."""

from copy import deepcopy
from functools import cache
from pathlib import Path
from typing import Any

import yaml

__all__ = ["ReadWorkflow"]


@cache
def ParseWorkflow(source: str) -> dict[str, Any]:
    """Cache the internal parse; public readers must return detached copies."""

    return yaml.safe_load(source)


def ReadWorkflow(path: Path) -> dict[str, Any]:
    """Read current source bytes and return a detached copy of their parsed YAML value."""

    return deepcopy(ParseWorkflow(path.read_text(encoding="utf-8")))
