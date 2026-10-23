# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Portable coverage-order tests for the explicit checkout-only pytest bootstrap."""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from types import SimpleNamespace

from tools import pytest_progress as bootstrap


def test_OptionRegistrationRequiresNoApplicationImport():
    """The early hook exposes only the fixed boolean diagnostic opt-in."""

    captured = []
    bootstrap.pytest_addoption(SimpleNamespace(
        addoption=lambda *args, **kwargs: captured.append((args, kwargs)),
    ))
    assert captured[0][0] == ("--1337-progress",), "Only the fixed opt-in may be registered."
    assert captured[0][1]["action"] == "store_true", "The option must not accept paths or code."
    tree = ast.parse(Path(bootstrap.__file__).read_text(encoding="utf-8"))
    imports = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
    imported_names = [node.module for node in imports
                      if isinstance(node, ast.ImportFrom) and node.module is not None]
    imported_names.extend(alias.name for node in imports if isinstance(node, ast.Import)
                          for alias in node.names)
    assert not any(name.startswith("fuzzy1337") for name in imported_names), (
        "The explicit early plugin import must have no application-package dependency."
    )


def test_RecorderImportOccursOnlyInOptedInTryLastSessionStart(monkeypatch):
    """The lazy import runs after default-order coverage startup in each actual process."""

    calls = []
    delegate = SimpleNamespace(ConfigureProgress=lambda config: calls.append(config))
    monkeypatch.setitem(sys.modules, "fuzzy1337.test_progress", delegate)
    enabled = [False]
    config = SimpleNamespace(getoption=lambda *args, **kwargs: enabled[0])
    session = SimpleNamespace(config=config)
    bootstrap.pytest_sessionstart(session)
    assert not calls, "Disabled diagnostics must not invoke the package recorder."
    enabled[0] = True
    bootstrap.pytest_sessionstart(session)
    assert calls == [config], "An opted-in session must delegate exactly its own configuration."
    assert bootstrap.pytest_sessionstart.pytest_impl["trylast"] is True, (
        "The actual pytest hook must run after pytest-cov's default-order worker startup."
    )
