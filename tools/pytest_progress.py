# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Register checkout-only pytest diagnostics after worker coverage starts.

The early ``-p`` import deliberately has no dependency on the measured application package.
The pinned pytest-cov worker starts tracing in its default-order session-start hook, before
this trylast hook imports the bounded recorder. Normal CLI startup does not load this tool.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pytest import hookimpl

if TYPE_CHECKING:
    from pytest import Parser, Session


def pytest_addoption(parser: Parser) -> None:
    """Register the fixed runner-only diagnostic opt-in without importing application code.

    Args:
        parser: Pytest option parser supplied through its public plugin interface.
    """

    parser.addoption("--1337-progress", action="store_true", default=False,
                     help="retain bounded partial test diagnostics beside JUnit")


@hookimpl(trylast=True)
def pytest_sessionstart(session: Session) -> None:
    """Import and register the recorder after coverage has started in the current worker.

    Args:
        session: Started pytest session with the existing fixed diagnostic option.
    """

    if session.config.getoption("--1337-progress", default=False):
        from fuzzy1337.test_progress import ConfigureProgress

        ConfigureProgress(session.config)
