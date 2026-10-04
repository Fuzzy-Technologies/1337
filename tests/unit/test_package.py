# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Tests for package behavior."""


def test_PackageImports():
    """Verify package imports."""

    import fuzzy1337

    assert fuzzy1337.__all__ == [], "package imports invariant failed."
