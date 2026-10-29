# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Opt-in single installed-image offline Nuclei prerequisite; no target or case execution."""

from __future__ import annotations

import os

import pytest

from .external_nuclei_host import SELECTION, Enabled, PrerequisiteHost

pytestmark = pytest.mark.serial


@pytest.fixture(scope="module")
def nuclei_prerequisite():
    """Skip disabled selection before discovery; enabled failures retain their owned evidence.

    Returns:
        Actual completed prerequisite-only host receipt after independent Docker cleanup.

    Raises:
        ValueError: Enabled source/image/container/prerequisite requirements refuse.
        OSError: Enabled local tooling or original evidence is unavailable.
        BaseException: The host owner propagates its primary failure after cleanup.
    """

    if not Enabled(os.environ.get(SELECTION)):
        pytest.skip("Nuclei image prerequisite is UNRUN without explicit linux-amd64 selection")

    return PrerequisiteHost().Run()


def test_InstalledImageRunsOfflineExactNucleiPrerequisites(nuclei_prerequisite):
    """Require actual version and exact-template Go validation under the inspected offline image.

    Args:
        nuclei_prerequisite: Actual non-skipped host receipt; no application case is configured.
    """

    assert nuclei_prerequisite["status"] == "completed-prerequisites", (
        'Actual prerequisite evidence must preserve its target-free scope and uncertainty.'
    )
    assert nuclei_prerequisite["configured_target_inputs"] == [], (
        'Actual prerequisite evidence must preserve its target-free scope and uncertainty.'
    )
    assert nuclei_prerequisite["governed_no_home_compatibility"] == "not-established", (
        'Actual prerequisite evidence must preserve its target-free scope and uncertainty.'
    )
