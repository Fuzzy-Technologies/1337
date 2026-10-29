# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Separate genuine target-free unchanged-provider environment prerequisite, with no HOME."""

from __future__ import annotations

import asyncio
import os

import pytest

from .external_nuclei_host import Enabled, PrerequisiteHost

pytestmark = pytest.mark.serial
SELECTION = "FUZZY1337_EXTERNAL_NUCLEI_GOVERNED_PREREQUISITES"


def test_InstalledImageRunsExactGovernedEnvironmentWithoutHome():
    """Require genuine version and strict Go validation before any comparative target starts."""

    if not Enabled(os.environ.get(SELECTION)):
        pytest.skip("Governed no-HOME compatibility is UNRUN without linux-amd64 selection")

    receipt = asyncio.run(PrerequisiteHost(governed_no_home=True).Run())
    assert receipt["status"] == "completed-governed-prerequisites" and (
        receipt["governed_no_home_compatibility"] == "established"
        and receipt["configured_target_inputs"] == []
    ), "Only genuine target-free unchanged-environment evidence can establish this prerequisite"
