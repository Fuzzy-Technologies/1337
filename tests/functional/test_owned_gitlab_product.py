# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Run the unchanged public template on an actually owned GitLab server and shell runner."""

import os
from pathlib import Path

import pytest

from tests.functional import owned_gitlab_platform as platform


@pytest.fixture
def owned_gitlab():
    """Own the finite real platform cohort; missing opt-in is explicitly unexecuted locally."""

    if os.environ.get("FUZZY1337_RUN_OWNED_GITLAB_ACCEPTANCE") != "1":
        pytest.skip("Real owned GitLab requires the explicit dedicated platform opt-in")

    source = Path(__file__).resolve().parents[2]
    output = Path(os.environ["FUZZY1337_GITLAB_EVIDENCE"])
    result = platform.Run(source, output, platform.PYTHON_IMAGE)

    return source, output, result


@pytest.mark.serial
def test_PublicTemplateRunsOnOwnedGitLab(owned_gitlab):
    """Require both actual approval outcomes and independently reopen their original artifacts."""

    source, output, result = owned_gitlab
    verified = platform.Verify(output, source)
    assert verified == result, (
        "Actual GitLab cohort must reopen exactly its original verified result")
    assert len(set(verified["job_ids"])) == 2, (
        "Approval absent and approved must execute as two distinct real GitLab jobs")
