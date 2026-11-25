# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Installed single-CVE inspection preserves saved Unicode through strict terminal codecs."""

import hashlib
import json
import os
import shutil
import subprocess
from io import StringIO

import pytest

from fuzzy1337 import intelligence_cve_remote as remote
from fuzzy1337.intelligence_cve_https_commands import RunCveHttpsCommands
from fuzzy1337.model import CanonicalModelJson
from tests.e2e.test_intelligence_cli import Files
from tests.integration.test_intelligence_cve_batch import Workspace
from tests.unit.test_intelligence_cve_https_commands import Body, Refuse


@pytest.fixture(name="saved_cve")
def SavedCve(request, monkeypatch):
    """Materialize only owned synthetic source bytes with a deterministic in-memory receiver."""

    workspace = Workspace(request.getfixturevalue("tmp_path"))
    document = json.loads(Body())
    document["containers"]["cna"]["descriptions"][0]["value"] = (
        "Owned Unicode source: \u00e9 \u03bb \U0001f9ea"
    )
    payload = CanonicalModelJson(document)
    source = remote.CveHttpsSource("a" * 40, "CVE-1900-9999", hashlib.sha256(payload).hexdigest())
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", lambda *a, **k: (payload, "succeeded", 200))
    acquired = remote.AcquireHttpsCveSelection(workspace.root, remote.CveHttpsRequest(source),
                                              scope_reference="scope:owned")
    assert acquired.state is remote.CveHttpsState.SUCCEEDED, "Owned saved-source fixture failed"
    monkeypatch.setattr(remote, "AcquireHttpsCveSelection", Refuse)
    monkeypatch.setattr(remote, "ReceiveIsolatedHttps", Refuse)

    return workspace.root, acquired


@pytest.mark.parametrize("encoding", ["utf-8", "ascii"])
@pytest.mark.parametrize("corrupt", [False, True])
def test_InstalledSingleInspectPreservesUnicodeJsonAndSavedBytes(
    saved_cve, tmp_path, encoding, corrupt,
):
    """Installed offline success and integrity refusal retain truthful JSON without a traceback."""

    root, acquired = saved_cve

    if corrupt:
        (root / "evidence" / acquired.raw.reference.locator).write_bytes(b"owned changed original")

    arguments = ["inspect", str(root), "--selection", acquired.snapshot_record.evidence_id,
                 "--receipt", acquired.receipt.evidence_id]
    expectedOutput = StringIO()
    expectedStatus = 4 if corrupt else 0
    assert RunCveHttpsCommands(arguments, expectedOutput, json_output=True) == expectedStatus, (
        "The saved fixture must retain its actual successful or corrupt-original status"
    )
    before = Files(root)
    executable = shutil.which("1337")
    assert executable is not None, "Installed inspection requires the actual product console"
    environment = dict(os.environ)
    environment["PYTHONIOENCODING"] = encoding + ":strict"
    result = subprocess.run([executable, "intel", "cve", "https", *arguments, "--json"],
                            env=environment, cwd=tmp_path, capture_output=True,
                            check=False, timeout=30)
    assert result.returncode == expectedStatus and not result.stderr, (
        "Strict terminal encoding must preserve the inspection status without a traceback"
    )
    actual = json.loads(result.stdout.decode(encoding))
    assert actual == json.loads(expectedOutput.getvalue()), (
        "Installed narrow JSON must retain the entire prior UTF-8 source and custody structure"
    )

    if encoding == "utf-8":
        assert result.stdout == expectedOutput.getvalue().encode("utf-8"), (
            "Installed UTF-8 mode must preserve every pre-existing canonical output byte"
        )

    elif not corrupt:
        assert result.stdout.isascii() and b"\\u00a9" in result.stdout and (
            b"\\ud83e\\uddea" in result.stdout
        ), "ASCII JSON must losslessly escape mandatory notices and supplementary source characters"

    if corrupt:
        assert actual["status"] == "failed" and actual["failure"] == "integrity", (
            "Encoding must not turn corrupt saved evidence into a successful inspection"
        )

    assert Files(root) == before, (
        "Installed inspection must preserve all original saved custody bytes"
    )
