# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Four original owned intelligence formats and explicit combined interpretation selections."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from io import StringIO

from fuzzy1337.intelligence import IntelligenceFeed
from fuzzy1337.intelligence_commands import RunIntelCommands
from tests.e2e.test_intelligence_cli import Files, ImportArguments
from tests.integration.test_intelligence_acquisition_persistence import Context, FeedBody


def Run(arguments, machine=True):
    """Use the actual dispatcher without substituting the original verification or model owner."""

    output = StringIO()
    status = RunIntelCommands(arguments, output, json_output=machine)

    return status, json.loads(output.getvalue()) if machine else output.getvalue()


def Body(feed):
    """Keep source CVSS as an original explicit CNA assertion, without score recomputation."""

    raw = FeedBody(feed)

    if feed is IntelligenceFeed.CVE:
        value = json.loads(raw)
        value["containers"]["cna"]["metrics"] = [{"cvssV3_1": {
            "version": "3.1", "baseScore": 9.8,
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }}]
        raw = json.dumps(value, sort_keys=True).encode()

    return raw


def Owned(parent):
    """Acquire four genuine test-owned local files through their existing explicit import route."""

    model, finding = Context(parent)
    imported = []
    paths = []

    for feed in IntelligenceFeed:
        path = parent / (feed.value + ".data")
        raw = Body(feed)
        path.write_bytes(raw)
        status, result = Run([*ImportArguments(model.root, path, feed),
            "--expected-sha256", hashlib.sha256(raw).hexdigest(), "--max-bytes", str(len(raw))])
        assert status == 0, "Actual local fixture acquisition failed before combined interpretation"
        imported.append(result)
        paths.append(path)

    return model, finding, imported, paths


def Arguments(action, model, finding, imported):
    """Select all original roots and one explicit interpretation basis without discovery."""

    latest = max(datetime.fromisoformat(item["finished_at"]) for item in imported)
    arguments = [action, str(model.root), "--finding", finding,
        "--expected-revision", str(model.Open().revision),
        "--as-of", (latest + timedelta(seconds=1)).isoformat(),
        "--max-age-seconds", "3600", "--scope", "scope:owned", "--run", "run:source-set",
        "--identifier", "CVE-1900-9999", "--identifier", "CWE-89",
        "--identifier", "CVE-1900-8888"]

    for item in imported:
        arguments += ["--selection", item["snapshot_id"], item["receipt_id"]]

    return arguments


__all__ = ["Arguments", "Body", "Files", "Owned", "Run"]
