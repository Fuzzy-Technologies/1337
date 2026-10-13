# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Direct owned lifecycle-oracle coverage without invoking a scanner or unowned target."""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path

import pytest

from fuzzy1337 import artifact_fixture_worker as worker


def Arguments(tmp_path, policy):
    """Select only finite owned direct fixture inputs for parser/lifecycle unit tests."""

    source = tmp_path / "image.tar"
    source.write_bytes(b"owned")
    material = tmp_path / "policy.json"
    material.write_text(json.dumps(policy))

    return [
        "owned-fixture",
        "--fixture-policy",
        str(material),
        "--cache-dir",
        str(tmp_path),
        "--config=",
        "image",
        "--input",
        str(source),
        "--cache-backend",
        "memory",
        "--format",
        "json",
        "--ignorefile=",
        "--exit-code",
        "0",
        "--timeout",
        "1s",
    ]


@pytest.mark.parametrize("mode", ["success", "failure", "wait", "overflow", "mutate", "scratch"])
def test_FixedLifecycleModesContainNoDetectorClaim(tmp_path, monkeypatch, capsys, mode):
    """Reviewed closed source supports only explicit finite synthetic lifecycle outcomes."""

    policy = {"schema_version": 1, "fixture_id": "owned-artifact-lifecycle-v1", "mode": mode}
    monkeypatch.setattr(sys, "argv", Arguments(tmp_path, policy))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(worker.time, "sleep", lambda _seconds: None)
    code = worker.Main()
    captured = capsys.readouterr()

    assert code == (7 if mode == "failure" else 0), "Owned lifecycle exit code changed"
    assert "clean" not in captured.out and "Vulnerabilities" not in captured.out, (
        "Lifecycle oracle invented a real scanner verdict"
    )


@pytest.mark.parametrize(
    "policy",
    [
        {},
        {"schema_version": 2, "fixture_id": "owned", "mode": "success"},
        {
            "schema_version": 1,
            "fixture_id": "owned-artifact-lifecycle-v1",
            "mode": "arbitrary-code",
        },
        {"extra": "x" * 5000},
    ],
)
def test_UnrecognizedPolicyCannotSelectArbitraryOperations(tmp_path, monkeypatch, policy):
    """Policy data does not become a script, template or caller-selected flags."""

    monkeypatch.setattr(sys, "argv", Arguments(tmp_path, policy))

    assert worker.Main() == 7, "Unrecognized policy was executed"


def test_StandaloneEntryPointAndConfigDirectoryRemainPortable(tmp_path, monkeypatch):
    """The bundled source runs as an actual entry point without shebang or package imports."""

    policy = {"schema_version": 1, "fixture_id": "owned-artifact-lifecycle-v1", "mode": "success"}
    arguments = Arguments(tmp_path, policy)
    arguments[arguments.index("image")] = "config"
    index = arguments.index("--input")
    del arguments[index : index + 2]
    source = tmp_path / "selected"
    source.mkdir()
    (source / "owned.yaml").write_bytes(b"owned-kubernetes-document")
    arguments.append(str(source))
    monkeypatch.setattr(sys, "argv", arguments)

    with pytest.raises(SystemExit) as raised:
        runpy.run_path(str(Path(worker.__file__)), run_name="__main__")

    assert raised.value.code == 0, "Portable bundled entry point failed"


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schema_version":true,"fixture_id":"owned-artifact-lifecycle-v1","mode":"success"}',
        b'{"schema_version":1.0,"fixture_id":"owned-artifact-lifecycle-v1","mode":"success"}',
        b'{"schema_version":1,"fixture_id":"owned-artifact-lifecycle-v1","mode":"failure","mode":"success"}',
        b'{"schema_version":NaN,"fixture_id":"owned-artifact-lifecycle-v1","mode":"success"}',
        b'{"schema_version":Infinity,"fixture_id":"owned-artifact-lifecycle-v1","mode":"success"}',
        b'{"schema_version":1,"fixture_id":"owned-artifact-lifecycle-v1","mode":[]}',
        b"\xff",
    ],
    ids=[
        "boolean-version",
        "float-version",
        "duplicate-mode",
        "nan",
        "infinity",
        "mode-type",
        "utf8",
    ],
)
def test_AmbiguousJsonCannotTurnFailureIntoSuccess(tmp_path, monkeypatch, payload):
    """The reviewed wire rejects duplicate/nonfinite/version-alias data before a lifecycle mode."""

    arguments = Arguments(tmp_path, {})
    Path(arguments[2]).write_bytes(payload)
    monkeypatch.setattr(sys, "argv", arguments)

    assert worker.Main() == 7, "Malformed material became a successful worker lifecycle"

    with pytest.raises(ValueError):
        worker.ParseFixturePolicy(payload)
