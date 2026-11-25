# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Strict saved LensQuery replay through the existing read-only shell projection."""

import json
import os
import shlex
import socket
import subprocess
from io import StringIO

import pytest

from fuzzy1337.lenses import LensQuery, ResolveLens
from fuzzy1337.model import CanonicalModelJson, ObjectKind
from fuzzy1337.shell import MAX_LENS_QUERY_BYTES, InteractiveShell, ReadLensQuery
from tests.unit.test_lenses import Model


def test_ExplicitQueryReplacesPresetForOneRenderWithoutActions(tmp_path, monkeypatch):
    """A literal case-preserving path replays the SDK query without retaining hidden filters."""

    state = Model()
    before = CanonicalModelJson(state.ToDict())
    query = LensQuery(object_kinds=(ObjectKind.ASSET,), attributes_match={"number": True},
                      key_contains="BUILD", include_observations=False)
    path = tmp_path / "Saved Query.JSON"
    path.write_bytes(CanonicalModelJson(query.ToDict()))
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    shell.BindModel(state)
    shell.onecmd("select explicit-reference")
    selected = shell.State.selected_object
    lens = ResolveLens("pentest")
    descriptor = lens.ToDict()

    def Deny(*arguments, **keywords):
        """Reject transport, process execution and foreground action dispatch during replay."""

        raise AssertionError("Read-only lens replay must not execute an action or open a socket")

    monkeypatch.setattr(socket, "socket", Deny)
    monkeypatch.setattr(subprocess, "Popen", Deny)
    monkeypatch.setattr(shell, "RunLocalCommand", Deny)

    for options in (f"--query {shlex.quote(str(path))} --json",
                    f"--json --query {shlex.quote(str(path))}"):
        shell.onecmd("view model " + options)
        actual = json.loads(output.getvalue().splitlines()[-1])
        assert actual == lens.Project(state, query), (
            "Saved replay must equal the typed SDK projection"
        )
        assert len(actual["object_references"]) == 1, (
            "Replacement must admit the excluded preset kind"
        )

    shell.onecmd(f"view model --query {shlex.quote(str(path))}")
    assert "asset: build:one" in output.getvalue(), "Human rows must use the explicit query too"
    shell.onecmd("view model --json")
    assert json.loads(output.getvalue().splitlines()[-1]) == lens.Project(state), (
        "An omitted query must restore the unchanged preset, without hidden persistent filters"
    )
    assert shell.State.selected_object == selected and shell.State.lens == "pentest", (
        "Replay must preserve operator selection and selected lens"
    )
    assert lens.ToDict() == descriptor and CanonicalModelJson(state.ToDict()) == before, (
        "Replay must preserve both canonical snapshot and immutable descriptor"
    )
    assert path.read_bytes() == CanonicalModelJson(query.ToDict()), (
        "Replay must not rewrite its input"
    )


@pytest.mark.parametrize("document", [
    {}, [], {**LensQuery().ToDict(), "script": "inert"},
    {**LensQuery().ToDict(), "object_kinds": ["unknown-kind"]},
    {**LensQuery().ToDict(), "object_kinds": ["host", "host"]},
    {**LensQuery().ToDict(), "include_observations": 1},
    {**LensQuery().ToDict(), "attributes_match": []},
    {**LensQuery().ToDict(), "key_contains": "x" * 4097},
])
def test_InvalidTypedQueryNeverFallsBackToPreset(tmp_path, document):
    """Rejected filter documents produce no projection and preserve existing presentation state."""

    path = tmp_path / "query.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    shell.BindModel(Model())
    before = shell.State
    shell.onecmd(f"view model --query {path} --json")
    assert output.getvalue().startswith("Could not open lens query:"), (
        "Invalid explicit filters must fail visibly instead of displaying a guessed preset"
    )
    assert shell.State == before, "Invalid replay must not change the selected presentation"


@pytest.mark.parametrize("query", [LensQuery(), LensQuery(object_kinds=(ObjectKind.HOST,)),
                                  LensQuery(include_observations=False)])
def test_ReplayedQueryRetainsInducedRelationAndObservationSemantics(tmp_path, query):
    """Existing query flags govern induced references without a second filtering implementation."""

    state = Model()
    path = tmp_path / "query.json"
    path.write_bytes(CanonicalModelJson(query.ToDict()))
    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    shell.BindModel(state)
    shell.onecmd(f"view model --query {path} --json")
    actual = json.loads(output.getvalue())
    assert actual == ResolveLens("pentest").Project(state, query), (
        "Replay must retain canonical induced relation and subject-bound observation semantics"
    )

    if query == LensQuery():
        assert len(actual["relation_references"]) == 1 and len(
            actual["observation_references"]
        ) == 6, "Empty kind lists must replace the preset and retain all canonical context"


@pytest.mark.parametrize("payload", [
    b"", b"{", b"\xff", b'{} {}', b'{"object_kinds":[],"object_kinds":[]}',
    json.dumps(LensQuery().ToDict()).replace('"attributes_match": {}',
        '"attributes_match": {"same": 1, "same": 2}').encode(),
    json.dumps(LensQuery().ToDict()).replace('"attributes_match": {}',
        '"attributes_match": {"number": NaN}').encode(),
    b"[" * 1500 + b"]" * 1500,
])
def test_StrictJsonRefusesAmbiguousMalformedAndUnboundedNesting(tmp_path, payload):
    """UTF-8, unique keys, finite numbers and parser depth are checked before projection."""

    path = tmp_path / "query.json"
    path.write_bytes(payload)

    with pytest.raises(ValueError):
        ReadLensQuery(path)

    assert path.read_bytes() == payload, "Refusing malformed saved JSON must preserve its bytes"


def test_QueryByteLimitIsInclusiveAndRegularFilesAreRequired(tmp_path):
    """The exact 64 KiB UTF-8 envelope passes and one extra byte or special input is refused."""

    path = tmp_path / "query.json"
    query = LensQuery(key_contains="\u00e9\u03bb")
    payload = CanonicalModelJson(query.ToDict())
    bounded = payload + b" " * (MAX_LENS_QUERY_BYTES - len(payload))
    path.write_bytes(bounded)
    assert ReadLensQuery(path) == query, "The documented byte limit must include its exact boundary"
    path.write_bytes(bounded + b" ")

    with pytest.raises(ValueError, match="65536"):
        ReadLensQuery(path)

    with pytest.raises(ValueError, match="regular"):
        ReadLensQuery(tmp_path)

    with pytest.raises(OSError):
        ReadLensQuery(tmp_path / "missing.json")


def test_QueryGrowthAfterMetadataCannotBypassTheReadLimit(tmp_path, monkeypatch):
    """A growing owned file remains byte-bounded even after an initially small size check."""

    path = tmp_path / "query.json"
    payload = CanonicalModelJson(LensQuery().ToDict())
    path.write_bytes(payload)
    originalStat = os.fstat

    def ObserveThenGrow(descriptor):
        """Return actual small-file metadata and grow the selected bytes before the read."""

        metadata = originalStat(descriptor)
        path.write_bytes(payload + b" " * MAX_LENS_QUERY_BYTES)

        return metadata

    monkeypatch.setattr(os, "fstat", ObserveThenGrow)

    with pytest.raises(ValueError, match="exceeds 65536"):
        ReadLensQuery(path)


def test_ExplicitEmptySelectionIsValidAndMissingSnapshotDoesNotReadQuery(tmp_path):
    """Zero matches are an honest projection; a file is never opened without a bound snapshot."""

    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    shell.onecmd(f"view model --query {tmp_path / 'missing'} --json")
    assert output.getvalue().strip() == "No model loaded. Use model <workspace-path>.", (
        "The shell must require an explicit model before reading the selected query file"
    )
    assert not list(tmp_path.iterdir()), (
        "A refused model view must not create query or workspace files"
    )
    output.seek(0)
    output.truncate()
    state = Model()
    query = LensQuery(key_contains="absent synthetic key")
    path = tmp_path / "empty-query.json"
    path.write_bytes(CanonicalModelJson(query.ToDict()))
    shell.BindModel(state)
    shell.onecmd(f"view model --query {path} --json")
    actual = json.loads(output.getvalue())
    assert actual == ResolveLens("pentest").Project(state, query) and not any(
        actual[field] for field in (
            "object_references", "relation_references", "observation_references"
        )
    ), "A zero-match query must retain identity and metadata without invented references"


@pytest.mark.skipif(os.name != "posix", reason="POSIX owns FIFO and local symlink semantics")
def test_SymlinkAndFifoAreRejectedWithoutReadingOrWaiting(tmp_path):
    """Special selected files cannot block replay or redirect the final query selection."""

    path = tmp_path / "query.json"
    path.write_bytes(CanonicalModelJson(LensQuery().ToDict()))
    link = tmp_path / "linked.json"
    link.symlink_to(path)
    fifo = tmp_path / "query.fifo"
    os.mkfifo(fifo)

    for selected in (link, fifo):
        with pytest.raises(ValueError, match="regular"):
            ReadLensQuery(selected)


@pytest.mark.parametrize("arguments", [
    "model --query", "model --query --json", 'model --query "unterminated', "model --query ''",
    "model --query a --query b", "model --json --json", "model --extra a",
    "context --query a", "updates --query a --json", "--query a",
])
def test_InvalidQueryOptionsDoNotSelectViewOrReadFiles(arguments):
    """Malformed or misplaced query selections fail before touching input or view state."""

    output = StringIO()
    shell = InteractiveShell(stdin=StringIO(), stdout=output)
    shell.BindModel(Model())
    before = shell.State
    shell.onecmd("view " + arguments)
    assert output.getvalue().strip() == "usage: view <name> [--query <file>] [--json]", (
        "Unsupported query arguments must yield exact usage before any projection"
    )
    assert shell.State == before, "Invalid syntax must leave the selected view unchanged"
