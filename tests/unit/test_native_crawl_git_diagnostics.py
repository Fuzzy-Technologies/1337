# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure original-exception diagnostic privacy and finite chain/frame contracts; no SDK execution."""

from __future__ import annotations

import errno
import json

import pytest

from tests.functional.native_crawl_git_diagnostics import OriginalGitSaveFailure


def test_OriginalCauseAndFixedOwnCodeLinesSurviveWithoutPrivateText(monkeypatch) -> None:
    """Capture original classes/errno/owned lines without consulting files, messages or locals."""

    class OwnedBusy(RuntimeError):
        """Model the exact known outer class without importing or invoking any storage owner."""

    def OwnedSave() -> None:
        """Raise one original chained failure whose private message must never be retained."""

        try:
            raise FileExistsError(errno.EEXIST, "private-path/private-token/pid-12345")

        except FileExistsError as original:
            raise OwnedBusy("private outer diagnostic") from original

    try:
        OwnedSave()

    except OwnedBusy as original:
        error = original

    def Forbidden(*args, **kwargs):
        """Prohibit fresh diagnostic filesystem I/O in this pure exception snapshot."""

        raise AssertionError("Diagnostics attempted fresh filesystem I/O")

    monkeypatch.setattr("builtins.open", Forbidden)
    result = OriginalGitSaveFailure(error, {OwnedSave.__code__: "model-save"},
                                    {OwnedBusy: "WorkspaceBusyError"})
    text = json.dumps(result)
    assert [(node["exception_class"], node["errno"], node["relation"])
        for node in result["chain"]] == [
        ("WorkspaceBusyError", None, "original"), ("FileExistsError", errno.EEXIST, "cause"),
    ], "Original class/cause and known errno must survive as closed attributed metadata."
    assert all(node["own_frames"] and all(frame["phase"] == "model-save"
        and type(frame["line"]) is int for frame in node["own_frames"])
        for node in result["chain"]), (
            "Only explicitly owned original code and observed integer lines may survive."
        )
    assert all(marker not in text for marker in ("private", "12345", "OwnedSave", __file__)), (
        "Exception messages, paths, PIDs, locals and unapproved function names must remain absent."
    )


@pytest.mark.parametrize("code", [None, True, 999999])
def test_UnknownClassAndUnsupportedErrnoStayBoundedAndUnidentified(code) -> None:
    """Unknown original values produce explicit neutral metadata without echoing private labels."""

    class PrivateError(OSError):
        """Supply an unapproved original class whose name must not become diagnostic output."""

    error = PrivateError(code, "private diagnostic")
    result = OriginalGitSaveFailure(error, {})
    node = result["chain"][0]
    assert node["exception_class"] == "other" and node["errno"] is None and (
        node["own_frames"] == []
    ), (
        "Only approved exact original classes, errno and own frames may survive."
    )
    assert "private" not in json.dumps(result).lower(), "Unknown text/class names must not leak."


def test_CyclicOriginalCauseChainStopsWithoutIdentifiers() -> None:
    """An original cause cycle remains bounded without retaining object or process identifiers."""

    first = RuntimeError("private first")
    second = OSError(errno.EIO, "private second")
    first.__cause__ = second
    second.__cause__ = first
    result = OriginalGitSaveFailure(first, {})
    assert len(result["chain"]) == 2 and result["chain_truncated_or_cyclic"] is True, (
        "Original cause cycles must stop at observed identity without infinite traversal."
    )
    assert len(json.dumps(result)) < 1024, "Original cyclic diagnostics must stay bounded."
