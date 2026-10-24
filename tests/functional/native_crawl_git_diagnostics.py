# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bounded original Git Save exception metadata; no diagnostic filesystem or message access."""

from __future__ import annotations

import errno
from types import CodeType

KNOWN_CLASSES = {
    OSError: "OSError", FileExistsError: "FileExistsError", FileNotFoundError: "FileNotFoundError",
    PermissionError: "PermissionError", NotADirectoryError: "NotADirectoryError",
    IsADirectoryError: "IsADirectoryError", ValueError: "ValueError", TypeError: "TypeError",
    RuntimeError: "RuntimeError", RecursionError: "RecursionError", MemoryError: "MemoryError",
}
EXTRA_CLASS_NAMES = frozenset({"WorkspaceBusyError", "WorkspaceConflictError"})
OWN_PHASES = frozenset({"observe-git-save", "model-save", "model-open", "model-validate-paths",
                        "model-write-state", "sync-storage-directory"})
MAX_CHAIN = 4
MAX_TRACEBACK = 16
MAX_OWN_FRAMES = 4


def OriginalGitSaveFailure(
    error: BaseException, own_codes: dict[CodeType, str],
    extra_classes: dict[type[BaseException], str] | None = None,
) -> dict[str, object]:
    """Read original exception/code/traceback facts without text, locals or fresh I/O."""

    known = dict(KNOWN_CLASSES)

    for kind, label in ({} if extra_classes is None else extra_classes).items():
        if label in EXTRA_CLASS_NAMES:
            known[kind] = label

    chain = []
    seen: list[BaseException] = []
    current: BaseException | None = error
    relation = "original"
    own_count = 0

    while current is not None and len(chain) < MAX_CHAIN:
        if any(previous is current for previous in seen):
            break

        seen.append(current)
        code = current.errno if isinstance(current, OSError) else None

        if type(code) is not int or code not in errno.errorcode:
            code = None

        frames = []
        trace = current.__traceback__
        walked = 0

        while trace is not None and walked < MAX_TRACEBACK:
            phase = own_codes.get(trace.tb_frame.f_code)
            line = trace.tb_lineno

            if phase in OWN_PHASES and own_count < MAX_OWN_FRAMES and (
                type(line) is int and 1 <= line <= 1000000
            ):
                frames.append({"phase": phase, "line": line})
                own_count += 1

            walked += 1
            trace = trace.tb_next

        chain.append({"relation": relation, "exception_class": known.get(type(current), "other"),
            "errno": code, "own_frames": frames, "traceback_truncated": trace is not None,
            "context_suppressed": current.__suppress_context__ is True})
        cause = current.__cause__
        context = current.__context__

        if isinstance(cause, BaseException):
            current, relation = cause, "cause"

        elif isinstance(context, BaseException):
            current, relation = context, "context"

        else:
            current = None

    return {"phase": "git-model-save", "chain": chain,
        "chain_truncated_or_cyclic": current is not None,
        "own_frame_limit_reached": own_count == MAX_OWN_FRAMES}
