# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Fixed isolated installed consumer entrypoint; no setup, targets or acceptance verdict."""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import importlib.metadata
import json
import sys
from pathlib import Path
from types import ModuleType

MAX_INPUT_BYTES = 8192
MAX_SOURCE_BYTES = 1024 * 1024
SOURCE_MODULES = ("adapters/owned_content_response.py", "owned_content_response_worker.py",
    "adapters/owned_response_capture.py", "owned_response_capture.py",
    "owned_response_capture_worker.py", "owned_response_custody.py", "owned_response_workflow.py",
    "native_response_headers.py", "native_response_header_workflow.py")


def BoundedRead(path: Path, maximum: int) -> bytes:
    """Read only a finite original prefix before parsing or executing any source.

    Args:
        path: Explicit input or fixed local source file.
        maximum: Inclusive original byte ceiling.

    Returns:
        Complete original bytes only if the read stayed within the fixed ceiling.
    """

    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)

    if len(raw) > maximum:
        raise ValueError("Fixed consumer input/source exceeds its byte ceiling")

    return raw


def UniqueObject(pairs):
    """Reject duplicate JSON members at every depth, without last-key-wins selection."""

    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate fixed consumer input member")

        result[key] = value

    return result


def RejectNumber(value):
    """Refuse all floating/nonfinite values; the fixed consumer needs only integer CAS bases."""

    raise ValueError("Non-integer fixed consumer input number")


def ReadInput(path: Path) -> dict:
    """Admit one bounded closed selection/observation envelope before installed SDK imports.

    Args:
        path: Explicit absolute input path supplied to the fixed entrypoint.

    Returns:
        Exact caller selection and fresh observation owner, without defaults or SDK activity.
    """

    if not path.is_absolute():
        raise ValueError("Fixed consumer input path must be absolute")

    raw = BoundedRead(path, MAX_INPUT_BYTES)
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=UniqueObject,
        parse_float=RejectNumber, parse_constant=RejectNumber)
    pending = [(value, 1)]
    nodes = 0

    while pending:
        item, depth = pending.pop()
        nodes += 1

        if nodes > 128 or depth > 8 or type(item) not in (dict, list, str, int, bool, type(None)):
            raise ValueError("Fixed consumer input exceeds its structural bound")

        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())

        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)

        elif type(item) is str:
            item.encode("utf-8", errors="strict")

    if type(value) is not dict or set(value) != {"selection", "observations"} or (
        type(value["selection"]) is not dict or type(value["observations"]) is not str or
        not Path(value["observations"]).is_absolute()
    ):
        raise ValueError("Consumer envelope requires explicit selection and observation owner")

    return value


def Identity() -> dict:
    """Observe nine real installed module identities inside this selected isolated environment.

    Returns:
        Actual distribution, interpreter/prefix and imported paths/hashes; the parent must
        independently reconcile these observations with its original wheel/checkpoint record.
    """

    prefix = Path(sys.prefix).resolve()
    if prefix == Path(sys.base_prefix).resolve():
        raise ValueError("Installed consumer requires a distinct selected clean environment")

    result = {"distribution_version": importlib.metadata.version("1337"),
        "python": sys.executable, "prefix": str(prefix), "installed_sources": {}}
    roots = set()

    for name in SOURCE_MODULES:
        module = importlib.import_module("fuzzy1337." + name[:-3].replace("/", "."))
        path = Path(module.__file__).resolve()
        parts = tuple(name.split("/"))
        suffix = ("site-packages", "fuzzy1337", *parts)

        if not path.is_relative_to(prefix) or path.parts[-len(suffix):] != suffix:
            raise ValueError("Consumer imports must belong to the selected installed environment")

        raw = BoundedRead(path, MAX_SOURCE_BYTES)
        roots.add(path.parents[len(parts) - 1])
        result["installed_sources"][name] = {"path": str(path),
            "sha256": hashlib.sha256(raw).hexdigest()}

    if len(roots) != 1:
        raise ValueError("Consumer modules must share one original installed package root")

    return result


def Sources() -> tuple[dict, bytes]:
    """Observe this entrypoint and its only fixed reviewed sibling independently of wheel modules.

    Returns:
        Exact original helper path/hash facts and the same bounded consumer bytes to be executed.
    """

    current = Path(__file__).resolve()
    sibling = current.with_name("owned_content_response_sdk_consumer.py")
    records = {}
    consumer = b""

    for path in (current, sibling):
        raw = BoundedRead(path, MAX_SOURCE_BYTES)
        records[path.name] = {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}

        if path == sibling:
            consumer = raw

    return records, consumer


def LoadConsumer(raw: bytes) -> ModuleType:
    """Execute only the fixed bounded reviewed sibling bytes, without import-path fallback.

    Args:
        raw: Same original consumer source bytes observed by Sources.

    Returns:
        Isolated fixed helper namespace; product imports occur only inside its selected operation.
    """

    path = Path(__file__).resolve().with_name("owned_content_response_sdk_consumer.py")
    module = ModuleType("owned_content_response_sdk_consumer")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)

    return module


def Main(argv: list[str] | None = None) -> int:
    """Dispatch only identity or one explicitly opted-in installed consumer operation.

    Args:
        argv: Identity, or capture/analyze/replay + absolute input + --execute.

    Returns:
        Zero after preserving one actual canonical consumer result; unexpected failures propagate.
    """

    arguments = sys.argv[1:] if argv is None else argv

    if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
        raise ValueError("Installed consumer requires the selected -I -B interpreter invocation")

    identity_only = arguments == ["identity"]

    if not identity_only and not (len(arguments) == 3 and arguments[0] in (
        "capture", "analyze", "replay") and arguments[2] == "--execute"):
        raise ValueError("Unsupported fixed installed consumer operation")

    config = None if identity_only else ReadInput(Path(arguments[1]))
    identity = Identity()
    sources, raw = Sources()
    output = {"installed_identity": identity, "consumer_sources": sources}

    if not identity_only:
        consumer = LoadConsumer(raw)
        selection, observations = config["selection"], Path(config["observations"])

        if arguments[0] == "capture":
            summary = asyncio.run(consumer.Capture(selection, observations, enabled=True))

        elif arguments[0] == "analyze":
            summary = consumer.Analyze(selection, observations, enabled=True)

        else:
            summary = consumer.Replay(selection, observations, enabled=True)

        output.update(operation=arguments[0], summary=summary)

    sys.stdout.buffer.write(json.dumps(output, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii"))
    sys.stdout.buffer.flush()

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
