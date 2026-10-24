# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Fixed installed capture/identity consumer reusing the accepted original SDK observer."""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import importlib.util
import json
import sys
from pathlib import Path

SOURCE_MODULES = ("adapters/owned_response_capture.py", "owned_response_capture.py",
    "owned_response_capture_worker.py", "owned_response_custody.py", "owned_response_workflow.py",
    "native_response_headers.py", "native_response_header_workflow.py")


def Identity() -> dict:
    """Observe actual imported installed bytes without invoking capture or an offline analysis."""

    result = {"distribution_version": importlib.metadata.version("1337"), "installed_sources": {}}

    for name in SOURCE_MODULES:
        module = importlib.import_module("fuzzy1337." + name[:-3].replace("/", "."))
        path = Path(module.__file__).resolve()
        assert path.stat().st_size <= 1024 * 1024, "Installed source exceeds its fixed ceiling"
        result["installed_sources"][name] = {"path": str(path),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    return result


def Main() -> int:
    """Dispatch only the fixed import probe or accepted original capture consumer."""

    arguments = sys.argv[1:]

    if arguments == ["identity"]:
        output = Identity()

    elif len(arguments) == 2 and arguments[0] == "capture":
        path = Path(__file__).with_name("owned_response_product_runner.py")
        spec = importlib.util.spec_from_file_location("owned_header_original_consumer", path)
        assert spec is not None and spec.loader is not None, (
            "Fixed accepted capture helper is absent"
        )
        original = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(original)
        raw = Path(arguments[1]).read_bytes()
        assert len(raw) <= 4096, "Fixed capture consumer input exceeds its finite ceiling"
        identity = Identity()
        output = original.Capture(json.loads(raw))
        module = sys.modules[original.RunOwnedResponseCapture.__module__]
        output["runtime_module"] = str(Path(module.__file__).resolve())
        output["installed_identity"] = identity

    else:
        raise ValueError("Unsupported fixed header capture consumer operation")

    sys.stdout.buffer.write(json.dumps(output, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii"))

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
