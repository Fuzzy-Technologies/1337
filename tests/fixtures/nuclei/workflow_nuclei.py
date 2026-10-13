# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned no-network Nuclei-format producer for deterministic workflow failure tests."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path


def Main() -> int:
    """Emit explicitly synthetic version/results only for the finite workflow argument shape."""

    if sys.argv[1:] == ["-version", "-duc"]:
        print("[INF] Nuclei Engine Version: v3.4.10-synthetic")

        return 0

    arguments = sys.argv[1:]

    if len(arguments) != 35:
        return 7

    target, configuration, rate, timeout = arguments[1], arguments[3], arguments[18], arguments[28]
    expected = ["-u", target, "-config", configuration, "-pt", "http", "-jsonl", "-silent", "-nc",
        "-omit-raw", "-omit-template", "-duc", "-ni", "-dr", "-no-stdin", "-nh", "-dc", "-rl",
        rate, "-bs", "1", "-c", "1", "-retries", "0", "-mhe", "1", "-timeout", timeout,
        "-rsr", "1048576", "-rss", "1048576"]
    # This producer is an argv/evidence oracle, never an implementation of a scanner.
    selected = arguments[len(expected):]

    if selected != ["-t", str(Path.cwd() / "reviewed-get.yaml")] or (
        arguments != expected + selected or Path(configuration).read_bytes() != b"{}\n"
    ):
        return 7

    root = Path.cwd()
    mode_path = root / "nuclei-workflow-mode"
    mode = mode_path.read_text(encoding="utf-8") if mode_path.exists() else "match"
    (root / "nuclei-launched").write_text("synthetic-no-network", encoding="utf-8")
    print("Owned synthetic producer; no network activity", file=sys.stderr, flush=True)

    if mode == "invalid":
        print("not-json", flush=True)

        return 0

    if mode == "empty":
        return 0

    record = {"template-id": "owned-http-marker", "template-path": selected[1],
        "info": {"name": "Owned synthetic HTTP marker", "severity": "info", "tags": ["synthetic"]},
        "type": "http", "host": target, "matched-at": target, "matcher-status": True}
    print(json.dumps(record, sort_keys=True), flush=True)

    if mode == "wait":
        time.sleep(30)

    if mode == "output-limit":
        sys.stdout.write("x" * (4 * 1024 * 1024 + 1))
        sys.stdout.flush()

    return 7 if mode == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(Main())
