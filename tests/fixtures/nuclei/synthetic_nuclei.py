# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned JSONL producer for SDK integration; this program is not Nuclei."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def Main() -> int:
    """Accept only the exact finite fixture profile and emit synthetic evidence.

    Returns:
        Zero for an expected version/fixture command; nonzero for other inputs.
    """

    if sys.argv[1:] == ["-version", "-duc"]:
        print("[INF] Nuclei Engine Version: v3.4.10-synthetic")

        return 0

    root = Path.cwd()
    configuration = root / "nuclei-empty.yaml"
    template = root / "reviewed-get.yaml"
    expected = ["-u", "http://127.0.0.1:8080/", "-config", str(configuration),
                "-pt", "http", "-jsonl", "-silent", "-nc", "-omit-raw", "-omit-template",
                "-duc", "-ni", "-dr", "-no-stdin", "-nh", "-dc", "-rl", "2", "-bs", "1",
                "-c", "1", "-retries", "0", "-mhe", "1", "-timeout", "10", "-rsr",
                "1048576", "-rss", "1048576", "-t", str(template)]

    if sys.argv[1:] != expected or configuration.read_bytes() != b"{}\n":
        print("Owned fixture rejected unexpected profile", file=sys.stderr)

        return 7

    record = {"template-id": "owned-http-marker", "template-path": str(template),
              "info": {"name": "Owned synthetic HTTP marker", "severity": "info",
                       "tags": ["synthetic"]}, "type": "http",
              "host": "http://127.0.0.1:8080/", "matched-at": "http://127.0.0.1:8080/",
              "ip": "127.0.0.1", "matcher-status": True}
    print(json.dumps(record, sort_keys=True))
    print("Owned synthetic Nuclei JSONL producer; no network activity", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
