# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned delayed XML producer for timeout custody; this executable performs no networking."""

from __future__ import annotations

import sys
import time
from pathlib import Path


def Main() -> int:
    """Flush exact partial streams before a ready marker and await the executor's deadline.

    Returns:
        Zero only for local version observation; unexpected scan argv fails closed.
    """

    if sys.argv[1:] == ["--version"]:
        print("Nmap version 7.95-synthetic ( https://nmap.org )")

        return 0

    expected = ["--unprivileged", "-n", "-Pn", "-sT", "-p", "80,443",
                "--host-timeout", "1s", "-oX", "-", "127.0.0.1"]

    if sys.argv[1:] != expected:
        return 7

    sys.stdout.buffer.write(b'<nmaprun scanner="nmap">owned-timeout-partial\n')
    sys.stdout.buffer.flush()
    sys.stderr.buffer.write(b"Owned delayed synthetic stderr; no network activity\n")
    sys.stderr.buffer.flush()
    Path(__file__).with_suffix(".ready").write_text("partial-streams-flushed\n", encoding="utf-8")
    time.sleep(3)

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
