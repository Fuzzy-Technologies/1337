# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned XML producer for adapter integration; this executable is not Nmap."""

from __future__ import annotations

import sys


def Main() -> int:
    """Emit an explicitly synthetic version or deterministic loopback-only XML.

    Returns:
        Zero for the expected finite test command; nonzero for every other input.
    """

    if sys.argv[1:] == ["--version"]:
        print("Nmap version 7.95-synthetic ( https://nmap.org )")

        return 0

    expected = ["--unprivileged", "-n", "-Pn", "-sT", "-p", "80,443",
                "--host-timeout", "10s", "-oX", "-", "127.0.0.1"]

    if sys.argv[1:] != expected:
        print("Synthetic fixture rejected unexpected arguments", file=sys.stderr)

        return 7

    sys.stdout.write('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" version="7.95-synthetic" xmloutputversion="1.05">
<host><status state="up" reason="user-set"/><address addr="127.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open" reason="synthetic"/>
<service name="http" product="Owned fixture" method="probed" conf="10"/></port>
<port protocol="tcp" portid="443"><state state="closed" reason="synthetic"/></port></ports>
</host><runstats><finished exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
''')
    sys.stderr.write("Owned synthetic Nmap XML producer; no network activity\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
