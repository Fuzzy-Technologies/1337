# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned native-profile wire producer; no image decoder, genuine scanner or network activity."""

import json
import sys
from pathlib import Path


def Main():
    """Emit known original version/scan bytes for the actual first-party capture boundary."""

    arguments = sys.argv[1:]
    cache = Path(arguments[arguments.index("--cache-dir") + 1])

    if "--version" in arguments:
        print(json.dumps({"Version": "0.75.0", "VulnerabilityDB": json.loads(
            (cache / "db" / "metadata.json").read_bytes()),
            "Fixture": "owned simulated native wire; no genuine scanner"}))

        return 0

    archive = Path(arguments[arguments.index("--input") + 1]).read_bytes()

    if archive == b"owned failure fixture":
        print('{"partial":', end="")
        print("owned simulated scan failure", file=sys.stderr)

        return 7

    vulnerabilities = [] if archive == b"owned fixed fixture" else [{
        "VulnerabilityID": "CVE-2099-0001", "PkgName": "owned-lib", "InstalledVersion": "1.0",
        "PkgID": "owned-lib@1.0", "Severity": "HIGH", "FixedVersion": "2.0"}]
    print(json.dumps({"SchemaVersion": 2, "ArtifactType": "container_image",
        "Metadata": {"ImageID": "sha256:" + "a" * 64},
        "Results": [{"Type": "python-pkg", "Packages": [{"ID": "owned-lib@1.0",
            "Name": "owned-lib", "Version": "1.0",
            "Identifier": {"PURL": "pkg:pypi/owned-lib@1.0"}}],
            "Vulnerabilities": vulnerabilities}]}))
    print("owned simulated native wire; no image decode or network activity", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
