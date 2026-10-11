# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Owned Trivy-compatible JSON producer; never scans an image or contacts a service."""

import json
import sys


def Main():
    """Accept the adapter's fixed version or image argv and emit explicit synthetic evidence."""

    args = sys.argv[1:]

    if "--version" in args:
        print(json.dumps({"Version": "0.75.0-synthetic", "VulnerabilityDB": {
            "Version": 2, "UpdatedAt": "2026-10-01T00:00:00Z",
            "NextUpdate": "2026-10-02T00:00:00Z", "DownloadedAt": "2026-10-01T01:00:00Z"}}))

        return 0

    if args[:1] != ["--cache-dir"] or "image" not in args or any(
        flag not in args for flag in ("--input", "--disable-telemetry", "--offline-scan",
            "--skip-db-update",
            "--skip-java-db-update", "--skip-check-update", "--skip-version-check",
            "--skip-vex-repo-update", "--ignorefile=", "--no-progress", "--list-all-pkgs")
    ) or args[args.index("--scanners") + 1] != "vuln":
        return 7

    print(json.dumps({"SchemaVersion": 2, "ArtifactType": "container_image",
        "ArtifactName": args[args.index("--input") + 1], "Results": [{
            "Target": "owned synthetic alpine fixture", "Type": "alpine",
            "Packages": [{"ID": "owned-lib@1.0", "Name": "owned-lib", "Version": "1.0"}],
            "Vulnerabilities": [{"VulnerabilityID": "CVE-2099-0001", "PkgName": "owned-lib",
                "InstalledVersion": "1.0", "FixedVersion": "2.0", "Severity": "HIGH"}]}]}))
    print("owned synthetic Trivy fixture; no image decode or network activity", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
