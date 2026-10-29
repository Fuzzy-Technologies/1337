# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Finite image-side comparison dispatch with independently owned host isolation."""

from __future__ import annotations

import asyncio
import os
import re
import time
from pathlib import Path

from .external_native_runner import MAX_FILE_BYTES, ExportBundle, StrictJson, WriteJson
from .external_nuclei_image import (
    GOVERNED_ENVIRONMENT,
    MANIFEST,
    MATERIAL,
    SOURCE,
    CurrentWheel,
    RequireImageRuntime,
)
from .external_nuclei_provisioning import IdentityBytes, InstalledSourceInventory
from .external_nuclei_runner import (
    TARGET_INDEX_DIGEST,
    TARGET_PLATFORM_DIGEST,
    TRACKS,
    VERSION,
    ExactUrl,
    ProfileDocument,
    RegularIdentity,
    RunStandalone,
    VerifyBinary,
)
from .external_nuclei_runtime import RunWhole1337

ROOT = Path("/tmp/nuclei-application")


def CaseSelection(track: str, path: str, target_instance: str, owner: str) -> dict:
    """Bind the three frozen inputs to one explicitly supplied inspected owned target identity."""

    if track not in TRACKS or re.fullmatch("[a-f0-9]{64}", target_instance) is None or (
        re.fullmatch("[a-f0-9]{32}", owner) is None
    ):
        raise ValueError("Nuclei application requires exact finite track/target/owner selections")

    return {"scanner_track": track, "path": path, "target_url": ExactUrl(path),
        "owner_token": owner, "authorization": {
            "basis": "owned-pinned-external-target-fixture",
            "authorization_reference": "lab:owned-nuclei:" + owner,
            "owner": "operator:nuclei-" + owner, "target_url": ExactUrl(path),
            "target_instance": target_instance, "image_index_digest": TARGET_INDEX_DIGEST,
            "platform_digest": TARGET_PLATFORM_DIGEST, "network_internal": True,
            "published_ports": 0}}


def RunApplication(track: str, path: str, target_instance: str, owner: str) -> dict:
    """Run one actual producer and export its complete original files without invocation rewriting.

    Args:
        track: Exact standalone or whole1337 selection; no other executable can be requested.
        path: One of the three unchanged Juice Shop case paths.
        target_instance: Full ID independently inspected by the host before launch.
        owner: Fresh host fixture ownership token, without credential or policy-grant semantics.

    Returns:
        Original producer outcome plus separately measured image wall time. Genuine prerequisite
        binding and actual target/internal-network readback belong to the host owner.
    """

    selected = CaseSelection(track, path, target_instance, owner)
    RequireImageRuntime(networked=True)

    if dict(os.environ) != GOVERNED_ENVIRONMENT:
        raise ValueError("Nuclei application requires exactly the clean PATH/LANG environment")

    identity = RegularIdentity(MANIFEST, maximum=MAX_FILE_BYTES)
    original = IdentityBytes(MANIFEST, identity, maximum=MAX_FILE_BYTES)
    manifest = StrictJson(original)
    installed = InstalledSourceInventory(manifest["source_revision"], CurrentWheel(), SOURCE)

    if installed != manifest["installed"]:
        raise ValueError("Nuclei application installed source changed after image preparation")

    executable = MATERIAL / "nuclei"
    template = MATERIAL / "prometheus-exposition.yaml"
    configuration = MATERIAL / "operator-config.yaml"
    expected = manifest["material"]["executable"]["sha256"]
    VerifyBinary(executable, expected, VERSION)
    ProfileDocument(template, configuration)
    ROOT.mkdir(mode=0o700)
    (ROOT / "image-provisioning.json").write_bytes(original)
    WriteJson(ROOT / "case-selection.json", selected)
    started = time.monotonic()
    previous = Path.cwd()
    outcome = {"status": "prerequisite-failed", "exit_code": None,
        "duration_seconds": 0.0, "target_url": selected["target_url"], "findings": [],
        "reason": "Application producer did not establish an observed invocation"}

    try:
        # Parent version probes may initialize local files; this is a private cwd, not HOME.
        os.chdir(ROOT)
        common = (ROOT / "scan", path, executable, template, configuration, expected,
                  VERSION, selected["authorization"])
        outcome = RunStandalone(*common) if track == "external-nuclei" else (
            RunWhole1337(*common, manifest["source_revision"], CurrentWheel()))

    except BaseException as error:
        invoked = (ROOT / "scan/invocation.json").is_file()
        outcome.update(status="cancelled" if isinstance(error, (
            KeyboardInterrupt, asyncio.CancelledError)) and invoked else (
            "failed" if invoked else "prerequisite-failed"),
            reason="Application producer refused; retained originals receive no score")
        WriteJson(ROOT / "failure.json", {"exception_type": type(error).__name__,
            "invocation_recorded": invoked, "scanner_completion_claimed": False})

        if (ROOT / "scan/process.json").is_file():
            process = StrictJson((ROOT / "scan/process.json").read_bytes())
            outcome.update(exit_code=process["exit_code"],
                           duration_seconds=process["duration_seconds"])

    finally:
        os.chdir(previous)

    outcome["image_wall_seconds"] = time.monotonic() - started
    WriteJson(ROOT / "outcome.json", outcome)

    return outcome


def ExportApplication(track: str, path: str, target_instance: str, owner: str) -> int:
    """Print one bounded original-byte bundle; failed or cancelled execution remains nonzero."""

    outcome = RunApplication(track, path, target_instance, owner)
    print(ExportBundle(ROOT, outcome))

    return 0 if outcome["status"] in {"completed", "unproven"} else (
        130 if outcome["status"] == "cancelled" else 4)
