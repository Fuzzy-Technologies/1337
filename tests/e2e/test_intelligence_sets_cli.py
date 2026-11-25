# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Installed four-feed original-set preview and one durable combined candidate save."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

from fuzzy1337.adapters.contracts import JsonValue
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.intelligence import IntelligenceFeed
from fuzzy1337.model import LocalModelStore, ObjectKind
from tests.e2e.test_intelligence_cli import ImportArguments
from tests.integration.test_intelligence_acquisition_persistence import Context
from tests.intelligence_set_helpers import Arguments, Body, Files


def Console(arguments):
    """Use the real installed entry point rather than invoking a copied source handler."""

    executable = Path(sys.executable).with_name("1337.exe" if sys.platform == "win32" else "1337")
    result = subprocess.run([str(executable), "intel", *arguments, "--json"],
                            capture_output=True, text=True, timeout=30, check=False)
    assert not result.stderr, "The installed intelligence-set console leaked a traceback"
    value = json.loads(result.stdout)
    assert value["exit_code"] == result.returncode if "exit_code" in value else (
        result.returncode == 0
    ), "Installed console exit and complete JSON result disagree"

    return result.returncode, value


def test_InstalledFourFeedSetReopensThenSavesOnePreviewedObservation(tmp_path):
    """Retain four originals, remove inputs, relocate, preview and save one exact candidate."""

    model, finding = Context(tmp_path)
    originalFinding = model.Open().Objects(ObjectKind.FINDING)
    imported = []
    paths = []

    for feed in IntelligenceFeed:
        path = tmp_path / (feed.value + ".data")
        raw = Body(feed)
        path.write_bytes(raw)
        status, value = Console([*ImportArguments(model.root, path, feed),
            "--expected-sha256", hashlib.sha256(raw).hexdigest(), "--max-bytes", str(len(raw))])
        assert status == 0, "The installed existing local importer did not retain an original feed"
        record = LocalEvidenceStore(model.root / "evidence").Get(value["raw_id"])
        assert LocalEvidenceStore(model.root / "evidence").Read(record.reference) == raw, (
            "The installed existing importer changed its exact selected original"
        )
        imported.append(value)
        paths.append(path)

    moved = tmp_path / "relocated original-set workspace"
    shutil.move(model.root, moved)
    model = LocalModelStore(moved)

    for path in paths:
        path.unlink()

    arguments = Arguments("preview-set", model, finding, imported)
    before = Files(moved)
    revision = model.Open().revision
    status, previewed = Console(arguments)
    assert status == 0 and previewed["model_commit"] == "not-attempted" and (
        Files(moved) == before
    ), "Installed combined preview saved state or depended on removed caller files"
    observation = previewed["preview"]["observations"][0]
    assertions = observation["attributes"]["source_assertions"]
    assert len(assertions) == 4 and {item["record"]["feed"] for item in assertions} == {
        feed.value for feed in IntelligenceFeed
    }, "Installed candidate did not join all four independently retained source families"
    assert observation["attributes"]["unmatched_identifiers"] == ["CVE-1900-8888"], (
        "Installed combined preview lost the explicit unmatched identifier"
    )
    assert all(item["association_state"] == "candidate" and item["review"] is None
               for item in assertions), (
        "Installed preview invented applicability review or approval"
    )
    assert Console(arguments) == (0, previewed), "Identical installed preview is nondeterministic"
    arguments[0] = "apply-set"
    status, applied = Console(arguments)
    saved = model.Open()
    stored = [item for item in saved.observations if item.Reference() == observation["reference"]]
    assert status == 0 and applied["model_commit"] == "confirmed" and saved.revision == (
        revision + 1
    ) and len(stored) == 1 and saved.Objects(ObjectKind.FINDING) == originalFinding, (
        "Installed combined save changed finding triage or did not persist exactly one revision"
    )
    assert JsonValue(stored[0]) == {key: value for key, value in observation.items()
                                  if key != "reference"}, (
        "Installed apply saved a different candidate than the reviewed source-set preview"
    )
    arguments[arguments.index("--expected-revision") + 1] = str(saved.revision)
    replayBefore = Files(moved)
    status, replay = Console(arguments)
    assert status == 0 and replay["preview"]["already_applied"] and Files(moved) == replayBefore, (
        "Installed exact replay created another revision or changed original evidence bytes"
    )
    corrupted = LocalEvidenceStore(moved / "evidence").Get(imported[-1]["raw_id"])
    (moved / "evidence" / corrupted.reference.locator).write_bytes(b"corrupt")
    damaged = Files(moved)
    status, refused = Console(arguments)
    assert status == 4 and refused["model_commit"] == "not-attempted" and all(
        key not in refused for key in ("preview", "selections")
    ), "A corrupt last source produced a saved or partial installed result"
    assert Files(moved) == damaged, "Installed source corruption refusal changed owning bytes"
