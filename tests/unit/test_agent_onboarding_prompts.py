# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Bind standalone onboarding translations to exact canonical source and prompt commands."""

import hashlib
import re
import tomllib
from pathlib import Path

from tools.locale_documentation import CanonicalHash, CanonicalUnit

ROOT = Path(__file__).resolve().parents[2]
PROMPTS = ROOT / "docs/i18n/agent-onboarding"


def test_OnboardingPromptProvenanceAndMachineInterfaceParity() -> None:
    """Fail on stale source/content digests, omitted locales or translated CLI identifiers."""

    manifest = tomllib.loads((PROMPTS / "units.toml").read_text(encoding="utf-8"))
    assert manifest["schemaVersion"] == 1 and len(manifest["units"]) == 1, (
        'The standalone prompt manifest must retain schema one and exactly one canonical source '
        'unit'
    )
    unit = manifest["units"][0]
    source = ROOT / unit["sourcePath"]
    assert unit["sourceHash"] == CanonicalHash(CanonicalUnit(
        unit["id"], unit["kind"], unit["sourcePath"], "", source.read_text(encoding="utf-8"),
    )), (
        'The prompt source digest must bind the exact canonical English content and unit identity'
    )
    assert set(unit["translations"]) == {"ru", "zh-cn"}, (
        'Both Russian and Simplified Chinese prompt drafts must remain explicitly inventoried'
    )
    paths = [source]

    for translation in unit["translations"].values():
        path = ROOT / translation["path"]
        digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        assert translation["contentHash"] == digest, (
            'Each translated prompt digest must match its exact retained UTF-8 bytes'
        )
        assert translation["state"] == "draft", "No translation approval is invented by this recipe"
        paths.append(path)

    for path in paths:
        blocks = re.findall(r"```text\n(.*?)\n```", path.read_text(encoding="utf-8"), re.DOTALL)
        assert len(blocks) == 1, f"{path.name} must provide one copyable task prompt"

        for token in ("docs/AGENT_QUICKSTART.md", "--approve-safe-http", "--json",
                      "scan_completeness: not-assessed"):
            assert token in blocks[0], f"{path.name} lost the canonical machine interface {token}"
