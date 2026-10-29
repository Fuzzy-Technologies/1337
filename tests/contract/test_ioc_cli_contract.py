# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Closed IOC CLI grammar, independent anchor, finite budget and diagnostic contracts."""

from __future__ import annotations

import pytest

from tests.ioc_cli_helpers import Files, ImportArguments, Owned, Run


@pytest.mark.parametrize("name", ["--file", "--source-id", "--source-version", "--source-locator",
    "--license-name", "--license-locator", "--expected-sha256", "--scope", "--owner",
    "--read-consent-reference"])
def test_ImportRequiresEveryExplicitSelectionBeforeReadingOrWriting(tmp_path, name):
    """Missing input/attribution/consent cannot infer a source, byte pin or dataset."""

    root, source = Owned(tmp_path)
    arguments = ImportArguments(root, source)
    index = arguments.index(name)
    del arguments[index:index + 2]
    before = Files(root)
    status, result = Run(arguments)
    assert status == 2 and result["failure"] == "configuration", (
        "An omitted explicit IOC selection was inferred or accepted"
    )
    assert Files(root) == before, "Rejected IOC grammar wrote owning workspace/evidence"


@pytest.mark.parametrize("name,value", [("--max-bytes", "65537"), ("--max-bytes", "0"),
    ("--max-lines", "257"), ("--max-items", "-1"), ("--max-line-bytes", "513"),
    ("--max-token-bytes", "true"), ("--expected-sha256", "ABC"),
    ("--scope", ""), ("--owner", ""), ("--read-consent-reference", "")])
def test_InvalidBudgetsPinsAndConsentFailWithoutPublication(tmp_path, name, value):
    """Closed SDK ceilings and exact pins remain enforced by the product consumer."""

    root, source = Owned(tmp_path)
    arguments = ImportArguments(root, source)

    if name in arguments:
        arguments[arguments.index(name) + 1] = value

    else:
        arguments.extend((name, value))

    before = Files(root)
    status, result = Run(arguments)
    assert status == 2 and result["evidence_commit"] == "not-attempted", (
        "Invalid bounded declarations attempted IOC evidence acquisition"
    )
    assert Files(root) == before, "Invalid IOC declarations changed owning storage"


@pytest.mark.parametrize("arguments", [
    ["ioc", "inspect", "/missing", "--snapshot", "sha256:" + "a" * 64],
    ["ioc", "inspect", "/missing", "--receipt", "sha256:" + "b" * 64],
    ["ioc", "inspect", "/missing", "--snapshot", "sha256:" + "a" * 64, "--receipt",
     "sha256:" + "b" * 64, "--source-id", "secret-sentinel"],
    ["ioc", "inspect", "/missing", "--snapshot", "sha256:" + "a" * 64, "--receipt",
     "sha256:" + "b" * 64, "--read-consent-reference", "secret-sentinel"],
    ["ioc", "apply", "secret-sentinel"], ["network", "import", "secret-sentinel"],
], ids=("missing-receipt", "missing-snapshot", "source-override", "consent-override",
        "unsupported-apply", "unsupported-profile"))
def test_InspectionRequiresIndependentAnchorAndRejectsOverrides(arguments):
    """Inspection cannot infer its trusted receipt or widen the closed offline grammar."""

    status, result = Run(arguments)
    assert status == 2 and "secret-sentinel" not in str(result), (
        "IOC inspection inferred authority/metadata or reflected rejected material"
    )


def test_SuccessSummaryNeverReturnsSourceTokensPhysicalPathsOrReadReferences(tmp_path):
    """Successful machine output provides counts and opaque evidence pins, not source bodies."""

    root, source = Owned(tmp_path)
    status, result = Run(ImportArguments(root, source))
    assert status == 0 and result["candidate_count"] == 5, "Owned IOC import failed"
    rendered = str(result)
    assert all(value not in rendered for value in ("192.0.2.7", "EXAMPLE.Invalid", str(source),
        "owner:fixture", "read:owned-non-secret", "opaque.tsv")), (
        "Successful IOC summary leaked original tokens, physical paths or read references"
    )
    assert result["publisher_authentication"] == "not-assessed" and result["core_mutation"] == (
        "none"
    ), "Supplied candidates acquired a maliciousness, publisher or Core mutation claim"
