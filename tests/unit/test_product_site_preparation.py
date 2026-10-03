# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify private build state cannot enter the staged public product site."""

import ast
import shutil
import sys
from pathlib import Path

import pytest

from tools.prepare_product_site import PRODUCT_SOURCES, Main, PrepareProductSite


def ProductSource(root: Path) -> Path:
    """Create a complete source allowlist with distinguishable file contents."""

    for name in PRODUCT_SOURCES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(name, encoding="utf-8")

    return root


def test_OnlyReviewedSourcesAreCopied(tmp_path: Path) -> None:
    """Prove runtime, wheel, evidence, and unreviewed files remain outside output."""

    root = ProductSource(tmp_path / "root")

    for name in ("dist/package.whl", "src/private.py", "coverage/report.json", "new-page.md"):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("private", encoding="utf-8")

    output = root / "_build/product-source"
    PrepareProductSite(root, output)
    actual = {path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file()}
    assert actual == set(PRODUCT_SOURCES), "Unreviewed source escaped the product allowlist"

    for name in PRODUCT_SOURCES:
        assert (output / name).read_bytes() == (root / name).read_bytes(), (
            f"Product source bytes changed while staging {name}"
        )


def test_MissingSourceDoesNotCreatePartialOutput(tmp_path: Path) -> None:
    """Reject incomplete input before creating a public staging directory."""

    root = ProductSource(tmp_path / "root")
    (root / "sitemap.xml").unlink()
    output = tmp_path / "output"

    with pytest.raises(ValueError, match="Missing reviewed"):
        PrepareProductSite(root, output)

    assert not output.exists(), "Incomplete input left public staging state"


def test_ExistingOutputIsPreserved(tmp_path: Path) -> None:
    """Reject reusing an old artifact instead of covering a failed fresh build."""

    root = ProductSource(tmp_path / "root")
    output = tmp_path / "output"
    output.mkdir()
    marker = output / "prior"
    marker.write_text("retain", encoding="utf-8")

    with pytest.raises(FileExistsError):
        PrepareProductSite(root, output)

    assert marker.read_text() == "retain", "Existing artifact was overwritten"


def test_SourceSymlinkIsRejected(tmp_path: Path) -> None:
    """Reject symbolic sources rather than following them to unrelated content."""

    root = ProductSource(tmp_path / "root")
    source = root / "index.md"
    source.unlink()

    try:
        source.symlink_to(root / "llms.txt")

    except OSError:
        pytest.skip("The platform does not permit test symlinks")

    with pytest.raises(ValueError, match="symbolic"):
        PrepareProductSite(root, tmp_path / "output")


def test_AllowlistMatchesReviewedSiteBoundary() -> None:
    """Keep the executable staging allowlist tied to the existing site contract."""

    source = Path(__file__).with_name("test_pages_source.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    expected = next(
        ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "SITE_SOURCE_FILES"
                for target in node.targets)
    )
    assert set(PRODUCT_SOURCES) == expected, "Public source allowlists diverged"


def test_StagingCliProducesOnlyFreshReviewedOutput(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise the real CLI against a complete controlled repository fixture."""

    root = ProductSource(tmp_path / "root")
    output = tmp_path / "output"
    monkeypatch.setattr(sys, "argv", ["stage", "--root", str(root), "--output", str(output)])
    assert Main() == 0, "A valid product staging invocation failed"
    assert (output / "index.md").read_text() == "index.md", "CLI failed to stage reviewed source"


def test_CopyFailureRollsBackFreshOutput(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed copy must not leave an apparently publishable partial product source."""

    root = ProductSource(tmp_path / "root")
    output = tmp_path / "output"

    def FailCopy(*args: object, **kwargs: object) -> None:
        """Simulate failure at the file-system copy boundary."""

        raise OSError("controlled copy failure")

    monkeypatch.setattr(shutil, "copyfile", FailCopy)

    with pytest.raises(OSError, match="controlled copy failure"):
        PrepareProductSite(root, output)

    assert not output.exists(), "Failed staging retained partial public output"


def test_OutputCannotCoverSourceTree(tmp_path: Path) -> None:
    """Existing source roots cannot become disposable output directories."""

    root = ProductSource(tmp_path / "root")

    with pytest.raises(FileExistsError):
        PrepareProductSite(root, root)


@pytest.mark.parametrize("linked_part", ("source-root", "output-parent"))
def test_LinkedBoundariesAreRejected(tmp_path: Path, linked_part: str) -> None:
    """Reject symbolic repository and destination parents before any file is copied."""

    root = ProductSource(tmp_path / "root")
    linked = tmp_path / "linked"

    try:
        linked.symlink_to(root, target_is_directory=True)

    except OSError:
        pytest.skip("The platform does not permit directory symlinks")

    with pytest.raises(ValueError, match="symbolic"):
        if linked_part == "source-root":
            PrepareProductSite(linked, tmp_path / "output")

        else:
            PrepareProductSite(root, linked / "new-output")
