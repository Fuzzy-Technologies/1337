# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Stage only reviewed Jekyll sources, excluding package and private build state."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

PRODUCT_SOURCES = (
    "_config.yml", "_layouts/default.html", "index.md", "llms.txt",
    "ru/index.md", "sitemap.xml", "static/style.css", "static/main.js",
    "static/images/1337-logo.png", "zh-cn/index.md",
)


def PrepareProductSite(root: Path, destination: Path) -> None:
    """Copy the explicit product-site allowlist to an absent directory.

    Args:
        root: Repository containing the reviewed product sources.
        destination: Disposable staging directory; existing output is rejected.

    Raises:
        ValueError: Input is missing, symbolic, or output overlaps source files.
        FileExistsError: Destination already exists.
        OSError: Staging fails; partially copied output is removed.
    """

    if root.is_symlink():
        raise ValueError("Product source root must not be a symbolic link")

    root = root.resolve(strict=True)
    destination = destination.absolute()

    if destination.is_symlink() or destination.exists():
        raise FileExistsError(f"Product staging output already exists: {destination}")

    if any(parent.is_symlink() for parent in destination.parents):
        raise ValueError("Product output parent must not be a symbolic link")

    for name in PRODUCT_SOURCES:
        source = root / name

        if any(part.is_symlink() for part in (source, *source.parents)):
            raise ValueError(f"Product source contains a symbolic link: {name}")

        if not source.is_file():
            raise ValueError(f"Missing reviewed product source: {name}")

        if source == destination or destination in source.parents:
            raise ValueError(f"Product output overlaps reviewed source: {name}")

    destination.mkdir(parents=True, exist_ok=False)

    try:
        for name in PRODUCT_SOURCES:
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / name, target)

    except BaseException:
        shutil.rmtree(destination)
        raise


def Main() -> int:
    """Stage reviewed product sources from command-line paths.

    Returns:
        Zero after the staging directory has been populated successfully.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    PrepareProductSite(arguments.root, arguments.output)

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
