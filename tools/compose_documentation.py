# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Compose immutable product and localized API documentation artifacts safely."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from collections.abc import Sequence
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

LOCALES = ("en", "ru", "zh-cn")
MANIFEST_NAME = "documentation-provenance.json"
SITE_ORIGIN = "https://fuzzy-technologies.github.io"
PUBLIC_EXTENSIONS = {
    ".html", ".htm", ".css", ".js", ".mjs", ".json", ".xml", ".txt",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".ico",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".webmanifest",
}
PRIVATE_COMPONENTS = {
    "src", "tests", "tools", "contracts", "prompts", "evidence", "coverage",
    "performance", "dist", "build", "credentials", "secrets",
}


class DocumentationError(ValueError):
    """Report a failed composition or local-link invariant."""


class HtmlReferences(HTMLParser):
    """Collect HTML targets and references without importing application code."""

    def __init__(self) -> None:
        """Initialize one page's deterministic reference inventory."""

        super().__init__(convert_charrefs=True)
        self.anchors: set[str] = set()
        self.references: list[str] = []
        self.has_base = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Collect IDs, named anchors, and href/src references from HTML.

        Args:
            tag: Parsed HTML element name supplied by HTMLParser.
            attrs: Decoded attributes and optional values supplied by HTMLParser.
        """

        for name, value in attrs:
            if value is None:
                continue

            if name == "id" or (tag == "a" and name == "name"):
                self.anchors.add(value)

            if name in {"href", "src"}:
                self.references.append(value)

            if tag == "base" and name == "href":
                self.has_base = True

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Collect references from self-closing HTML elements too.

        Args:
            tag: Parsed self-closing element name supplied by HTMLParser.
            attrs: Decoded attributes and optional values supplied by HTMLParser.
        """

        self.handle_starttag(tag, attrs)


def SafePath(path: Path) -> Path:
    """Reject lexical traversal and symlink ancestors before reading a tree.

    Args:
        path: Candidate filesystem root or destination with no traversal components.

    Returns:
        Absolute lexical path after checking existing ancestors for symbolic links.

    Raises:
        DocumentationError: Traversal or a symlink ancestor violates the path boundary.
    """

    if ".." in path.parts:
        raise DocumentationError(f"Path traversal is prohibited: {path}")

    absolute = path.absolute()

    for ancestor in (*reversed(absolute.parents), absolute):
        if ancestor.is_symlink():
            raise DocumentationError(f"Symlink paths are prohibited: {ancestor}")

    return absolute


def Inventory(root: Path) -> dict[str, str]:
    """Hash regular files in a symlink-free directory tree in lexical order.

    Args:
        root: Existing artifact directory whose contents must be regular files/directories.

    Returns:
        Sorted POSIX-relative file paths mapped to their SHA-256 digests.

    Raises:
        DocumentationError: The root is absent or contains symlinks/non-regular entries.
        OSError: An artifact file cannot be read.
    """

    root = SafePath(root)

    if not root.is_dir():
        raise DocumentationError(f"Artifact directory does not exist: {root}")

    inventory = {}

    for directory, directories, files in os.walk(root, followlinks=False):
        for name in sorted((*directories, *files)):
            path = Path(directory) / name

            if path.is_symlink():
                raise DocumentationError(f"Artifact contains a symlink: {path}")

            if not path.is_dir() and not path.is_file():
                raise DocumentationError(f"Artifact contains a non-regular entry: {path}")

        for name in sorted(files):
            path = Path(directory) / name
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            inventory[path.relative_to(root).as_posix()] = digest

    return dict(sorted(inventory.items()))


def ValidateArtifact(root: Path) -> dict[str, str]:
    """Allow web artifacts while rejecting source, package, and private-state paths.

    Args:
        root: Existing directory containing the candidate public website tree.

    Returns:
        Validated relative-file digest inventory, including permitted license assets.

    Raises:
        DocumentationError: Paths, entry types, or extensions violate the publication list.
        OSError: An artifact file cannot be read.
    """

    inventory = Inventory(root)

    for relative in inventory:
        path = PurePosixPath(relative)
        parts = path.parts

        if relative in {".nojekyll", "CNAME"}:
            continue

        if any(part.startswith(".") or part.lower() in PRIVATE_COMPONENTS for part in parts):
            raise DocumentationError(f"Private artifact path is prohibited: {relative}")

        if (
            path.suffix.lower() not in PUBLIC_EXTENSIONS
            and path.parts[-3:] != ("assets", "mathjax", "LICENSE")
        ):
            raise DocumentationError(f"Unsupported public artifact file type: {relative}")

    return inventory


def BasePath(base_path: str) -> str:
    """Normalize a Pages mount while rejecting ambiguous path syntax.

    Args:
        base_path: Absolute project mount or slash for an origin-root site.

    Returns:
        Mount without a trailing slash; the origin root is represented by an empty string.

    Raises:
        DocumentationError: The mount contains traversal, empty segments, or URL ambiguity.
    """

    if base_path == "/":
        return ""

    if (not base_path.startswith("/") or any(
        part in {".", "..", ""} for part in base_path.strip("/").split("/")
    ) or any(character in base_path for character in "\\?#%")):
        raise DocumentationError(f"Invalid Pages base path: {base_path}")

    return base_path.rstrip("/")


def LinkTarget(root: Path, page: Path, reference: str, base_path: str) -> tuple[Path, str] | None:
    """Resolve an internal URL without allowing it to escape the Pages mount.

    Args:
        root: Validated artifact directory used as the local resolution boundary.
        page: Current HTML path beneath root, for relative links and same-page fragments.
        reference: href/src value whose scheme, target, and escapes must be validated.
        base_path: Normalized project mount without a trailing slash.

    Returns:
        Internal destination and decoded fragment, or None for an excluded external URL.

    Raises:
        DocumentationError: URL syntax, traversal, scheme, mount, or destination is invalid.
        UnicodeError: A percent-encoded path cannot be decoded as UTF-8.
    """

    try:
        parsed = urlsplit(reference.strip())

    except ValueError as error:
        raise DocumentationError(f"Invalid URL in {page}: {reference}") from error

    if parsed.scheme and parsed.scheme not in {"http", "https", "mailto", "tel", "data"}:
        raise DocumentationError(f"Unsupported URL scheme in {page}: {reference}")

    if parsed.netloc or parsed.scheme in {"http", "https"}:
        canonical_host = urlsplit(SITE_ORIGIN).netloc
        is_local = parsed.netloc.lower() == canonical_host and (
            not base_path or parsed.path == base_path or parsed.path.startswith(base_path + "/")
        )

        if not is_local:
            return None

    elif parsed.scheme in {"mailto", "tel", "data"}:
        return None

    if re.search(r"%(?![0-9A-Fa-f]{2})", parsed.path + parsed.fragment):
        raise DocumentationError(f"Malformed percent escape in {page}: {reference}")

    url_path = unquote(parsed.path, errors="strict")

    if "\\" in url_path or "\x00" in url_path:
        raise DocumentationError(f"Invalid URL path in {page}: {reference}")

    if url_path.startswith("/"):
        if base_path and url_path != base_path and not url_path.startswith(base_path + "/"):
            raise DocumentationError(f"Link escapes Pages base path in {page}: {reference}")

        parts = PurePosixPath(url_path[len(base_path):].lstrip("/")).parts

    elif not url_path:
        return page, unquote(parsed.fragment)

    else:
        parts = (*page.parent.relative_to(root).parts, *PurePosixPath(url_path).parts)

    normalized: list[str] = []

    for part in parts:
        if part == "..":
            if not normalized:
                raise DocumentationError(f"Link traverses outside artifact in {page}: {reference}")

            normalized.pop()

        elif part != ".":
            normalized.append(part)

    target = root.joinpath(*normalized)

    if target.is_dir():
        target /= "index.html"

    if not target.is_file():
        raise DocumentationError(f"Missing link target in {page}: {reference}")

    return target, unquote(parsed.fragment)


def ValidateLinks(site_root: Path, base_path: str = "/1337") -> dict[str, int]:
    """Check local href/src destinations and HTML anchors without network access.

    Args:
        site_root: Composed directory to validate.
        base_path: Absolute GitHub Pages project mount.

    Returns:
        Counts of HTML pages, internal references, and excluded external references.

    Raises:
        DocumentationError: A tree, destination, anchor, or mount invariant fails.
    """

    root = SafePath(site_root)
    inventory = ValidateArtifact(root)
    base_path = BasePath(base_path)
    pages: dict[Path, HtmlReferences] = {}

    for relative in inventory:
        if Path(relative).suffix.lower() not in {".html", ".htm"}:
            continue

        page = root / relative
        parsed = HtmlReferences()
        parsed.feed(page.read_text(encoding="utf-8"))

        if parsed.has_base:
            raise DocumentationError(f"HTML base elements are unsupported: {relative}")

        pages[page] = parsed

    counts = {"html_pages": len(pages), "internal_references": 0, "external_references": 0}

    for page, parsed in pages.items():
        for reference in parsed.references:
            target = LinkTarget(root, page, reference, base_path)

            if target is None:
                counts["external_references"] += 1
                continue

            target_path, fragment = target

            if fragment and target_path in pages and fragment not in pages[target_path].anchors:
                raise DocumentationError(f"Missing HTML anchor in {page}: {reference}")

            counts["internal_references"] += 1

    return counts


def ComposeDocumentation(
    product_site: Path,
    api_root: Path,
    output: Path,
    revision: str,
    base_path: str = "/1337",
) -> dict[str, object]:
    """Build and validate a complete artifact without replacing existing output.

    Args:
        product_site: Existing Jekyll artifact with an index.html entry point.
        api_root: Directory containing en, ru, and zh-cn API artifacts.
        output: Absent destination whose parent directory already exists.
        revision: Full Git commit identifier for publication traceability.
        base_path: Absolute GitHub Pages project mount.

    Returns:
        Deterministic provenance including source inventories and artifact identity.

    Raises:
        DocumentationError: An input, collision, URL, or publication invariant fails.
        OSError: A filesystem failure prevents publication; owned partial output is removed.
    """

    product_site, api_root, output = map(SafePath, (product_site, api_root, output))
    roots = (product_site, api_root, output)

    for index, first in enumerate(roots):
        for second in roots[index + 1:]:
            if first == second or first in second.parents or second in first.parents:
                raise DocumentationError(f"Artifact paths overlap: {first} and {second}")

    if output.exists():
        raise DocumentationError(f"Output already exists; refusing replacement: {output}")

    if not output.parent.is_dir():
        raise DocumentationError(f"Output parent directory does not exist: {output.parent}")

    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision):
        raise DocumentationError("Revision must be a full lowercase Git commit identifier")

    base_path = BasePath(base_path)
    product_inventory = Inventory(product_site)
    api_inventory = Inventory(api_root)

    if "index.html" not in product_inventory:
        raise DocumentationError("Product artifact is missing index.html")

    if (product_site / MANIFEST_NAME).exists() or (product_site / "api/latest").exists():
        raise DocumentationError("Product artifact collides with reserved composition paths")

    if (product_site / "api").exists() and not (product_site / "api").is_dir():
        raise DocumentationError("Product artifact contains a file at the API mount")

    unexpected = {path.name for path in api_root.iterdir()} - set(LOCALES)

    if unexpected:
        raise DocumentationError(f"Unexpected API locale entries: {sorted(unexpected)}")

    for locale in LOCALES:
        if f"{locale}/index.html" not in api_inventory:
            raise DocumentationError(f"API artifact is missing {locale}/index.html")

    with tempfile.TemporaryDirectory(
        prefix=".documentation-compose-", dir=output.parent
    ) as temporary:
        staging = Path(temporary) / "artifact"
        shutil.copytree(product_site, staging, symlinks=True)

        for locale in LOCALES:
            shutil.copytree(api_root / locale, staging / "api/latest" / locale, symlinks=True)

        link_counts = ValidateLinks(staging, base_path or "/")
        files = Inventory(staging)
        expected_files = {**product_inventory, **{
            f"api/latest/{path}": digest for path, digest in api_inventory.items()
        }}

        if files != dict(sorted(expected_files.items())):
            raise DocumentationError("Source artifacts changed while being copied")

        identity_source = json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
        manifest: dict[str, object] = {
            "schema_version": 1,
            "revision": revision,
            "base_path": base_path or "/",
            "api_mount": "api/latest",
            "locales": list(LOCALES),
            "sources": {"product": product_inventory, "api": api_inventory},
            "files": files,
            "artifact_sha256": hashlib.sha256(identity_source).hexdigest(),
            "validation": link_counts,
        }
        (staging / MANIFEST_NAME).write_text(
            json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        # Exclusive reservation prevents overwriting a destination created during validation.
        output.mkdir()

        try:
            for child in sorted(staging.iterdir()):
                child.rename(output / child.name)

        except BaseException:
            shutil.rmtree(output)
            raise

    return manifest


def Main(argv: Sequence[str] | None = None) -> int:
    """Compose or validate an artifact and print a machine-readable result.

    Args:
        argv: Explicit CLI tokens, or None to consume the process arguments.

    Returns:
        Zero after successful JSON output, or one after a reported validation failure.

    Raises:
        SystemExit: Help is requested or conflicting/missing CLI arguments are rejected.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product-site", type=Path)
    parser.add_argument("--api-root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--revision")
    parser.add_argument("--base-path", default="/1337")
    parser.add_argument("--validate-only", type=Path)
    arguments = parser.parse_args(argv)

    if arguments.validate_only and any(
        (arguments.product_site, arguments.api_root, arguments.output, arguments.revision)
    ):
        parser.error("--validate-only cannot be combined with composition arguments")

    if not arguments.validate_only and not all(
        (arguments.product_site, arguments.api_root, arguments.output, arguments.revision)
    ):
        parser.error("composition requires --product-site, --api-root, --output, and --revision")

    result: dict[str, object]

    try:
        if arguments.validate_only:
            result = dict(ValidateLinks(arguments.validate_only, arguments.base_path))

        else:
            result = ComposeDocumentation(
                arguments.product_site, arguments.api_root, arguments.output,
                arguments.revision, arguments.base_path,
            )

    except (DocumentationError, OSError, UnicodeError) as error:
        print(f"Documentation validation failed: {error}", file=sys.stderr)

        return 1

    print(json.dumps(result, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
