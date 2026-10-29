# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Compose immutable product and localized API documentation artifacts safely."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from collections.abc import Sequence
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

LOCALES = ("en", "ru", "zh-cn")
MANIFEST_NAME = "documentation-provenance.json"
VERSION_PROVENANCE = "api-version-provenance.json"
MAX_API_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_API_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_API_ARCHIVE_FILES = 20000
SITE_ORIGIN = "https://fuzzy-technologies.github.io"
RELEASE_API = "https://api.github.com/repos/Fuzzy-Technologies/1337"
RELEASE_DOWNLOAD = "https://github.com/Fuzzy-Technologies/1337/releases/download/v0.3.0/"
RELEASE_ARCHIVE = "1337-0.3.0-api-docs.tar.gz"
RELEASE_TRANSFER = "1337-0.3.0-api-docs.manifest.json"
MAX_RELEASE_METADATA_BYTES = 1024 * 1024
MAX_RELEASE_TRANSFER_BYTES = 16384
MAX_RELEASE_CONTROL_BYTES = 16384
RELEASE_CALL_SECONDS = 30.0
RELEASE_ACQUISITION_SECONDS = 120.0
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


class NoReleaseRedirect(urllib.request.HTTPRedirectHandler):
    """Withhold automatic redirects so the parent validates source and credential boundaries."""

    def RedirectRequest(self, request: urllib.request.Request, response: object,
                        code: int, message: str, headers: object, new_url: str) -> None:
        """Withhold automatic requests until the parent validates each closed asset hop.

        Args:
            request: Original request whose authority must not be forwarded automatically.
            response: Original response stream retained by urllib.
            code: Observed redirect status.
            message: Original status description, unused for authority.
            headers: Original response headers inspected separately by the parent.
            new_url: Proposed destination requiring independent source validation.

        Returns:
            None, preventing urllib from following the proposed redirect.
        """

        return None

    # urllib owns this callback name; implementation follows repository naming.
    redirect_request = RedirectRequest


def ReleaseSource(kind: str, url: str) -> int:
    """Admit only finite first-0.3 GitHub metadata and the two exact public release assets.

    Args:
        kind: Fixed metadata, archive or manifest role.
        url: Original API/asset URL or one explicitly selected official CDN redirect.

    Returns:
        Inclusive role body limit; arbitrary hosts, paths and roles are refused.
    """

    if type(url) is not str or len(url) > 8192 or any(ord(char) <= 32 for char in url):
        raise DocumentationError("Invalid retained API source URL")

    try:
        parsed = urlsplit(url)
        port = parsed.port

    except ValueError:
        raise DocumentationError("Invalid retained API source URL control") from None

    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment or (
        port is not None or "\\" in url
    ):
        raise DocumentationError("Retained API acquisition requires its exact HTTPS source")

    if kind == "metadata":
        suffix = url.removeprefix(RELEASE_API)

        if not url.startswith(RELEASE_API + "/") or not re.fullmatch(
            r"/git/ref/tags/v0\.3\.0|/git/(?:tags|commits)/[0-9a-f]{40}|/releases/tags/v0\.3\.0",
            suffix,
        ):
            raise DocumentationError("Retained API metadata source is outside the closed release")

        return MAX_RELEASE_METADATA_BYTES

    names = {"archive": RELEASE_ARCHIVE, "manifest": RELEASE_TRANSFER}

    if kind not in names:
        raise DocumentationError("Unknown retained API acquisition role")

    direct = url == RELEASE_DOWNLOAD + names[kind]
    cdn = parsed.netloc == "release-assets.githubusercontent.com" and (
        parsed.path.startswith("/github-production-release-asset/")
        and ".." not in PurePosixPath(parsed.path).parts and "%" not in parsed.path
    )

    if not direct and not cdn:
        raise DocumentationError("Retained API asset source is outside its exact release/CDN")

    return MAX_API_ARCHIVE_BYTES if kind == "archive" else MAX_RELEASE_TRANSFER_BYTES


def ReadReleaseHttp(kind: str, url: str, timeout_seconds: float,
                    token: str | None) -> tuple[int, str | None, bytes]:
    """Read one original response in the deadline-owned child with during-read admission caps.

    Args:
        kind: Closed metadata/archive/manifest role.
        url: Validated exact source, with redirects disabled.
        timeout_seconds: Positive parent-selected allowance no larger than thirty seconds.
        token: Optional bounded GitHub API credential; never sent to asset/CDN hosts.

    Returns:
        Original status, optional bounded redirect location and bounded body bytes.
    """

    maximum = ReleaseSource(kind, url)

    if type(timeout_seconds) not in {int, float} or not 0 < timeout_seconds <= RELEASE_CALL_SECONDS:
        raise DocumentationError("Invalid retained API call allowance")

    if token is not None and (type(token) is not str or not re.fullmatch(r"[A-Za-z0-9_]{1,1024}",
                                                                       token)):
        raise DocumentationError("Invalid retained API credential syntax")

    headers = {"User-Agent": "1337-retained-api/1", "Accept": "application/octet-stream"}

    if kind == "metadata":
        headers.update({"Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28"})

        if token is not None:
            headers["Authorization"] = "Bearer " + token

    request = urllib.request.Request(url, headers=headers)
    opener = urllib.request.build_opener(NoReleaseRedirect(), urllib.request.ProxyHandler({}))

    try:
        response = opener.open(request, timeout=timeout_seconds)

    except urllib.error.HTTPError as error:
        response = error

    with response:
        status = response.code
        location = response.headers.get("Location")

        if type(status) is not int or location is not None and len(location) > 8192:
            raise DocumentationError("Invalid retained API response control")

        lengths = response.headers.get_all("Content-Length", [])

        if len(lengths) > 1 or lengths and (not lengths[0].isdigit() or int(lengths[0]) > maximum):
            raise DocumentationError("Retained API response exceeds its declared body limit")

        body = bytearray()

        while chunk := response.read(64 * 1024):
            if len(chunk) > maximum - len(body):
                raise DocumentationError("Retained API response exceeded its during-read limit")

            body.extend(chunk)

    return status, location, bytes(body)


def ReleaseWorker() -> int:
    """Serve one fixed bounded HTTP read; the parent owns a killable whole-call deadline.

    Returns:
        Zero with bounded framed original response, or one with no credential-bearing diagnostics.
    """

    try:
        raw = sys.stdin.buffer.read(MAX_RELEASE_CONTROL_BYTES + 1)

        if len(raw) > MAX_RELEASE_CONTROL_BYTES:
            raise DocumentationError("Retained API worker control exceeds its bound")

        value = json.loads(raw)

        if type(value) is not dict or set(value) != {"kind", "url", "timeout_seconds", "token"}:
            raise DocumentationError("Invalid retained API worker control")

        status, location, body = ReadReleaseHttp(**value)
        control = json.dumps({"status": status, "location": location}, sort_keys=True).encode()

        if len(control) > MAX_RELEASE_CONTROL_BYTES:
            raise DocumentationError("Retained API response control exceeds its bound")

        sys.stdout.buffer.write(control + b"\n" + body)

        return 0

    except (OSError, ValueError, TypeError, urllib.error.URLError):
        return 1


def FetchRelease(kind: str, url: str, deadline: float,
                 token: str | None = None) -> tuple[int, bytes]:
    """Own finite HTTP children and validate each asset redirect without forwarding API secrets.

    Args:
        kind: Closed original response role.
        url: Exact original fixed API/asset URL.
        deadline: Original inclusive monotonic whole-acquisition deadline.
        token: Optional API-only credential, supplied through private stdin rather than argv.

    Returns:
        Final original HTTP status and role-bounded body; no body is persisted here.
    """

    for hop in range(4):
        maximum = ReleaseSource(kind, url)
        call_deadline = min(deadline, time.monotonic() + RELEASE_CALL_SECONDS)
        remaining = call_deadline - time.monotonic()

        if remaining <= 0:
            raise DocumentationError("Retained API acquisition deadline exhausted")

        if token is not None and (type(token) is not str or not re.fullmatch(
            r"[A-Za-z0-9_]{1,1024}", token,
        )):
            raise DocumentationError("Invalid retained API credential syntax")

        control = json.dumps({"kind": kind, "url": url, "timeout_seconds": remaining,
                              "token": token if kind == "metadata" else None}).encode()

        try:
            completed = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()),
                "--version-fetch-worker"], input=control, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, check=False, timeout=remaining,
                env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"})

        except subprocess.TimeoutExpired:
            raise DocumentationError("Retained API HTTP call exceeded its deadline") from None

        if completed.returncode != 0 or time.monotonic() > call_deadline or (
            len(completed.stdout) > maximum + MAX_RELEASE_CONTROL_BYTES
        ):
            raise DocumentationError("Retained API original HTTP response is unverified")

        header, separator, body = completed.stdout.partition(b"\n")

        if not separator or len(header) > MAX_RELEASE_CONTROL_BYTES or len(body) > maximum:
            raise DocumentationError("Retained API original response framing exceeds its bound")

        try:
            response = json.loads(header)

        except (json.JSONDecodeError, UnicodeError):
            raise DocumentationError("Invalid retained API response control encoding") from None

        if type(response) is not dict or set(response) != {"status", "location"} or (
            type(response["status"]) is not int
        ):
            raise DocumentationError("Retained API original response control is invalid")

        if response["status"] not in {301, 302, 303, 307, 308}:
            return response["status"], body

        if kind == "metadata" or hop == 3 or type(response["location"]) is not str:
            raise DocumentationError("Retained API redirect is outside its finite source policy")

        url = response["location"]

    raise DocumentationError("Retained API redirect allowance exhausted")


def ReleaseJson(url: str, deadline: float, token: str | None) -> dict:
    """Decode bounded successful metadata from one fixed original repository API source.

    Args:
        url: Exact repository API URL admitted by the closed source policy.
        deadline: Original monotonic deadline shared by the complete acquisition.
        token: Optional private API credential, never forwarded to public assets.

    Returns:
        The decoded original metadata object after status, byte and type checks.
    """

    status, raw = FetchRelease("metadata", url, deadline, token)

    if status != 200:
        raise DocumentationError("Retained API selected release metadata is unavailable")

    try:
        value = json.loads(raw)

    except (json.JSONDecodeError, UnicodeError):
        raise DocumentationError("Invalid retained API release metadata encoding") from None

    if type(value) is not dict:
        raise DocumentationError("Retained API release metadata must be an object")

    return value


def SelectVersionSource(root: Path) -> dict[str, str]:
    """Select only initial 0.3 generation or verified original tagged release assets.

    Args:
        root: Explicit reviewed checkout. Other package versions perform no GitHub operation.

    Returns:
        Closed workflow outputs after acquisition/source verification and exclusive publication.
    """

    root = SafePath(root)
    package = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    result = {"release_version": "", "retained_archive": "", "retained_sha256": ""}

    if package["project"]["version"] != "0.3.0":
        return result

    deadline = time.monotonic() + RELEASE_ACQUISITION_SECONDS
    token = os.environ.get("GH_TOKEN")
    status, raw = FetchRelease("metadata", RELEASE_API + "/git/ref/tags/v0.3.0", deadline, token)

    if status == 404:
        return {**result, "release_version": "0.3.0"}

    if status != 200:
        raise DocumentationError("Retained API tag query failed without proving tag absence")

    try:
        tag = json.loads(raw)

    except (json.JSONDecodeError, UnicodeError):
        raise DocumentationError("Invalid retained API tag response encoding") from None

    if type(tag) is not dict or tag.get("ref") != "refs/tags/v0.3.0":
        raise DocumentationError("Retained API tag response differs from the selected exact tag")

    selected = tag.get("object")

    for hop in range(5):
        if type(selected) is not dict or type(selected.get("sha")) is not str or not re.fullmatch(
            r"[0-9a-f]{40}", selected["sha"],
        ) or selected.get("type") not in {"tag", "commit"}:
            raise DocumentationError("Retained API tag object identity is invalid")

        revision = selected["sha"]

        if selected["type"] == "commit":
            break

        if hop == 4:
            raise DocumentationError("Retained API annotated tag depth exceeds its finite bound")

        annotation = ReleaseJson(RELEASE_API + "/git/tags/" + revision, deadline, token)

        if annotation.get("sha") != revision:
            raise DocumentationError("Retained API annotation differs from its selected tag object")

        selected = annotation.get("object")

    commit = ReleaseJson(RELEASE_API + "/git/commits/" + revision, deadline, token)
    tree_value = commit.get("tree")
    committer = commit.get("committer")

    if type(tree_value) is not dict or type(committer) is not dict or type(
        committer.get("date")
    ) is not str:
        raise DocumentationError("Retained API source commit metadata is malformed")

    tree = tree_value.get("sha")

    if commit.get("sha") != revision or type(tree) is not str or not re.fullmatch(
        r"[0-9a-f]{40}", tree,
    ):
        raise DocumentationError("Retained API source commit/tree identity is invalid")

    try:
        timestamp = datetime.fromisoformat(committer["date"].replace("Z", "+00:00"))

    except ValueError:
        raise DocumentationError("Retained API commit timestamp is invalid") from None

    if timestamp.utcoffset() is None:
        raise DocumentationError("Retained API commit timestamp must have an explicit timezone")

    epoch = int(timestamp.timestamp())
    release = ReleaseJson(RELEASE_API + "/releases/tags/v0.3.0", deadline, token)

    if release.get("tag_name") != "v0.3.0" or release.get("draft") is not False or (
        release.get("prerelease") is not False
        or release.get("html_url") != "https://github.com/Fuzzy-Technologies/1337/releases/tag/v0.3.0"
        or type(release.get("assets")) is not list or len(release["assets"]) > 64
    ):
        raise DocumentationError("Retained API release differs from the selected public tag")

    bodies = {}

    for kind, name in (("manifest", RELEASE_TRANSFER), ("archive", RELEASE_ARCHIVE)):
        assets = [item for item in release["assets"]
                  if type(item) is dict and item.get("name") == name]

        if len(assets) != 1:
            raise DocumentationError("Retained API release requires both exact unique assets")

        asset = assets[0]
        url = RELEASE_DOWNLOAD + name
        maximum = ReleaseSource(kind, url)

        if asset.get("browser_download_url") != url or asset.get("state") != "uploaded" or (
            type(asset.get("size")) is not int or not 0 < asset["size"] <= maximum
        ):
            raise DocumentationError("Retained API asset source or declared size is invalid")

        status, body = FetchRelease(kind, url, deadline)

        if status != 200 or len(body) != asset["size"]:
            raise DocumentationError("Retained API original asset status/size differs")

        bodies[name] = body

    directory = SafePath(root / "_build/docs")
    destination = directory / "retained-api"

    if destination.exists() or time.monotonic() > deadline:
        raise DocumentationError("Retained API destination or overall deadline is invalid")

    with tempfile.TemporaryDirectory(prefix=".retained-api-", dir=directory) as temporary:
        staging = Path(temporary)

        for name, body in bodies.items():
            with (staging / name).open("xb") as output:
                output.write(body)

        verified = VerifyVersionTransfer(staging / RELEASE_ARCHIVE, staging / RELEASE_TRANSFER,
                                         revision, tree, "0.3.0", epoch)

        if time.monotonic() > deadline:
            raise DocumentationError("Retained API verification exceeded the overall deadline")

        staging.rename(destination)

    return {**result, "retained_archive": "_build/docs/retained-api/" + RELEASE_ARCHIVE,
            "retained_sha256": verified["sha256"]}


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



def ApiVersion(version: object) -> str:
    """Require one canonical stable release route, without aliases or path syntax.

    Args:
        version: Explicit X.Y.Z release spelling from reviewed provenance.

    Returns:
        Unchanged validated version string.

    Raises:
        DocumentationError: The version is not a canonical numeric release.
    """

    if type(version) is not str or not re.fullmatch(
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version,
    ):
        raise DocumentationError("Immutable API version must use canonical X.Y.Z syntax")

    return version


def ValidateVersionArtifact(root: Path) -> dict:
    """Verify a closed three-locale immutable API tree against its source-bound inventory.

    Args:
        root: Explicit version directory containing locales and its provenance document.

    Returns:
        Validated source/version metadata with an exact complete file inventory.

    Raises:
        DocumentationError: Metadata, paths, entry points or original digests differ.
        OSError: An explicitly selected artifact cannot be read.
    """

    inventory = ValidateArtifact(root)
    provenance_path = root / VERSION_PROVENANCE

    if provenance_path.stat().st_size > 4 * 1024 * 1024:
        raise DocumentationError("API version provenance exceeds its byte limit")

    try:
        record = json.loads(provenance_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeError) as error:
        raise DocumentationError("Invalid API version provenance encoding") from error

    required = {"schema_version", "version", "revision", "tree", "base_path", "locales",
                "source_date_epoch", "files", "artifact_sha256"}

    if type(record) is not dict or set(record) != required or type(
        record["schema_version"]
    ) is not int or record["schema_version"] != 1:
        raise DocumentationError("Invalid API version provenance schema")

    ApiVersion(record["version"])

    if record["locales"] != list(LOCALES) or any(
        type(record[name]) is not str
        or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", record[name])
        for name in ("revision", "tree")
    ) or type(record["source_date_epoch"]) is not int or record["source_date_epoch"] < 0:
        raise DocumentationError("Invalid API version source identity or locale inventory")

    if type(record["base_path"]) is not str or BasePath(record["base_path"]) != "/1337":
        raise DocumentationError("Immutable API artifact must retain the /1337 publication mount")

    files = {name: digest for name, digest in inventory.items() if name != VERSION_PROVENANCE}

    if not all(name.split("/", 1)[0] in LOCALES for name in files) or any(
        f"{locale}/index.html" not in files for locale in LOCALES
    ) or files != record["files"]:
        raise DocumentationError("Immutable API files differ from the declared complete inventory")

    encoded = json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")

    if hashlib.sha256(encoded).hexdigest() != record["artifact_sha256"]:
        raise DocumentationError("Immutable API inventory digest differs")

    return {**record, "provenance_sha256": inventory[VERSION_PROVENANCE]}


def ExtractVersionArchive(
    archive: Path, expected_sha256: str, destination: Path,
) -> tuple[str, dict]:
    """Verify a caller-pinned closed archive before publishing its selected version directory.

    Args:
        archive: Existing gzip tar with only version-prefixed regular files.
        expected_sha256: Trusted digest selected independently by the release/catalog caller.
        destination: Absent staging destination beneath an existing physical parent.

    Returns:
        Version and verified provenance; destination contains that version's original bytes.

    Raises:
        DocumentationError: Digest, bounds, tar paths/types or source inventory are invalid.
        OSError: Explicit archive inputs or owned staging cannot be accessed.
    """

    archive, destination = map(SafePath, (archive, destination))

    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256) or not archive.is_file() or (
        archive.stat().st_size > MAX_API_ARCHIVE_BYTES
    ):
        raise DocumentationError("Invalid immutable API archive selection or size")

    with archive.open("rb") as selected:
        original = selected.read(MAX_API_ARCHIVE_BYTES + 1)

    if len(original) > MAX_API_ARCHIVE_BYTES or (
        hashlib.sha256(original).hexdigest() != expected_sha256
    ):
        raise DocumentationError("Immutable API archive checksum differs from the selected digest")

    if destination.exists() or not destination.parent.is_dir():
        raise DocumentationError("API archive destination must be absent below an existing parent")

    with tempfile.TemporaryDirectory(prefix=".api-archive-", dir=destination.parent) as temporary:
        unpacked = Path(temporary) / "archive.tar"
        total = 0

        with (
            gzip.GzipFile(fileobj=io.BytesIO(original), mode="rb") as compressed,
            unpacked.open("xb") as expanded,
        ):
            while chunk := compressed.read(1024 * 1024):
                total += len(chunk)

                if total > MAX_API_EXPANDED_BYTES:
                    raise DocumentationError("Immutable API archive exceeds its expanded limit")

                expanded.write(chunk)

        staging = Path(temporary) / "files"
        staging.mkdir()
        version = None
        names = set()

        with tarfile.open(unpacked, "r:") as contents:
            for member in contents:
                path = PurePosixPath(member.name)

                if member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE} or member.pax_headers or (
                    member.name != path.as_posix()
                    or any(ord(character) < 32 or ord(character) == 127
                           for character in member.name)
                    or path.is_absolute() or ".." in path.parts or len(path.parts) < 2
                    or "\\" in member.name or len(member.name.encode("utf-8")) > 4096
                    or member.name in names or len(names) >= MAX_API_ARCHIVE_FILES
                ):
                    raise DocumentationError("Immutable API tar contains an unsupported entry")

                selected = ApiVersion(path.parts[0])

                if version is not None and version != selected:
                    raise DocumentationError("Immutable API archive contains multiple versions")

                version = selected
                names.add(member.name)
                target = staging / path
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = contents.extractfile(member)

                if stream is None:
                    raise DocumentationError("Immutable API archive lost a regular file stream")

                with stream, target.open("xb") as output:
                    shutil.copyfileobj(stream, output)

            with unpacked.open("rb") as trailing:
                trailing.seek(contents.offset)

                while chunk := trailing.read(1024 * 1024):
                    if any(chunk):
                        raise DocumentationError("Immutable API archive contains trailing payload")

        if version is None:
            raise DocumentationError("Immutable API archive is empty")

        root = staging / version
        record = ValidateVersionArtifact(root)

        if record["version"] != version:
            raise DocumentationError("Immutable API archive path differs from its version identity")

        destination.mkdir()

        try:
            for child in sorted(root.iterdir()):
                child.rename(destination / child.name)
        except BaseException:
            shutil.rmtree(destination)
            raise

    return version, record



def VerifyVersionTransfer(
    archive: Path, transfer_manifest: Path, expected_revision: str, expected_tree: str,
    expected_version: str, expected_epoch: int,
) -> dict:
    """Verify exact master-render bytes against a selected tag or accepted master-run identity.

    Args:
        archive: Selected release archive; never a rebuilt replacement.
        transfer_manifest: Separate master-build checksum and source-identity document.
        expected_revision: Trusted tag/master-run commit, supplied independently by the caller.
        expected_tree: Trusted source tree belonging to that exact commit.
        expected_version: Explicit release version, without a moving alias.
        expected_epoch: Commit timestamp used to derive SOURCE_DATE_EPOCH.

    Returns:
        Verified transfer metadata after closed archive and embedded provenance comparison.

    Raises:
        DocumentationError: Original bytes, selected source identity or metadata differ.
        OSError: Selected transfer inputs cannot be read.
    """

    archive, transfer_manifest = map(SafePath, (archive, transfer_manifest))
    version = ApiVersion(expected_version)

    if transfer_manifest.stat().st_size > 16384:
        raise DocumentationError("API transfer manifest exceeds its byte limit")

    try:
        transfer = json.loads(transfer_manifest.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeError) as error:
        raise DocumentationError("Invalid API transfer manifest encoding") from error

    required = {"schema_version", "filename", "sha256", "size_bytes", "version", "revision",
                "tree", "base_path", "locales", "source_date_epoch", "provenance_sha256"}

    if type(transfer) is not dict or set(transfer) != required:
        raise DocumentationError("Invalid API transfer manifest schema")

    if type(transfer["schema_version"]) is not int or transfer["schema_version"] != 1 or (
        transfer["filename"] != archive.name
        or archive.name != f"1337-{version}-api-docs.tar.gz"
        or transfer["version"] != version or transfer["revision"] != expected_revision
        or transfer["tree"] != expected_tree or transfer["base_path"] != "/1337"
        or transfer["locales"] != list(LOCALES)
        or type(transfer["source_date_epoch"]) is not int
        or transfer["source_date_epoch"] != expected_epoch
        or type(transfer["size_bytes"]) is not int
        or not 0 < transfer["size_bytes"] <= MAX_API_ARCHIVE_BYTES
        or transfer["size_bytes"] != archive.stat().st_size
        or type(transfer["sha256"]) is not str
        or not re.fullmatch(r"[0-9a-f]{64}", transfer["sha256"])
    ):
        raise DocumentationError("API transfer differs from its selected release source or bytes")

    with tempfile.TemporaryDirectory(prefix=".api-transfer-", dir=archive.parent) as temporary:
        actual_version, provenance = ExtractVersionArchive(
            archive, transfer["sha256"], Path(temporary) / "verified",
        )

        if actual_version != version or any(provenance[key] != transfer[key] for key in (
            "revision", "tree", "base_path", "locales", "source_date_epoch", "provenance_sha256",
        )):
            raise DocumentationError("Embedded API provenance differs from the original transfer")

    return transfer


def ComposeDocumentation(
    product_site: Path,
    api_root: Path,
    output: Path,
    revision: str,
    base_path: str = "/1337",
    version_root: Path | None = None,
    retained_archive: Path | None = None,
    retained_sha256: str | None = None,
) -> dict[str, object]:
    """Build and validate a complete artifact without replacing existing output.

    Args:
        product_site: Existing Jekyll artifact with an index.html entry point.
        api_root: Directory containing en, ru, and zh-cn API artifacts.
        output: Absent destination whose parent directory already exists.
        revision: Full Git commit identifier for publication traceability.
        base_path: Absolute GitHub Pages project mount.
        version_root: Current independently rendered immutable API version, if selected.
        retained_archive: Optional closed archive for one previously published version.
        retained_sha256: Independently pinned digest required with the retained archive.

    Returns:
        Deterministic provenance including source inventories and artifact identity.

    Raises:
        DocumentationError: An input, collision, URL, or publication invariant fails.
        OSError: A filesystem failure prevents publication; owned partial output is removed.
    """

    product_site, api_root, output = map(SafePath, (product_site, api_root, output))
    if (retained_archive is None) != (retained_sha256 is None):
        raise DocumentationError("Retained API archive requires an independently selected checksum")

    if version_root is not None:
        version_root = SafePath(version_root)

    roots = (product_site, api_root, output, *((version_root,) if version_root else ()))

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

    if (version_root is not None or retained_archive is not None) and base_path != "/1337":
        raise DocumentationError("Immutable API composition must retain the /1337 mount")

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

    current = ValidateVersionArtifact(version_root) if version_root is not None else None

    if current and current["revision"] != revision:
        raise DocumentationError("Current API source differs from the publication revision")

    with tempfile.TemporaryDirectory(
        prefix=".documentation-compose-", dir=output.parent
    ) as temporary:
        staging = Path(temporary) / "artifact"
        shutil.copytree(product_site, staging, symlinks=True)

        for locale in LOCALES:
            shutil.copytree(api_root / locale, staging / "api/latest" / locale, symlinks=True)

        versions = {}
        version_files = {}

        if current is not None:
            version = current["version"]

            if (staging / "api" / version).exists():
                raise DocumentationError("Product artifact collides with an immutable API version")

            shutil.copytree(version_root, staging / "api" / version, symlinks=True)
            versions[version] = current
            version_files.update({f"api/{version}/{name}": digest for name, digest in {
                **current["files"], VERSION_PROVENANCE: current["provenance_sha256"],
            }.items()})

        if retained_archive is not None:
            retained = Path(temporary) / "retained"
            version, previous = ExtractVersionArchive(retained_archive, retained_sha256, retained)
            target = staging / "api" / version

            if version in versions:
                if Inventory(target) != Inventory(retained):
                    raise DocumentationError("An immutable API version cannot be replaced")

            elif target.exists():
                raise DocumentationError("Product artifact collides with a retained API version")

            else:
                shutil.copytree(retained, target, symlinks=True)
                versions[version] = previous
                version_files.update({f"api/{version}/{name}": digest for name, digest in {
                    **previous["files"], VERSION_PROVENANCE: previous["provenance_sha256"],
                }.items()})

        link_counts = ValidateLinks(staging, base_path or "/")
        files = Inventory(staging)
        expected_files = {**product_inventory, **{
            f"api/latest/{path}": digest for path, digest in api_inventory.items()
        }, **version_files}

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
        if versions:
            manifest["api_versions"] = versions

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

    tokens = list(sys.argv[1:] if argv is None else argv)

    if tokens == ["--version-fetch-worker"]:
        return ReleaseWorker()

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product-site", type=Path)
    parser.add_argument("--api-root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--revision")
    parser.add_argument("--base-path", default="/1337")
    parser.add_argument("--validate-only", type=Path)
    parser.add_argument("--version-root", type=Path)
    parser.add_argument("--retained-api-archive", type=Path)
    parser.add_argument("--retained-api-sha256")
    parser.add_argument("--verify-version-archive", type=Path)
    parser.add_argument("--archive-manifest", type=Path)
    parser.add_argument("--expected-revision")
    parser.add_argument("--expected-tree")
    parser.add_argument("--expected-version")
    parser.add_argument("--expected-epoch", type=int)
    parser.add_argument("--select-version-source", type=Path)
    arguments = parser.parse_args(tokens)

    verification = (arguments.archive_manifest, arguments.expected_revision,
                    arguments.expected_tree, arguments.expected_version, arguments.expected_epoch)

    if arguments.select_version_source and any((
        arguments.product_site, arguments.api_root, arguments.output, arguments.revision,
        arguments.validate_only, arguments.version_root, arguments.retained_api_archive,
        arguments.retained_api_sha256, arguments.verify_version_archive,
        *[value is not None for value in verification],
    )):
        parser.error("version source selection requires only the explicit project root")

    if arguments.verify_version_archive:
        if any(value is None for value in verification) or any((
            arguments.product_site, arguments.api_root, arguments.output, arguments.revision,
            arguments.validate_only, arguments.version_root, arguments.retained_api_archive,
            arguments.retained_api_sha256,
        )):
            parser.error("archive verification requires only its manifest and source identity")

    elif any(value is not None for value in verification):
        parser.error("archive source arguments require --verify-version-archive")

    if arguments.validate_only and any(
        (arguments.product_site, arguments.api_root, arguments.output, arguments.revision,
         arguments.version_root, arguments.retained_api_archive, arguments.retained_api_sha256)
    ):
        parser.error("--validate-only cannot be combined with composition arguments")

    if not arguments.validate_only and not arguments.verify_version_archive and not (
        arguments.select_version_source
    ) and not all(
        (arguments.product_site, arguments.api_root, arguments.output, arguments.revision)
    ):
        parser.error("composition requires --product-site, --api-root, --output, and --revision")

    result: dict[str, object]

    try:
        if arguments.select_version_source:
            result = dict(SelectVersionSource(arguments.select_version_source))

        elif arguments.verify_version_archive:
            result = VerifyVersionTransfer(
                arguments.verify_version_archive, arguments.archive_manifest,
                arguments.expected_revision, arguments.expected_tree, arguments.expected_version,
                arguments.expected_epoch,
            )

        elif arguments.validate_only:
            result = dict(ValidateLinks(arguments.validate_only, arguments.base_path))

        else:
            result = ComposeDocumentation(
                arguments.product_site, arguments.api_root, arguments.output,
                arguments.revision, arguments.base_path, arguments.version_root,
                arguments.retained_api_archive, arguments.retained_api_sha256,
            )

    except (DocumentationError, OSError, UnicodeError, tarfile.TarError, EOFError) as error:
        print(f"Documentation validation failed: {error}", file=sys.stderr)

        return 1

    print(json.dumps(result, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
