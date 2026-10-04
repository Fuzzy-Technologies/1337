# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Build and inspect multilingual API documentation without importing the runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from html.parser import HTMLParser
from pathlib import Path, PureWindowsPath
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def LocalInput(root: Path, relative: str) -> Path:
    """Resolve a declared project path without reading outside or following links.

    Args:
        root: Explicit repository boundary selected for the documentation build.
        relative: Nonempty project-relative path from reviewed configuration.

    Returns:
        A contained path, which may not yet exist for disposable build output.

    Raises:
        ValueError: Path syntax escapes the boundary or any component is symbolic.
    """

    path = Path(relative)

    if (
        not relative or path.anchor or PureWindowsPath(relative).drive
        or ".." in path.parts or "\\" in relative
    ):
        raise ValueError(f"Documentation input must be project-relative: {relative}")

    candidate = root / path

    if not candidate.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"Documentation path escapes the project: {relative}")

    if any(part.is_symlink() for part in (candidate, *candidate.parents)):
        raise ValueError(f"Documentation paths cannot follow symlinks: {relative}")

    return candidate


def ReadManifest(root: Path) -> dict:
    """Read the portable documentation project contract.

    Args:
        root: Checkout containing docs/i18n/project.toml.

    Returns:
        Parsed project settings used for static discovery and locale rendering.

    Raises:
        OSError: The manifest cannot be read.
        ValueError: The manifest is not valid TOML.
    """

    manifest = tomllib.loads(LocalInput(root, "docs/i18n/project.toml").read_text(encoding="utf-8"))

    for field in ("contentRoot", "unitManifest", "buildRoot", "apiCoverageManifest"):
        LocalInput(root, manifest[field])

    for glossary in manifest.get("glossaries", {}).values():
        LocalInput(root, glossary)

    return manifest


def ValidateInventory(root: Path, manifest: dict) -> list[dict]:
    """Reject unclassified modules, duplicate declarations, and invalid API pages.

    Args:
        root: Checkout containing source modules, authored pages, and locale units.
        manifest: Project package roots and inventory/content/unit manifest paths.

    Returns:
        Module-sorted surface records enriched with expected canonical symbol anchors.

    Raises:
        ValueError: Source coverage, exclusions, package ownership, or pages are invalid.
        OSError: A declared inventory or canonical page cannot be read.
        KeyError: Required inventory or unit metadata is absent.
    """

    inventory = tomllib.loads(
        LocalInput(root, manifest["apiCoverageManifest"]).read_text(encoding="utf-8")
    )
    surfaces = inventory.get("surfaces", [])
    exclusions = inventory.get("moduleExclusions", [])
    declared = [record["source"] for record in surfaces + exclusions]
    actual = {path.relative_to(root).as_posix() for path in (root / "src").rglob("*.py")}

    if len(declared) != len(set(declared)) or set(declared) != actual:
        raise ValueError("API inventory must classify every source module exactly once")

    for record in exclusions:
        if not record.get("reason", "").strip():
            raise ValueError("Excluded modules require an explicit reason")

    for record in surfaces:
        LocalInput(root, record["source"])
        if record["mode"] not in {"authored", "exports"}:
            raise ValueError("API surfaces require a static authored/exports mode")

        if record["module"].partition(".")[0] not in manifest["packageNames"]:
            raise ValueError("API modules must belong to a declared package")

        page = LocalInput(root, f"{manifest['contentRoot']}/en/{record['page']}")

        if not page.is_file() or f"::: {record['module']}" not in page.read_text():
            raise ValueError(f"API page must document the declared module: {page}")

    units = tomllib.loads((root / manifest["unitManifest"]).read_text(encoding="utf-8"))

    for record in surfaces:
        record["symbols"] = sorted(
            unit["id"].removeprefix("symbol:") for unit in units["units"]
            if unit["kind"] == "symbol" and unit["sourcePath"] == record["source"]
        )

    return sorted(surfaces, key=lambda surface: surface["module"])


class ImportTripwire:
    """Reject every attempted import of a security runtime package."""

    def __init__(self, packages: list[str]) -> None:
        """Store the declared runtime package names.

        Args:
            packages: Top-level runtime roots whose documentation imports are forbidden.
        """

        self.packages = packages

    def find_spec(
        self, fullname: str, path: object | None = None, target: object | None = None
    ) -> None:
        """Deny security runtime imports while allowing other finders to proceed.

        Args:
            fullname: Fully qualified module name requested by Python's import machinery.
            path: Parent-package search path supplied by importlib; unused by this guard.
            target: Existing module supplied for reload; unused by this guard.

        Raises:
            RuntimeError: The requested module belongs to a forbidden runtime package.
        """

        if fullname.partition(".")[0] in self.packages:
            raise RuntimeError(f"Documentation attempted to import security runtime: {fullname}")

        return None


class HtmlInventory(HTMLParser):
    """Collect generated HTML anchors and local resource links."""

    def __init__(self) -> None:
        """Create empty deterministic link and anchor collections."""

        super().__init__()
        self.anchors: set[str] = set()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Collect HTML IDs and href/src references from parser callbacks.

        Args:
            tag: Parsed element name supplied by HTMLParser.
            attrs: Decoded attribute names and optional values supplied by HTMLParser.
        """

        attributes = dict(attrs)

        if attributes.get("id"):
            self.anchors.add(str(attributes["id"]))

        for name in ("href", "src"):
            if attributes.get(name):
                self.links.append(str(attributes[name]))


def ValidateSymbolAnchors(anchors: set[str], symbols: list[str]) -> None:
    """Reject any omitted documented public function, class, or class method.

    Args:
        anchors: IDs collected from the generated module page.
        symbols: Canonical fully qualified symbol names expected on that page.

    Raises:
        ValueError: At least one documented public symbol anchor is absent.
    """

    missing = sorted(set(symbols) - anchors)

    if missing:
        raise ValueError(f"Generated public API symbol anchors are missing: {', '.join(missing)}")


def ValidateFallbackState(root: Path, manifest: dict) -> None:
    """Reject states this initial fallback renderer cannot publish honestly.

    Args:
        root: Checkout containing the canonical locale unit manifest.
        manifest: Unit-manifest path and ordered publication locales.

    Raises:
        ValueError: A target translation has any state other than explicit missing.
        OSError: The locale manifest cannot be read.
        KeyError: Required locale or unit fields are absent.
    """

    units = tomllib.loads((root / manifest["unitManifest"]).read_text(encoding="utf-8"))

    for unit in units["units"]:
        for locale in manifest["locales"][1:]:
            if unit.get("translations", {}).get(locale, {}).get("state") != "missing":
                raise ValueError(
                    f"Initial reference renderer supports only missing translations: "
                    f"{unit['id']} {locale}; implement reviewed translation selection first"
                )


def ValidateWheelSources(root: Path, installed_packages: Path, packages: list[str]) -> None:
    """Require installed Python source to match the reviewed checkout exactly.

    Args:
        root: Reviewed checkout with canonical source below src.
        installed_packages: Clean environment's installed package directory.
        packages: Declared top-level packages whose Python files must match.

    Raises:
        ValueError: Installed Python paths or source digests differ from the checkout.
        OSError: A compared source cannot be read.
    """

    for package in packages:
        expected = {
            path.relative_to(root / "src").as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (root / "src" / package).rglob("*.py")
        }
        actual = {
            path.relative_to(installed_packages).as_posix(): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in (installed_packages / package).rglob("*.py")
        }

        if expected != actual:
            raise ValueError("Installed wheel Python sources differ from the reviewed checkout")


def CheckOutput(site: Path, modules: list[dict], base_url: str) -> dict:
    """Require search, static symbols, source blocks, and valid local anchors.

    Args:
        site: Generated output tree for one publication locale.
        modules: Surface records declaring module pages and public symbol anchors.
        base_url: Absolute locale API URL path used to resolve generated root links.

    Returns:
        HTML page count and deterministic relative-file SHA-256 inventory.

    Raises:
        ValueError: Search, source, formula, symbol, link, or anchor evidence is missing.
        OSError: Generated output cannot be read.
    """

    pages: dict[Path, HtmlInventory] = {}

    for path in sorted(site.rglob("*.html")):
        parsed = HtmlInventory()
        parsed.feed(path.read_text(encoding="utf-8"))
        pages[path.resolve()] = parsed

    if not (site / "search/search_index.json").is_file():
        raise ValueError("API output is missing the search index")

    for module in modules:
        page = site / module["page"].removesuffix(".md") / "index.html"

        if not page.is_file() or module["module"] not in pages[page.resolve()].anchors:
            raise ValueError(f"Generated API module anchor is missing: {module['module']}")

        ValidateSymbolAnchors(pages[page.resolve()].anchors, module["symbols"])

    authored_pages = [
        site / module["page"].removesuffix(".md") / "index.html" for module in modules
    ]

    if authored_pages and not any(
        'class="mkdocstrings-source"' in page.read_text(encoding="utf-8") for page in authored_pages
    ):
        raise ValueError("API output must expose statically analyzed source blocks")

    if modules and (
        "arithmatex" not in (site / "index.html").read_text(encoding="utf-8")
        or not (site / "assets/mathjax/tex-mml-svg.js").is_file()
    ):
        raise ValueError("Formula markup and locally hosted SVG renderer must be present")

    for path, parsed in pages.items():
        for link in parsed.links:
            url = urlsplit(link)

            if url.scheme or url.netloc or not link:
                continue

            route = unquote(url.path)

            if route.startswith("/"):
                if not route.startswith(base_url):
                    continue

                target = site / route.removeprefix(base_url)

            else:
                target = path.parent / route if route else path

            if target.is_dir():
                target = target / "index.html"

            target = target.resolve()

            if not target.is_relative_to(site.resolve()) or not target.is_file():
                raise ValueError(f"Broken generated local link: {path.name}: {link}")

            if (
                url.fragment and target in pages
                and unquote(url.fragment) not in pages[target].anchors
            ):
                raise ValueError(f"Broken generated anchor: {path.name}: {link}")

    return {
        "pages": len(pages),
        "files": {
            path.relative_to(site).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(site.rglob("*")) if path.is_file()
        },
    }


def PreparePublicOutput(site: Path) -> None:
    """Remove generated renderer auxiliaries outside the reviewed public artifact contract.

    Args:
        site: Fresh locale output owned by the documentation renderer.

    Raises:
        OSError: A generated source map or optional inventory cannot be removed.
    """

    for path in site.rglob("*"):
        if path.is_file() and (
            path.suffix == ".map" or path.relative_to(site).as_posix()
            in {"objects.inv", "sitemap.xml.gz"}
        ):
            path.unlink()



def Render(root: Path, installed_packages: Path) -> None:
    """Render installed-wheel sources strictly under an active runtime-import guard.

    Args:
        root: Checkout with reviewed manifests, pages, theme assets, and configuration.
        installed_packages: Source directory from a clean installed 1337 wheel.

    Raises:
        ValueError: Wheel provenance, inventory, locale states, or output validation fails.
        RuntimeError: Documentation attempts to import the security runtime.
        OSError: Build inputs or disposable output cannot be read or written.
    """

    import yaml
    from mkdocs.commands.build import build
    from mkdocs.config import load_config

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    manifest = ReadManifest(root)
    surfaces = ValidateInventory(root, manifest)
    ValidateFallbackState(root, manifest)

    if (
        not installed_packages.is_dir()
        or installed_packages.is_relative_to(root)
        or not list(installed_packages.glob("1337-*.dist-info"))
    ):
        raise ValueError("Static reference sources must come from a clean installed 1337 wheel")

    ValidateWheelSources(root, installed_packages, manifest["packageNames"])

    sys.meta_path.insert(0, ImportTripwire(manifest["packageNames"]))
    output = root / "_build/api-reference"
    build_root = root / manifest["buildRoot"]
    build_root.mkdir(parents=True, exist_ok=True)
    evidence = {"schemaVersion": 1, "runtimeImported": False, "locales": {}}

    with tempfile.TemporaryDirectory(prefix="1337-reference-") as temporary_root:
        for locale in manifest["locales"]:
            content = build_root / "content" / locale
            shutil.rmtree(content, ignore_errors=True)
            shutil.copytree(root / manifest["contentRoot"] / "en", content)

            if locale != "en":
                for page in content.rglob("*.md"):
                    page.write_text(
                        "!!! note \"English fallback\"\n"
                        "    This translation is missing; "
                        "the canonical English reference follows.\n\n"
                        + page.read_text(encoding="utf-8"), encoding="utf-8"
                    )

            base_url = f"{manifest['publicationPath']}/api/latest/{locale}/"
            config = yaml.safe_load((root / "docs/site/mkdocs.yml").read_text(encoding="utf-8"))
            config["docs_dir"] = str(content)
            rendered = Path(temporary_root) / locale
            config["site_dir"] = str(rendered)
            config["site_url"] = "https://fuzzy-technologies.github.io" + base_url
            config["theme"]["language"] = "zh" if locale == "zh-cn" else locale
            config["nav"] = [{"Overview": "index.md"}, {"Modules": [
                {surface["module"]: surface["page"]} for surface in surfaces
            ]}]
            python = config["plugins"][1]["mkdocstrings"]["handlers"]["python"]

            if any(python["options"].get(option) is not False
                   for option in ("allow_inspection", "force_inspection")):
                raise ValueError(
                    "Static API discovery must explicitly disable both inspection options"
                )

            python["paths"] = [str(installed_packages)]
            config_path = build_root / f"mkdocs-{locale}.yml"
            config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
            build(load_config(config_file=str(config_path)), dirty=False)
            PreparePublicOutput(rendered)
            evidence["locales"][locale] = CheckOutput(rendered, surfaces, base_url)
            shutil.rmtree(output / locale, ignore_errors=True)
            shutil.copytree(rendered, output / locale)

    if any(name.partition(".")[0] in manifest["packageNames"] for name in sys.modules):
        raise RuntimeError("Security runtime was imported during documentation rendering")

    (build_root / "api-build.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def TrackedSourceHashes(root: Path) -> dict[str, str]:
    """Snapshot tracked source bytes without including disposable build output.

    Args:
        root: Git repository containing reviewed documentation and source inputs.

    Returns:
        Repository-relative paths and SHA-256 digests in deterministic order.

    Raises:
        ValueError: A tracked input is symbolic or escapes the checkout.
        OSError: A tracked source cannot be read.
    """

    paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=root, text=True, timeout=30)
    result: dict[str, str] = {}

    for name in sorted(filter(None, paths.split("\0"))):
        path = root / name

        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(root.resolve()):
            raise ValueError(f"Tracked source must stay within the checkout: {name}")

        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()

    return result


def Build(root: Path) -> None:
    """Build a clean wheel and prove reproducible documentation without source mutation.

    Args:
        root: Git checkout containing locked tools and reviewed documentation inputs.

    Raises:
        RuntimeError: uv is unavailable or the wheel build is not uniquely identified.
        ValueError: Inventory, reproducibility, or tracked-source preservation fails.
        OSError: Build inputs or evidence cannot be read or written.
        subprocess.CalledProcessError: A provisioning, wheel, or rendering command fails.
    """

    original_sources = TrackedSourceHashes(root)
    manifest = ReadManifest(root)
    ValidateInventory(root, manifest)
    source_epoch = subprocess.check_output(
        ["git", "show", "-s", "--format=%ct", "HEAD"], cwd=root, text=True, timeout=30,
    ).strip()
    render_environment = dict(os.environ, SOURCE_DATE_EPOCH=source_epoch)
    subprocess.run([sys.executable, str(root / "tools/locale_documentation.py"), "validate"],
                   cwd=root, check=True, timeout=300)
    uv = shutil.which("uv")

    if uv is None:
        raise RuntimeError("The locked documentation build requires uv")

    build_root = root / manifest["buildRoot"]
    with tempfile.TemporaryDirectory(prefix="1337-docs-") as temporary_root:
        environment = Path(temporary_root) / "venv"
        subprocess.run([uv, "venv", "--clear", str(environment)], cwd=root, check=True, timeout=300)
        python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        subprocess.run([uv, "pip", "install", "--python", str(python), "--require-hashes",
                        "-r", str(root / "docs/requirements-api.lock")],
                       cwd=root, check=True, timeout=300)
        wheels = build_root / "wheel"
        shutil.rmtree(wheels, ignore_errors=True)
        subprocess.run([str(python), "-m", "build", "--wheel", "--no-isolation", "--outdir",
                        str(wheels)], cwd=root, check=True, timeout=300, env=render_environment)
        wheel_paths = list(wheels.glob("*.whl"))

        if len(wheel_paths) != 1:
            raise RuntimeError("Documentation build requires exactly one newly built wheel")

        subprocess.run([uv, "pip", "install", "--python", str(python), "--no-deps",
                        str(wheel_paths[0])], cwd=root, check=True, timeout=300)
        installed = subprocess.check_output(
            [str(python), "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
            cwd=Path(temporary_root), text=True, timeout=30,
        ).strip()
        subprocess.run([str(python), "-I", str(Path(__file__).resolve()), "render",
                        "--root", str(root), "--installed-packages", installed],
                       cwd=Path(temporary_root), check=True, timeout=180, env=render_environment)
        report_path = build_root / "api-build.json"
        first = json.loads(report_path.read_text(encoding="utf-8"))
        (build_root / "api-first-build.json").write_text(
            json.dumps(first, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        shutil.rmtree(root / "_build/api-reference")
        subprocess.run([str(python), "-I", str(Path(__file__).resolve()), "render",
                        "--root", str(root), "--installed-packages", installed],
                       cwd=Path(temporary_root), check=True, timeout=180, env=render_environment)
        second = json.loads(report_path.read_text(encoding="utf-8"))

        if first != second:
            changed = [
                f"{locale}/{name}"
                for locale in sorted(first["locales"].keys() | second["locales"].keys())
                for name in sorted(
                    first["locales"].get(locale, {}).get("files", {}).keys()
                    | second["locales"].get(locale, {}).get("files", {}).keys()
                )
                if first["locales"].get(locale, {}).get("files", {}).get(name)
                != second["locales"].get(locale, {}).get("files", {}).get(name)
            ]
            raise ValueError(
                "Fresh strict documentation builds produced different outputs: "
                + ", ".join(changed)
            )

        if original_sources != TrackedSourceHashes(root):
            raise ValueError("Documentation generation modified tracked source inputs")

        second["sourceDateEpoch"] = int(source_epoch)
        second["reproducible"] = True
        second["sourceUnchanged"] = True
        second["wheelSha256"] = hashlib.sha256(wheel_paths[0].read_bytes()).hexdigest()
        report_path.write_text(
            json.dumps(second, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )



def Main() -> int:
    """Run the build CLI and report validation or subprocess failures.

    Returns:
        Zero after successful build/render, or one after a reported operational failure.

    Raises:
        SystemExit: Help is requested or CLI arguments are invalid.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "render"), nargs="?", default="build")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--installed-packages", type=Path)
    arguments = parser.parse_args()

    try:
        if arguments.command == "render":
            if arguments.installed_packages is None:
                raise ValueError("Render requires an installed wheel source path")

            Render(arguments.root.resolve(), arguments.installed_packages.resolve())

        else:
            Build(arguments.root.resolve())

    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)

        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
