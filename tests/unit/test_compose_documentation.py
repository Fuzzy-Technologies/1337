# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic composition, link, and failure-boundary tests."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest


def Composer() -> ModuleType:
    """Load the standalone tool without importing the security runtime."""

    path = Path(__file__).resolve().parents[2] / "tools/compose_documentation.py"
    spec = importlib.util.spec_from_file_location("compose_documentation", path)
    assert spec and spec.loader, "Composer must remain a loadable standalone Python tool"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def Artifacts(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Create minimal product/API artifacts with real cross-artifact references."""

    product = tmp_path / "product"
    api = tmp_path / "reference"
    product.mkdir()
    (product / "index.html").write_text(
        '<h1 id="vision">Vision</h1><a href="/1337/api/latest/en/#reference">API</a>'
        '<a href="https://example.invalid/path">External</a>', encoding="utf-8",
    )

    for locale in ("en", "ru", "zh-cn"):
        locale_root = api / locale
        locale_root.mkdir(parents=True)
        (locale_root / "index.html").write_text(
            '<h1 id="reference">Reference</h1><img src="assets/brand.svg">'
            '<a href="../../../#vision">Product</a>', encoding="utf-8",
        )
        (locale_root / "assets").mkdir()
        (locale_root / "assets/brand.svg").write_text('<svg id="brand"/>', encoding="utf-8")

    return product, api, tmp_path / "composed"


def test_DeterministicCompositionPreservesProductAndRecordsIdentity(tmp_path: Path):
    """Composition preserves original bytes and has no host/time-dependent metadata."""

    module = Composer()
    product, api, output = Artifacts(tmp_path)
    revision = "a" * 40
    first = module.ComposeDocumentation(product, api, output, revision)
    second_output = tmp_path / "second"
    second = module.ComposeDocumentation(product, api, second_output, revision)
    assert first == second, "Identical inputs must generate identical provenance"
    assert module.Inventory(output) == module.Inventory(second_output), (
        "Artifact byte inventory must be deterministic across destination directories"
    )
    assert (output / "index.html").read_bytes() == (product / "index.html").read_bytes(), (
        "Composition must preserve existing product URLs and page bytes"
    )
    manifest = json.loads((output / module.MANIFEST_NAME).read_text())
    assert manifest["revision"] == revision, "Publication must retain the tested source revision"
    assert manifest["validation"]["external_references"] == 1, (
        "External URLs must be inventoried without contacting the network"
    )
    assert module.MANIFEST_NAME not in manifest["files"], (
        "Artifact identity must exclude the self-referential provenance manifest"
    )


@pytest.mark.parametrize("collision", ["api/latest", "api", "documentation-provenance.json"])
def test_ReservedPathsRejectCollisionsWithoutPartialOutput(tmp_path: Path, collision: str):
    """Product pages must never be overwritten by API mounts or provenance."""

    module = Composer()
    product, api, output = Artifacts(tmp_path)
    target = product / collision
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("Preserve me", encoding="utf-8")

    with pytest.raises(module.DocumentationError, match="collid|API mount"):
        module.ComposeDocumentation(product, api, output, "a" * 40)

    assert not output.exists(), "Collision failure must leave the destination absent"
    assert target.read_text() == "Preserve me", "Collision validation must preserve source bytes"


@pytest.mark.parametrize("missing", ["product", "en", "ru", "zh-cn"])
def test_MissingEntryPointsFailClosed(tmp_path: Path, missing: str):
    """Every locale and the product site must supply a real entry point."""

    module = Composer()
    product, api, output = Artifacts(tmp_path)
    target = product if missing == "product" else api / missing
    (target / "index.html").unlink()

    with pytest.raises(module.DocumentationError, match="missing"):
        module.ComposeDocumentation(product, api, output, "a" * 40)

    assert not output.exists(), "Missing entry points must not publish a partial artifact"


@pytest.mark.parametrize("relationship", ["same", "inside", "parent", "inputs"])
def test_OverlappingPathsFailBeforeWrites(tmp_path: Path, relationship: str):
    """No composition input or output may contain another artifact tree."""

    module = Composer()
    product, api, output = Artifacts(tmp_path)

    if relationship == "same":
        output = product

    elif relationship == "inside":
        output = product / "nested"

    elif relationship == "parent":
        output = tmp_path

    else:
        api = product / "api"

    with pytest.raises(module.DocumentationError, match="overlap"):
        module.ComposeDocumentation(product, api, output, "a" * 40)

    assert (product / "index.html").exists(), "Overlap validation must preserve product input"


@pytest.mark.parametrize("reference,diagnostic", [
    ("missing.js", "Missing link target"),
    ("/1337/api/latest/en/#absent", "Missing HTML anchor"),
    ("../outside.html", "traverses outside"),
    ("%2e%2e/outside.html", "traverses outside"),
    ("/other-project/index.html", "escapes Pages"),
    ("https://fuzzy-technologies.github.io/1337/missing", "Missing link target"),
    ("javascript:alert(1)", "Unsupported URL scheme"),
    ("bad%escape", "Malformed percent escape"),
    ("..%5coutside", "Invalid URL path"),
])
def test_InvalidReferencesPreventPublication(tmp_path: Path, reference: str, diagnostic: str):
    """Missing links, anchors, unsafe schemes, and traversal fail before output exists."""

    module = Composer()
    product, api, output = Artifacts(tmp_path)
    (product / "index.html").write_text(
        f'<h1 id="vision">Vision</h1><a href="{reference}">Broken</a>', encoding="utf-8"
    )

    with pytest.raises(module.DocumentationError, match=diagnostic):
        module.ComposeDocumentation(product, api, output, "a" * 40)

    assert not output.exists(), "Link validation must prevent incomplete output publication"


def test_SymlinkInputAndNestedSymlinksFailClosed(tmp_path: Path):
    """Reject linked artifacts and assets even when their targets exist inside the input."""

    module = Composer()
    product, api, output = Artifacts(tmp_path)

    try:
        (product / "linked.html").symlink_to(product / "index.html")

    except OSError as error:
        pytest.skip(f"Test environment cannot create symlinks: {error}")

    with pytest.raises(module.DocumentationError, match="symlink"):
        module.ComposeDocumentation(product, api, output, "a" * 40)

    (product / "linked.html").unlink()
    linked_product = tmp_path / "linked-product"
    linked_product.symlink_to(product, target_is_directory=True)

    with pytest.raises(module.DocumentationError, match="Symlink"):
        module.ComposeDocumentation(linked_product, api, output, "a" * 40)

    assert not output.exists(), "Symlink validation must leave output absent"


def test_ExistingOutputIsNeverReplaced(tmp_path: Path):
    """An existing artifact is retained byte for byte for safe rollback and review."""

    module = Composer()
    product, api, output = Artifacts(tmp_path)
    output.mkdir()
    (output / "retained.txt").write_text("Previous artifact", encoding="utf-8")

    with pytest.raises(module.DocumentationError, match="already exists"):
        module.ComposeDocumentation(product, api, output, "a" * 40)

    assert (output / "retained.txt").read_text() == "Previous artifact", (
        "A refused replacement must preserve the previous artifact"
    )


def test_PublicationFailureRemovesOwnedPartialOutput(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A filesystem failure during final publication rolls back only newly owned output."""

    module = Composer()
    product, api, output = Artifacts(tmp_path)
    original_rename = Path.rename
    calls = 0

    def FailSecondRename(self: Path, target: Path) -> Path:
        """Simulate one successful move followed by a failed filesystem operation."""

        nonlocal calls
        calls += 1

        if calls == 2:
            raise OSError("Synthetic publication failure")

        return original_rename(self, target)

    monkeypatch.setattr(Path, "rename", FailSecondRename)

    with pytest.raises(OSError, match="Synthetic publication failure"):
        module.ComposeDocumentation(product, api, output, "a" * 40)

    assert not output.exists(), "Failed publication must remove all newly owned partial output"
    assert not list(tmp_path.glob(".documentation-compose-*")), (
        "Failed publication must clean up its staging directory"
    )


def test_CliReportsCompositionValidationAndFailures(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    """The standalone CLI exposes deterministic JSON and a nonzero failure contract."""

    module = Composer()
    product, api, output = Artifacts(tmp_path)
    status = module.Main([
        "--product-site", str(product), "--api-root", str(api), "--output", str(output),
        "--revision", "a" * 40,
    ])
    assert status == 0, "Valid CLI composition must succeed"
    assert json.loads(capsys.readouterr().out)["schema_version"] == 1, (
        "CLI composition must emit machine-readable provenance"
    )
    assert module.Main(["--validate-only", str(output)]) == 0, (
        "Standalone validation must accept the composed artifact"
    )
    capsys.readouterr()
    (output / "api/latest/en/index.html").unlink()
    assert module.Main(["--validate-only", str(output)]) == 1, (
        "Standalone validation must return nonzero for an unresolved target"
    )
    assert "Missing link target" in capsys.readouterr().err, (
        "CLI failure must expose an actionable broken-link diagnostic"
    )


def test_ConcurrentDestinationCreationIsPreserved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Exclusive output reservation preserves output created by another producer."""

    module = Composer()
    product, api, output = Artifacts(tmp_path)
    original_validate = module.ValidateLinks

    def CreateOtherOutput(site_root: Path, base_path: str) -> dict[str, int]:
        """Create a competing artifact after validation but before output reservation."""

        counts = original_validate(site_root, base_path)
        output.mkdir()
        (output / "other-producer.txt").write_text("Keep this", encoding="utf-8")

        return counts

    monkeypatch.setattr(module, "ValidateLinks", CreateOtherOutput)

    with pytest.raises(FileExistsError):
        module.ComposeDocumentation(product, api, output, "a" * 40)

    assert (output / "other-producer.txt").read_text() == "Keep this", (
        "Concurrent producer output must never be overwritten or removed"
    )


def test_SourceMutationDuringCopyFailsClosed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Publication inventory must exactly match the inspected immutable source inputs."""

    module = Composer()
    product, api, output = Artifacts(tmp_path)
    original_copy = module.shutil.copytree
    changed = False

    def MutateBeforeCopy(
        source: Path, destination: Path, *arguments: object, **kwargs: object
    ) -> Path:
        """Alter the product after inventory but before its first staging copy."""

        nonlocal changed

        if source == product and not changed:
            changed = True
            (product / "changed.txt").write_text("Changed source", encoding="utf-8")

        return original_copy(source, destination, *arguments, **kwargs)

    monkeypatch.setattr(module.shutil, "copytree", MutateBeforeCopy)

    with pytest.raises(module.DocumentationError, match="changed while"):
        module.ComposeDocumentation(product, api, output, "a" * 40)

    assert not output.exists(), "Changing inputs must not produce misleading provenance"


def test_ParserAndUrlSchemesRespectExternalContracts(tmp_path: Path):
    """HTML callbacks, canonical-host URLs, and non-HTML fragments resolve consistently."""

    module = Composer()
    product, api, output = Artifacts(tmp_path)
    (product / "index.html").write_text(
        '<h1 id="vision">Vision</h1><a name="legacy"></a><a href="#legacy">Legacy</a>'
        '<a href="//FUZZY-TECHNOLOGIES.GITHUB.IO/1337/api/latest/en/#reference">API</a>'
        '<img src="api/latest/en/assets/brand.svg#symbol"/><img disabled>'
        '<a href="mailto:help@example.invalid">Mail</a>'
        '<a href="https://fuzzy-technologies.github.io/FuzzyRoutines/">Other project</a>',
        encoding="utf-8",
    )
    manifest = module.ComposeDocumentation(product, api, output, "a" * 40)
    assert manifest["validation"]["external_references"] == 2, (
        "Other project URLs and mail links must remain external while local host is validated"
    )

    with pytest.raises(module.DocumentationError, match="Unsupported URL scheme"):
        module.LinkTarget(output, output / "index.html", "ftp://example.invalid/file", "/1337")

    with pytest.raises(module.DocumentationError, match="Unsupported URL scheme"):
        module.LinkTarget(
            output, output / "index.html",
            "javascript://fuzzy-technologies.github.io/1337/index.html", "/1337",
        )


@pytest.mark.parametrize("relative", [
    "exposed.py", "source.md", "package.whl", "settings.toml", "static/source.js.map",
    ".env", "unknown.binary", "contracts/schema.json", "credentials/token.txt",
])
def test_ArtifactAllowlistRejectsPrivateOrUnknownFiles(tmp_path: Path, relative: str):
    """Public composition rejects sources, packages, hidden state, and unknown assets."""

    module = Composer()
    product, api, output = Artifacts(tmp_path)
    leaked = api / "en" / relative
    leaked.parent.mkdir(parents=True, exist_ok=True)
    leaked.write_text("Synthetic forbidden artifact", encoding="utf-8")

    with pytest.raises(module.DocumentationError, match="prohibited|Unsupported public"):
        module.ComposeDocumentation(product, api, output, "a" * 40)

    assert not output.exists(), "Artifact allowlist failure must prevent output publication"


def test_AllowedArtifactAssetsAndPagesMarkersRemainIntact(tmp_path: Path):
    """Public image/font/search assets and recognized root markers survive assembly."""

    module = Composer()
    product, api, output = Artifacts(tmp_path)

    for relative in (".nojekyll", "CNAME", "static/app.css", "static/font.woff2", "search.json"):
        path = product / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("Synthetic public fixture", encoding="utf-8")

    module.ComposeDocumentation(product, api, output, "a" * 40)
    assert (output / ".nojekyll").exists(), "Composition must preserve the Pages processing marker"
    assert (output / "search.json").exists(), "Composition must preserve public search indexes"
