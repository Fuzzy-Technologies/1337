# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic composition, link, and failure-boundary tests."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import tarfile
from email.message import Message
from pathlib import Path
from types import ModuleType, SimpleNamespace

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


def VersionArtifact(parent: Path, version: str = "0.3.0", revision: str = "a" * 40) -> Path:
    """Create a closed independently inventoried immutable artifact with ordinary local links."""

    module = Composer()
    root = parent / version
    root.mkdir(parents=True)

    for locale in module.LOCALES:
        destination = root / locale
        destination.mkdir()
        (destination / "index.html").write_text(
            f'<h1 id="reference">Version {version}</h1><img src="brand.svg">'
            '<a href="../../../#vision">Product</a>', encoding="utf-8",
        )
        (destination / "brand.svg").write_text('<svg id="brand"/>', encoding="utf-8")

    files = module.Inventory(root)
    identity = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    record = {"schema_version": 1, "version": version, "revision": revision, "tree": "b" * 40,
              "base_path": "/1337", "locales": list(module.LOCALES), "source_date_epoch": 123,
              "files": files, "artifact_sha256": hashlib.sha256(identity).hexdigest()}
    (root / module.VERSION_PROVENANCE).write_text(json.dumps(record, sort_keys=True))
    return root


def VersionArchive(
    root: Path, output: Path, *, extra: tuple[str, bytes, bytes] | None = None,
) -> str:
    """Write a finite synthetic tar, optionally injecting one invalid original entry."""

    stream = io.BytesIO()

    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                raw = path.read_bytes()
                member = tarfile.TarInfo(f"{root.name}/{path.relative_to(root).as_posix()}")
                member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))

        if extra is not None:
            name, raw, kind = extra
            member = tarfile.TarInfo(name)
            member.type = kind
            member.linkname = "../../outside"
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))

    output.write_bytes(gzip.compress(stream.getvalue(), mtime=123))
    return hashlib.sha256(output.read_bytes()).hexdigest()


def test_CompositionRetainsOriginalPriorVersionBesideLatestAndNewVersion(tmp_path: Path) -> None:
    """A checksum-pinned previous release keeps its bytes while latest/current advance."""

    module = Composer()
    product, api, output = Artifacts(tmp_path)
    current = VersionArtifact(tmp_path / "current", "0.4.0")
    previous = VersionArtifact(tmp_path / "previous", "0.3.0", "c" * 40)
    archive = tmp_path / "old.tar.gz"
    digest = VersionArchive(previous, archive)
    manifest = module.ComposeDocumentation(
        product, api, output, "a" * 40, version_root=current,
        retained_archive=archive, retained_sha256=digest,
    )
    assert set(manifest["api_versions"]) == {"0.3.0", "0.4.0"}, (
        'Composition must retain both supplied immutable release API versions'
    )
    assert module.Inventory(output / "api/0.3.0") == module.Inventory(previous), (
        'The previous immutable API version must preserve every retained file byte'
    )
    assert module.Inventory(output / "api/0.4.0") == module.Inventory(current), (
        'The current immutable API version must preserve every supplied rendered file byte'
    )
    assert (output / "api/latest/en/index.html").read_bytes() == (
        api / "en/index.html"
    ).read_bytes(), (
        'The latest API route must use the separately supplied latest rendering'
    )
    assert manifest["api_versions"]["0.3.0"]["revision"] == "c" * 40, (
        'The retained prior API version must keep its original provenance revision'
    )


@pytest.mark.parametrize("changed", [False, True])
def test_SameVersionRequiresByteIdentityRatherThanReplacingHistory(tmp_path: Path, changed: bool):
    """A retained version may coincide only when its complete original bytes are identical."""

    module = Composer()
    product, api, output = Artifacts(tmp_path)
    current = VersionArtifact(tmp_path / "current")
    previous = VersionArtifact(tmp_path / "previous", revision=("c" if changed else "a") * 40)
    archive = tmp_path / "old.tar.gz"
    digest = VersionArchive(previous, archive)

    if changed:
        with pytest.raises(module.DocumentationError, match="cannot be replaced"):
            module.ComposeDocumentation(product, api, output, "a" * 40, version_root=current,
                                        retained_archive=archive, retained_sha256=digest)
        assert not output.exists(), (
            'Rejected immutable-version replacement must leave no partially composed output'
        )

    else:
        manifest = module.ComposeDocumentation(product, api, output, "a" * 40, version_root=current,
                                               retained_archive=archive, retained_sha256=digest)
        assert set(manifest["api_versions"]) == {"0.3.0"}, (
            'An identical retained archive must preserve exactly one immutable API version'
        )


@pytest.mark.parametrize("name,kind", [
    ("../outside.html", tarfile.REGTYPE), ("/outside.html", tarfile.REGTYPE),
    ("0.3.0/../outside.html", tarfile.REGTYPE), ("0.3.0/en/link", tarfile.SYMTYPE),
    ("0.3.0/en/link", tarfile.LNKTYPE), ("0.3.0/en/dir", tarfile.DIRTYPE),
    ("0.3.0/en/index.html", tarfile.REGTYPE), ("0.4.0/en/index.html", tarfile.REGTYPE),
    ("0.3.0/en/hidden\n.html", tarfile.REGTYPE), ("0.3.0/en\\outside.html", tarfile.REGTYPE),
])
def test_ClosedArchiveRejectsTraversalLinksDuplicatesAndUnexpectedVersions(
    tmp_path: Path, name: str, kind: bytes,
) -> None:
    """No archive entry can escape, alias another file or silently introduce another version."""

    module = Composer()
    version = VersionArtifact(tmp_path / "original")
    archive = tmp_path / "invalid.tar.gz"
    digest = VersionArchive(version, archive, extra=(name, b"changed", kind))
    destination = tmp_path / "restored"

    with pytest.raises((module.DocumentationError, ValueError)):
        module.ExtractVersionArchive(archive, digest, destination)

    assert not destination.exists() and not (tmp_path / "outside.html").exists(), (
        'Rejected archive paths must create neither a restore root nor an escaped outside file'
    )


@pytest.mark.parametrize("mode", ["checksum", "compressed", "expanded", "files",
                                  "missing-locale", "corrupt-source", "bad-metadata"])
def test_ArchiveQuotaIntegrityAndMetadataFailuresWithholdDestination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str,
) -> None:
    """Bounds and original source/provenance corruption fail before a retained tree is published."""

    module = Composer()
    root = VersionArtifact(tmp_path / "original")

    if mode == "missing-locale":
        (root / "zh-cn/index.html").unlink()
    elif mode == "corrupt-source":
        (root / "en/index.html").write_text("changed")
    elif mode == "bad-metadata":
        (root / module.VERSION_PROVENANCE).write_text("[]")

    archive = tmp_path / "input.tar.gz"
    digest = VersionArchive(root, archive)

    if mode == "checksum":
        digest = "0" * 64
    elif mode in {"compressed", "expanded", "files"}:
        field = {"compressed": "MAX_API_ARCHIVE_BYTES", "expanded": "MAX_API_EXPANDED_BYTES",
                 "files": "MAX_API_ARCHIVE_FILES"}[mode]
        monkeypatch.setattr(module, field, 1)

    with pytest.raises(module.DocumentationError):
        module.ExtractVersionArchive(archive, digest, tmp_path / "restored")

    assert not (tmp_path / "restored").exists(), (
        'Rejected version archive provenance must prevent creation of a restored output root'
    )


def test_CurrentVersionMutationAndWrongPublicationBasisCannotPass(tmp_path: Path, monkeypatch):
    """Current source bindings and copied bytes must both match the preverified version input."""

    module = Composer()
    product, api, output = Artifacts(tmp_path)
    current = VersionArtifact(tmp_path / "current")

    with pytest.raises(module.DocumentationError, match="publication revision"):
        module.ComposeDocumentation(product, api, output, "d" * 40, version_root=current)

    with pytest.raises(module.DocumentationError, match="/1337 mount"):
        module.ComposeDocumentation(product, api, output, "a" * 40, "/", version_root=current)

    original = module.shutil.copytree

    def Mutate(source: Path, destination: Path, *arguments: object, **kwargs: object) -> Path:
        """Change a verified version source between its inventory and staging copy."""

        if source == current:
            (current / "en/index.html").write_text("changed after verification")

        return original(source, destination, *arguments, **kwargs)

    monkeypatch.setattr(module.shutil, "copytree", Mutate)

    with pytest.raises(module.DocumentationError, match="changed while"):
        module.ComposeDocumentation(product, api, output, "a" * 40, version_root=current)

    assert not output.exists(), (
        'Rejected retained API inputs must leave no partially published composed site'
    )


def TransferManifest(root: Path, archive: Path, destination: Path) -> dict:
    """Bind the exact synthetic master archive to its selected source identities."""

    provenance = json.loads((root / "api-version-provenance.json").read_bytes())
    transfer = {"schema_version": 1, "filename": archive.name,
                "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "size_bytes": archive.stat().st_size,
                **{key: provenance[key] for key in (
                    "version", "revision", "tree", "base_path", "locales", "source_date_epoch",
                )}, "provenance_sha256": hashlib.sha256(
                    (root / "api-version-provenance.json").read_bytes()).hexdigest()}
    destination.write_text(json.dumps(transfer))
    return transfer


@pytest.mark.parametrize("field", [None, "filename", "sha256", "size_bytes", "version",
                                   "revision", "tree", "base_path", "locales",
                                   "source_date_epoch", "provenance_sha256", "unknown"])
def test_ReleaseTransferRequiresExactSelectedTagOrMasterRunIdentity(
    tmp_path: Path, field: str | None,
) -> None:
    """Only the original archive bound to an independently selected source may enter a release."""

    module = Composer()
    root = VersionArtifact(tmp_path / "original")
    archive = tmp_path / "1337-0.3.0-api-docs.tar.gz"
    VersionArchive(root, archive)
    transfer_path = tmp_path / "transfer.json"
    transfer = TransferManifest(root, archive, transfer_path)

    if field is not None:
        transfer[field] = "changed"
        transfer_path.write_text(json.dumps(transfer))

        with pytest.raises(module.DocumentationError):
            module.VerifyVersionTransfer(archive, transfer_path, "a" * 40, "b" * 40, "0.3.0", 123)

    else:
        assert module.VerifyVersionTransfer(
            archive, transfer_path, "a" * 40, "b" * 40, "0.3.0", 123,
        ) == transfer, (
            'Valid transfer verification must return the exact independently bound original '
            'manifest'
        )


@pytest.mark.parametrize("body", [b"not-json", b"\xff", b"[]"])
def test_MalformedTransferManifestReturnsSafeNonzeroCliResult(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], body: bytes,
) -> None:
    """Malformed retained metadata must not escape the documented standalone validation CLI."""

    module = Composer()
    root = VersionArtifact(tmp_path / "original")
    archive = tmp_path / "1337-0.3.0-api-docs.tar.gz"
    VersionArchive(root, archive)
    transfer = tmp_path / "transfer.json"
    transfer.write_bytes(body)
    assert module.Main([
        "--verify-version-archive", str(archive), "--archive-manifest", str(transfer),
        "--expected-revision", "a" * 40, "--expected-tree", "b" * 40,
        "--expected-version", "0.3.0", "--expected-epoch", "123",
    ]) == 1, (
        'The archive verification CLI must return failure for the mismatched original source '
        'binding'
    )
    assert "Documentation validation failed" in capsys.readouterr().err, (
        'Failed archive verification must retain an actionable documentation validation diagnostic'
    )


@pytest.mark.parametrize("url", ["http://api.github.com/repos/Fuzzy-Technologies/1337/git/ref/tags/v0.3.0",
    "https://evil.invalid/metadata", "https://user@api.github.com/repos/Fuzzy-Technologies/1337",
    "https://api.github.com:443/repos/Fuzzy-Technologies/1337/git/ref/tags/v0.3.0",
    "https://api.github.com/repos/other/1337/git/ref/tags/v0.3.0",
    "https://api.github.com/repos/Fuzzy-Technologies/1337/git/ref/tags/v0.3.1"])
def test_RetainedAcquisitionCannotChooseAnotherSource(url):
    """Fixed release metadata cannot turn the internal reader into an arbitrary HTTP client."""

    module = Composer()

    with pytest.raises(module.DocumentationError):
        module.ReleaseSource("metadata", url)


@pytest.mark.parametrize("declared", [True, False])
def test_OriginalHttpBodyCapAppliesBeforePersistenceAndAdmission(monkeypatch, declared):
    """Announced oversize refuses before reads; growing bodies stop at the actual byte cap."""

    module = Composer()
    monkeypatch.setattr(module, "MAX_RELEASE_METADATA_BYTES", 3)
    headers = Message()

    if declared:
        headers["Content-Length"] = "4"

    reads = []

    class Response(io.BytesIO):
        """Expose original bounded synthetic bytes and count actual read requests."""

        code = 200

        def Read(self, maximum=-1):
            """Return the original over-limit chunk instead of trusting Content-Length."""

            reads.append(maximum)

            return super().read(maximum)

        read = Read

    response = Response(b"over")
    response.headers = headers
    opener = SimpleNamespace(open=lambda request, timeout: response)
    monkeypatch.setattr(module.urllib.request, "build_opener", lambda *args: opener)

    with pytest.raises(module.DocumentationError, match="limit"):
        module.ReadReleaseHttp("metadata", module.RELEASE_API + "/git/ref/tags/v0.3.0", 1, None)

    assert reads == ([] if declared else [64 * 1024]), (
        "An unannounced over-limit chunk must refuse before any body can be returned or written"
    )


@pytest.mark.parametrize("kind", ["metadata", "archive"])
@pytest.mark.parametrize("token", ["ghs_synthetic", "opaque-header.payload-signature.tail",
                                  "A-._~+/9==", "a" * 1024, "a" + "=" * 1023])
def test_OriginalHttpCredentialsNeverReachAssetOrRedirectRequests(monkeypatch, kind, token):
    """The original API token stays in API headers and automatic redirects remain disabled."""

    module = Composer()
    requests = []

    class Response(io.BytesIO):
        """Provide an inert successful original body with ordinary HTTP headers."""

        code = 200
        headers = Message()

    def Open(request, timeout):
        """Observe only the exact prevalidated synthetic request without connecting."""

        requests.append(request)

        return Response(b"ok")

    monkeypatch.setattr(module.urllib.request, "build_opener",
                        lambda *args: SimpleNamespace(open=Open))
    url = module.RELEASE_API + "/git/ref/tags/v0.3.0" if kind == "metadata" else (
        module.RELEASE_DOWNLOAD + module.RELEASE_ARCHIVE)
    assert module.ReadReleaseHttp(kind, url, 1, token) == (200, None, b"ok"), (
        'The bounded release reader must return the original admitted HTTP status and body'
    )
    assert requests[0].get_header("Authorization") == (
        "Bearer " + token if kind == "metadata" else None
    ), "Public asset requests must contain no inherited GitHub credential"
    assert module.NoReleaseRedirect().RedirectRequest(None, None, 302, None, None, None) is None, (
        'The release HTTP handler must refuse implicit redirects that could forward credentials'
    )


@pytest.mark.parametrize("mode", ["timeout", "late", "oversize", "unknown", "bad-json",
                                  "metadata-redirect", "foreign-redirect", "redirect-loop"])
def test_OwnedHttpChildRefusesDeadlineOverflowAndUnselectedRedirect(monkeypatch, mode):
    """A killable original child has per-call and overall deadlines plus closed framed output."""

    module = Composer()
    clock = [0.0]
    calls = []
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(module, "MAX_RELEASE_METADATA_BYTES", 3)

    def Run(argv, **options):
        """Supply explicit subprocess observations while preserving the actual timeout contract."""

        control = json.loads(options["input"])
        calls.append(control)
        assert argv[-1] == "--version-fetch-worker" and argv[1] == "-I", (
            'Release HTTP acquisition must use the isolated bounded worker entry point'
        )
        assert "ghs_synthetic" not in repr(argv) and "GH_TOKEN" not in options["env"], (
            'The release worker must receive no credential in its command line or inherited '
            'token environment'
        )
        assert 0 < options["timeout"] <= 30, "Each HTTP child needs a bounded wall deadline"

        if mode == "timeout":
            raise module.subprocess.TimeoutExpired(argv, options["timeout"])

        if mode == "late":
            clock[0] = 31.0

        status = 302 if "redirect" in mode else 200
        location = "https://evil.invalid/unselected" if mode == "foreign-redirect" else (
            "https://release-assets.githubusercontent.com/github-production-release-asset/1/a")
        body = b"over" if mode == "oversize" else b"ok"
        header = {"status": status, "location": location if status == 302 else None}
        output = b"not-json\n" if mode == "bad-json" else json.dumps(header).encode() + b"\n" + body

        return SimpleNamespace(returncode=1 if mode == "unknown" else 0, stdout=output)

    monkeypatch.setattr(module.subprocess, "run", Run)
    kind = "archive" if mode in {"foreign-redirect", "redirect-loop"} else "metadata"
    url = module.RELEASE_DOWNLOAD + module.RELEASE_ARCHIVE if kind == "archive" else (
        module.RELEASE_API + "/git/ref/tags/v0.3.0")

    with pytest.raises(module.DocumentationError):
        module.FetchRelease(kind, url, 120, "ghs_synthetic")

    assert len(calls) <= 4, "Redirects cannot replenish the original finite acquisition allowance"


def RetainedFixture(tmp_path, module):
    """Provide real closed archive bytes and independently declared fixed GitHub observations."""

    original = VersionArtifact(tmp_path / "original")
    archive = tmp_path / module.RELEASE_ARCHIVE
    VersionArchive(original, archive)
    transfer = tmp_path / module.RELEASE_TRANSFER
    TransferManifest(original, archive, transfer)
    root = tmp_path / "project"
    (root / "_build/docs").mkdir(parents=True)
    (root / "pyproject.toml").write_text('[project]\nversion = "0.3.0"\n', encoding="utf-8")
    bodies = {module.RELEASE_ARCHIVE: archive.read_bytes(),
              module.RELEASE_TRANSFER: transfer.read_bytes()}
    metadata = {
        "/git/ref/tags/v0.3.0": {"ref": "refs/tags/v0.3.0",
                                  "object": {"type": "commit", "sha": "a" * 40}},
        "/git/commits/" + "a" * 40: {"sha": "a" * 40, "tree": {"sha": "b" * 40},
            "committer": {"date": "1970-01-01T00:02:03Z"}},
        "/releases/tags/v0.3.0": {"tag_name": "v0.3.0", "draft": False, "prerelease": False,
            "html_url": "https://github.com/Fuzzy-Technologies/1337/releases/tag/v0.3.0",
            "assets": [{"name": name, "size": len(body), "state": "uploaded",
                        "browser_download_url": module.RELEASE_DOWNLOAD + name}
                       for name, body in bodies.items()]},
    }

    return root, metadata, bodies


@pytest.mark.parametrize("attack", [None, "ref", "commit", "tree", "date", "release", "draft",
    "source", "declared-size", "duplicate", "missing", "actual-size", "overall"])
def test_OnlyVerifiedExactReleaseAssetsEnterRetainedPublication(tmp_path, monkeypatch, attack):
    """Changed metadata/body/source or elapsed overall budget withholds retained publication."""

    module = Composer()
    root, metadata, bodies = RetainedFixture(tmp_path, module)
    release = metadata["/releases/tags/v0.3.0"]
    commit = metadata["/git/commits/" + "a" * 40]

    if attack == "ref":
        metadata["/git/ref/tags/v0.3.0"]["ref"] = "refs/tags/v0.3.1"
    elif attack == "commit":
        commit["sha"] = "c" * 40
    elif attack == "tree":
        commit["tree"] = None
    elif attack == "date":
        commit["committer"]["date"] = "1970-01-01T00:02:03"
    elif attack == "release":
        release["tag_name"] = "v0.3.1"
    elif attack == "draft":
        release["draft"] = True
    elif attack == "source":
        release["assets"][0]["browser_download_url"] = "https://evil.invalid/asset"
    elif attack == "declared-size":
        release["assets"][0]["size"] = module.MAX_API_ARCHIVE_BYTES + 1
    elif attack == "duplicate":
        release["assets"].append(release["assets"][0])
    elif attack == "missing":
        release["assets"] = []
    elif attack == "actual-size":
        bodies[module.RELEASE_ARCHIVE] += b"changed"

    calls = []
    clock = [0.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])

    def Fetch(kind, url, deadline, token=None):
        """Return original inert source observations without reading any live endpoint."""

        calls.append((kind, url))

        if kind == "metadata":
            return 200, json.dumps(metadata[url.removeprefix(module.RELEASE_API)]).encode()

        if attack == "overall":
            clock[0] = 121.0

        return 200, bodies[url.removeprefix(module.RELEASE_DOWNLOAD)]

    monkeypatch.setattr(module, "FetchRelease", Fetch)

    if attack is None:
        result = module.SelectVersionSource(root)
        assert not result["release_version"] and result["retained_sha256"] == hashlib.sha256(
            bodies[module.RELEASE_ARCHIVE]).hexdigest(), (
            'An existing release must retain the independently hashed original archive instead '
            'of rerendering'
        )
        assert (root / result["retained_archive"]).read_bytes() == bodies[module.RELEASE_ARCHIVE], (
            'The retained release archive must preserve the downloaded original bytes'
        )

    else:
        with pytest.raises(module.DocumentationError):
            module.SelectVersionSource(root)

        assert not (root / "_build/docs/retained-api").exists(), (
            "A refused original source must leave no canonical retained publication"
        )


@pytest.mark.parametrize("mode", ["legacy", "absent", "broken", "missing-release"])
def test_OnlyOriginalTagNotFoundCanSelectInitialGeneration(tmp_path, monkeypatch, mode):
    """Older versions make no GitHub call; failed queries/assets never regenerate history."""

    module = Composer()
    root, metadata, bodies = RetainedFixture(tmp_path, module)
    calls = []

    if mode == "legacy":
        (root / "pyproject.toml").write_text('[project]\nversion = "0.2.1"\n', encoding="utf-8")

    def Fetch(kind, url, deadline, token=None):
        """Provide independent original statuses and reject undeclared source expansion."""

        calls.append(url)

        if mode == "absent":
            return 404, b"Not Found"

        if mode == "missing-release" and url.endswith("/git/ref/tags/v0.3.0"):
            return 200, json.dumps(metadata["/git/ref/tags/v0.3.0"]).encode()

        return 503, b"Unavailable"

    monkeypatch.setattr(module, "FetchRelease", Fetch)

    if mode in {"legacy", "absent"}:
        result = module.SelectVersionSource(root)
        assert result["release_version"] == ("0.3.0" if mode == "absent" else ""), (
            'Only an absent release tag may select a fresh versioned API rendering'
        )
        assert len(calls) == (1 if mode == "absent" else 0), (
            'Absent and legacy version selection must perform only their declared bounded '
            'metadata reads'
        )

    else:
        with pytest.raises(module.DocumentationError):
            module.SelectVersionSource(root)

    assert not (root / "_build/docs/retained-api").exists(), (
        'Rejected release acquisition must leave no apparently accepted retained API directory'
    )


def test_OriginalHttpDeadlineActuallyTerminatesAnInertOwnedChild(monkeypatch):
    """An actual waiting child cannot extend the original HTTP-call wall deadline."""

    module = Composer()
    original = module.subprocess.run
    monkeypatch.setattr(module, "RELEASE_CALL_SECONDS", 0.02)

    def Run(argv, **options):
        """Substitute an inert waiting producer while retaining real timeout ownership."""

        return original([module.sys.executable, "-I", "-c", "import time; time.sleep(2)"],
                        **options)

    monkeypatch.setattr(module.subprocess, "run", Run)
    started = module.time.monotonic()

    with pytest.raises(module.DocumentationError, match="deadline"):
        module.FetchRelease("metadata", module.RELEASE_API + "/git/ref/tags/v0.3.0", started + 120)

    assert module.time.monotonic() - started < 1, "Actual child settlement must remain finite"


def test_OriginalWorkerFramingAndPrivateCredentialTransport(monkeypatch):
    """The real framed worker receives bounded private control and returns only original bytes."""

    module = Composer()
    url = module.RELEASE_API + "/git/ref/tags/v0.3.0"
    control = {"kind": "metadata", "url": url, "timeout_seconds": 1, "token": "ghs_synthetic"}
    stdout = io.BytesIO()
    encoded = io.BytesIO(json.dumps(control).encode())
    monkeypatch.setattr(module.sys, "stdin", SimpleNamespace(buffer=encoded))
    monkeypatch.setattr(module.sys, "stdout", SimpleNamespace(buffer=stdout))
    monkeypatch.setattr(module, "ReadReleaseHttp", lambda **values: (200, None, b"original"))
    assert module.ReleaseWorker() == 0, (
        'An admitted worker response must complete its bounded framed protocol successfully'
    )
    header, _, raw = stdout.getvalue().partition(b"\n")
    assert json.loads(header) == {"status": 200, "location": None} and raw == b"original", (
        'The worker frame must preserve the original response metadata and exact body bytes'
    )
    assert b"ghs_synthetic" not in stdout.getvalue(), "Credential cannot enter response bytes"


@pytest.mark.parametrize("control", [b"not-json", b"[]", b'{"unexpected":"field"}'])
def test_MalformedOriginalWorkerControlReturnsNoBytes(monkeypatch, control):
    """Malformed private control cannot start a provider read or emit partial response evidence."""

    module = Composer()
    output = io.BytesIO()
    monkeypatch.setattr(module.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(control)))
    monkeypatch.setattr(module.sys, "stdout", SimpleNamespace(buffer=output))
    assert module.ReleaseWorker() == 1 and output.getvalue() == b"", (
        'A refused release worker must return failure without publishing a partial output frame'
    )


@pytest.mark.parametrize("token", ["ghs_synthetic", "opaque-header.payload-signature.tail",
                                  "A-._~+/9==", "a" * 1024, "a" + "=" * 1023])
@pytest.mark.parametrize("kind", ["metadata", "archive"])
def test_ValidatedChildSuccessRetainsOriginalStatusAndBody(monkeypatch, token, kind):
    """A successful framed original response keeps finite deadlines and API token off argv/env."""

    module = Composer()
    calls = []

    def Run(argv, **options):
        """Observe the actual private original-control serialization without executing HTTP."""

        calls.append(json.loads(options["input"]))
        assert token not in repr(argv) and set(options["env"]) == {"PATH", "LANG", "LC_ALL"}, (
            'The isolated release worker must not expose its credential through argv or ambient '
            'environment'
        )

        return SimpleNamespace(returncode=0,
            stdout=json.dumps({"status": 200, "location": None}).encode() + b"\noriginal")

    monkeypatch.setattr(module.subprocess, "run", Run)
    url = module.RELEASE_API + "/git/ref/tags/v0.3.0" if kind == "metadata" else (
        module.RELEASE_DOWNLOAD + module.RELEASE_ARCHIVE)
    status, raw = module.FetchRelease(kind, url, module.time.monotonic() + 120, token)
    assert (status, raw) == (200, b"original") and calls[0]["token"] == (
        token if kind == "metadata" else None
    ), (
        'The worker must preserve the original successful body and receive only the explicit '
        'private credential'
    )


@pytest.mark.parametrize("token", ["", "=", "==", "a=b", "a==b", "a b", " a", "a ",
                                  "a\r\nb", "a\tb", "é", "a\u00a0b", "a" * 1025,
                                  "a" + "=" * 1024,
                                  *("a" + chr(code) + "b" for code in range(33)),
                                  "a\x7fb", 1, b"opaque"])
@pytest.mark.parametrize("boundary", ["reader", "parent"])
def test_InvalidBearerEnvelopeRefusesBeforeAnyHttpOrChild(monkeypatch, token, boundary):
    """Whitespace, controls, non-ASCII and misplaced padding cannot reach a transport seam."""

    module = Composer()
    url = module.RELEASE_API + "/git/ref/tags/v0.3.0"

    def Unexpected(*args, **kwargs):
        """Detect an attempted network opener or child before invalid control is refused."""

        pytest.fail("Invalid Bearer syntax must refuse before HTTP or child construction")

    monkeypatch.setattr(module.urllib.request, "build_opener", Unexpected)
    monkeypatch.setattr(module.subprocess, "run", Unexpected)

    with pytest.raises(module.DocumentationError, match="credential syntax"):
        if boundary == "reader":
            module.ReadReleaseHttp("metadata", url, 1, token)

        else:
            module.FetchRelease("metadata", url, module.time.monotonic() + 120, token)
