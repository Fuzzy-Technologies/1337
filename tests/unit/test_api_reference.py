# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify static API inventory and generated-output fail-closed boundaries."""

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "api_reference", ROOT / "tools/build_api_reference.py"
)
assert SPEC is not None and SPEC.loader is not None, "API reference builder must be loadable"
API = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(API)


def SmallProject(parent: Path) -> tuple[Path, Path]:
    """Create a minimal static source and matching installed-wheel layout fixture."""

    root = parent / "project"
    installed = parent / "installed"
    source = root / "src/docfixture/__init__.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        '\"\"\"Static fixture that rejects runtime imports.\"\"\"\n\n'
        'raise RuntimeError("Security runtime must never execute")\n\n'
        'def Execute(value: int) -> int:\n'
        '    \"\"\"Return the documented input value.\"\"\"\n\n'
        '    return value\n'
    )
    (installed / "docfixture").mkdir(parents=True)
    shutil.copyfile(source, installed / "docfixture/__init__.py")
    (installed / "1337-1.0.dist-info").mkdir()
    docs = root / "docs"
    (docs / "i18n").mkdir(parents=True)
    content = docs / "site/content/en"
    (content / "assets/mathjax").mkdir(parents=True)
    (content / "index.md").write_text("# Static fixture\n\n$value$\n")
    (content / "api.md").write_text("# Fixture contract\n\n::: docfixture\n")
    (content / "assets/mathjax/tex-mml-svg.js").write_text("/* Formula renderer fixture. */\n")
    (docs / "i18n/project.toml").write_text(
        'packageNames = ["docfixture"]\ncontentRoot = "docs/site/content"\n'
        'unitManifest = "docs/i18n/units.toml"\nbuildRoot = "_build/docs"\n'
        'apiCoverageManifest = "docs/site/api-coverage.toml"\n'
        'publicationPath = "/1337"\nlocales = ["en", "ru", "zh-cn"]\n'
    )
    (docs / "site/api-coverage.toml").write_text(
        '[[surfaces]]\nmodule = "docfixture"\nsource = "src/docfixture/__init__.py"\n'
        'mode = "authored"\npage = "api.md"\n'
    )
    (docs / "i18n/units.toml").write_text(
        '[[units]]\nid = "symbol:docfixture.Execute"\nkind = "symbol"\n'
        'sourcePath = "src/docfixture/__init__.py"\n'
        '[units.translations.ru]\nstate = "missing"\n'
        '[units.translations.zh-cn]\nstate = "missing"\n'
    )
    shutil.copyfile(ROOT / "docs/site/mkdocs.yml", docs / "site/mkdocs.yml")

    return root, installed


@pytest.mark.parametrize("mutation,diagnostic", (
    ('mode = "authored"', "static authored/exports mode"),
    ('module = "docfixture"', "declared package"),
    ('page = "api.md"', "document the declared module"),
))
def test_InvalidInventoryContractsAreRejected(
    tmp_path: Path, mutation: str, diagnostic: str
) -> None:
    """Reject unsupported discovery, foreign ownership, and absent authored pages."""

    root, _ = SmallProject(tmp_path)
    manifest = root / "docs/site/api-coverage.toml"
    replacement = {
        'mode = "authored"': 'mode = "inspection"',
        'module = "docfixture"': 'module = "foreignpackage"',
        'page = "api.md"': 'page = "missing.md"',
    }[mutation]
    manifest.write_text(manifest.read_text().replace(mutation, replacement))

    with pytest.raises(ValueError, match=diagnostic):
        API.ValidateInventory(root, API.ReadManifest(root))


@pytest.mark.parametrize("relative", (
    "", "../outside", "/outside", "docs\\unsafe.toml", "C:/outside", "C:outside",
    "//server/outside",
))
def test_LocalInputsRejectAbsoluteTraversalAndForeignSeparators(
    tmp_path: Path, relative: str
) -> None:
    """Reject path syntax that can escape or change meaning across operating systems."""

    with pytest.raises(ValueError, match="project-relative"):
        API.LocalInput(tmp_path, relative)


def test_LocalInputsRejectSymlinkComponents(tmp_path: Path) -> None:
    """Reject indirect paths even when the symlink points back inside the checkout."""

    if sys.platform == "win32":
        pytest.skip("Creating symbolic links requires elevated Windows permission")

    root = tmp_path / "project"
    root.mkdir()
    (root / "contained").mkdir()
    (root / "internal-link").symlink_to(root / "contained", target_is_directory=True)

    with pytest.raises(ValueError, match="cannot follow symlinks"):
        API.LocalInput(root, "internal-link/page.md")

    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "external-link").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="escapes the project"):
        API.LocalInput(root, "external-link/page.md")


def test_ManifestRejectsUnsafeFieldsAndGlossaryPaths(tmp_path: Path) -> None:
    """Reject both standard manifest paths and localized glossary paths outside the checkout."""

    root, _ = SmallProject(tmp_path)
    manifest = root / "docs/i18n/project.toml"
    original = manifest.read_text()
    manifest.write_text(original.replace('buildRoot = "_build/docs"', 'buildRoot = "../outside"'))

    with pytest.raises(ValueError, match="project-relative"):
        API.ReadManifest(root)

    manifest.write_text(original + '\n[glossaries]\nru = "../outside.toml"\n')

    with pytest.raises(ValueError, match="project-relative"):
        API.ReadManifest(root)


def test_InventoryRejectsUnsafeAuthoredPagePath(tmp_path: Path) -> None:
    """Do not follow page paths that escape the canonical content root."""

    root, _ = SmallProject(tmp_path)
    manifest = root / "docs/site/api-coverage.toml"
    manifest.write_text(manifest.read_text().replace('page = "api.md"', 'page = "../api.md"'))

    with pytest.raises(ValueError, match="project-relative"):
        API.ValidateInventory(root, API.ReadManifest(root))


def test_MissingCanonicalUnitManifestFailsClosed(tmp_path: Path) -> None:
    """Require canonical locale inventory before discovering or publishing API symbols."""

    root, _ = SmallProject(tmp_path)
    (root / "docs/i18n/units.toml").unlink()

    with pytest.raises(FileNotFoundError):
        API.ValidateInventory(root, API.ReadManifest(root))


def test_InventoryRejectsDuplicateAndUnexplainedExclusions(tmp_path: Path) -> None:
    """Prevent duplicate source ownership and exclusions that hide undocumented modules."""

    root, _ = SmallProject(tmp_path)
    manifest = root / "docs/site/api-coverage.toml"
    original = manifest.read_text()
    manifest.write_text(original + "\n" + original)

    with pytest.raises(ValueError, match="every source module exactly once"):
        API.ValidateInventory(root, API.ReadManifest(root))

    manifest.write_text(
        '[[moduleExclusions]]\nsource = "src/docfixture/__init__.py"\nreason = ""\n'
    )

    with pytest.raises(ValueError, match="explicit reason"):
        API.ValidateInventory(root, API.ReadManifest(root))

    manifest.write_text(manifest.read_text().replace(
        'reason = ""', 'reason = "Executable wrapper"'
    ))

    assert API.ValidateInventory(root, API.ReadManifest(root)) == [], (
        "An explained exclusion must remain an explicit reviewed manifest decision"
    )


def test_OutputRequiresSearchAndModuleAnchors(tmp_path: Path) -> None:
    """Require the search artifact and declared module page before accepting a reference."""

    with pytest.raises(ValueError, match="missing the search index"):
        API.CheckOutput(tmp_path, [], "/1337/api/latest/en/")

    (tmp_path / "search").mkdir()
    (tmp_path / "search/search_index.json").write_text("{}")
    module = {"module": "docfixture", "page": "api.md", "symbols": []}

    with pytest.raises(ValueError, match="module anchor is missing"):
        API.CheckOutput(tmp_path, [module], "/1337/api/latest/en/")


def test_OutputRequiresSourceAndFormulaResources(tmp_path: Path) -> None:
    """Reject rendering configurations that suppress source contracts or formula resources."""

    (tmp_path / "search").mkdir()
    (tmp_path / "search/search_index.json").write_text("{}")
    (tmp_path / "api").mkdir()
    api_page = tmp_path / "api/index.html"
    api_page.write_text('<h1 id="docfixture">Fixture</h1>')
    (tmp_path / "index.html").write_text('<p class="arithmatex">Formula</p>')
    module = {"module": "docfixture", "page": "api.md", "symbols": []}

    with pytest.raises(ValueError, match="statically analyzed source blocks"):
        API.CheckOutput(tmp_path, [module], "/1337/api/latest/en/")

    api_page.write_text(api_page.read_text() + '<details class="mkdocstrings-source"></details>')

    with pytest.raises(ValueError, match="locally hosted SVG renderer"):
        API.CheckOutput(tmp_path, [module], "/1337/api/latest/en/")

    assets = tmp_path / "assets/mathjax"
    assets.mkdir(parents=True)
    (assets / "tex-mml-svg.js").write_text("/* Local resource fixture. */")

    assert API.CheckOutput(tmp_path, [module], "/1337/api/latest/en/")["pages"] == 2, (
        "All mandatory output resources must permit the generated reference"
    )


def test_OutputResolvesDirectoryAbsoluteAndExternalLinks(tmp_path: Path) -> None:
    """Resolve local cross-page links while ignoring external and product-site routes."""

    (tmp_path / "search").mkdir()
    (tmp_path / "search/search_index.json").write_text("{}")
    (tmp_path / "linked").mkdir()
    (tmp_path / "linked/index.html").write_text('<h1 id="target">Linked page</h1>')
    (tmp_path / "index.html").write_text(
        '<a href="linked/#target">Relative</a>'
        '<a href="/1337/api/latest/en/linked/#target">Absolute</a>'
        '<a href="https://example.invalid/">External</a>'
        '<a href="/1337/">Product site</a><img src="">'
    )

    assert API.CheckOutput(tmp_path, [], "/1337/api/latest/en/")["pages"] == 2, (
        "Relative and absolute reference links must resolve against the same output tree"
    )


def test_StaticRenderNeverImportsAndKeepsFallbackExplicit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Render actual Griffe reference pages from a small matching wheel-layout fixture."""

    pytest.importorskip("mkdocs", reason="Strict rendering requires the separate docs tooling lock")
    pytest.importorskip("mkdocstrings_handlers.python")
    root, installed = SmallProject(tmp_path)
    monkeypatch.setattr(sys, "meta_path", list(sys.meta_path))
    API.Render(root, installed)
    evidence = json.loads((root / "_build/docs/api-build.json").read_text())

    assert evidence["runtimeImported"] is False, "Import-raising fixture must remain unexecuted"
    assert set(evidence["locales"]) == {"en", "ru", "zh-cn"}, "All locale routes must be generated"

    for locale in ("ru", "zh-cn"):
        rendered = (root / f"_build/api-reference/{locale}/api/index.html").read_text()
        assert "English fallback" in rendered, "Missing translations must expose fallback visibly"
        assert "docfixture.Execute" in rendered, "Static renderer must expose public symbol anchors"


@pytest.mark.parametrize("condition", ("inside", "missing", "uninstalled"))
def test_RenderRejectsNonInstalledCheckoutSources(tmp_path: Path, condition: str) -> None:
    """Refuse source discovery from inside the checkout or uninstalled directories."""

    pytest.importorskip("mkdocs", reason="Strict rendering requires the separate docs tooling lock")
    root, installed = SmallProject(tmp_path)

    if condition == "inside":
        installed = root / "src"

    elif condition == "missing":
        installed = tmp_path / "absent"

    else:
        (installed / "1337-1.0.dist-info").rmdir()

    with pytest.raises(ValueError, match="clean installed 1337 wheel"):
        API.Render(root, installed)


@pytest.mark.parametrize("option,value", (
    ("allow_inspection", "true"),
    ("force_inspection", "true"),
    ("allow_inspection", "missing"),
    ("force_inspection", "missing"),
))
def test_RenderRequiresExplicitStaticInspectionContract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, option: str, value: str
) -> None:
    """Reject inspection-enabled and omitted options before invoking the static renderer."""

    pytest.importorskip("mkdocs", reason="Strict rendering requires the separate docs tooling lock")
    root, installed = SmallProject(tmp_path)
    config = root / "docs/site/mkdocs.yml"
    declaration = f"            {option}: false\n"
    replacement = f"            {option}: true\n" if value == "true" else ""
    config.write_text(config.read_text().replace(declaration, replacement))
    monkeypatch.setattr(sys, "meta_path", list(sys.meta_path))

    with pytest.raises(ValueError, match="explicitly disable both inspection options"):
        API.Render(root, installed)


def InitializeTrackedFixture(root: Path) -> None:
    """Commit controlled fixture inputs to bind reproducible rendering to Git time."""

    if shutil.which("git") is None:
        pytest.skip("Git is required to verify tracked-source immutability")

    subprocess.run(["git", "init", "--quiet", str(root)], check=True)
    subprocess.run(["git", "add", "src", "docs"], cwd=root, check=True)
    subprocess.run([
        "git", "-c", "user.name=Documentation Fixture", "-c", "user.email=fixture@example.invalid",
        "commit", "--quiet", "-m", "Controlled documentation inputs",
    ], cwd=root, check=True)


def test_TrackedSourceHashesDetectMutationAndSymlinks(tmp_path: Path) -> None:
    """Bind tracked inputs to bytes and refuse indirect paths outside the checkout."""

    root, _ = SmallProject(tmp_path)
    InitializeTrackedFixture(root)
    initial = API.TrackedSourceHashes(root)
    source = root / "src/docfixture/__init__.py"
    source.write_text(source.read_text() + "\n# Changed fixture contract.\n")

    assert API.TrackedSourceHashes(root) != initial, (
        "Tracked input edits must change source snapshots"
    )

    if sys.platform == "win32":
        return

    source.unlink()
    source.symlink_to(tmp_path / "outside.py")

    with pytest.raises(ValueError, match="stay within the checkout"):
        API.TrackedSourceHashes(root)


@pytest.mark.parametrize("arguments", (
    ["render"],
    ["build", "--root", "/nonexistent/documentation-fixture"],
))
def test_CommandLineErrorsReturnFailure(
    arguments: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Expose missing installation and absent checkout failures through the actual CLI parser."""

    monkeypatch.setattr(sys, "argv", ["build_api_reference.py", *arguments])

    assert API.Main() == 1, "CLI failures must return a nonzero status"
    assert capsys.readouterr().err.strip(), "CLI failures must retain actionable stderr diagnostics"


def test_ExternalDeadlineFailureReturnsNonzeroCliStatus(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Preserve an external-tool deadline failure rather than report successful documentation."""

    def DeadlineExceeded(arguments: list[str], **options: object) -> str:
        """Represent a Git snapshot operation exceeding its explicit external-process budget."""

        assert options["timeout"] == 30, "Git provenance reads require a bounded deadline"

        raise subprocess.TimeoutExpired(arguments, 30)

    monkeypatch.setattr(API.subprocess, "check_output", DeadlineExceeded)
    monkeypatch.setattr(sys, "argv", ["build_api_reference.py", "build", "--root", str(tmp_path)])

    assert API.Main() == 1, "A timed-out external tool must produce a nonzero CLI status"
    assert "timed out" in capsys.readouterr().err, "Timeout diagnostics must remain actionable"


def test_RenderCommandLineUsesInstalledFixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Execute the successful renderer CLI against real static documentation tooling."""

    pytest.importorskip("mkdocs", reason="Strict rendering requires the separate docs tooling lock")
    root, installed = SmallProject(tmp_path)
    monkeypatch.setattr(sys, "meta_path", list(sys.meta_path))
    monkeypatch.setattr(sys, "argv", [
        "build_api_reference.py", "render", "--root", str(root),
        "--installed-packages", str(installed),
    ])

    assert API.Main() == 0, "The strict installed-source renderer CLI must succeed"


def test_RenderRejectsAlreadyImportedRuntime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reject a contaminated renderer process even when static output itself is valid."""

    pytest.importorskip("mkdocs", reason="Strict rendering requires the separate docs tooling lock")
    root, installed = SmallProject(tmp_path)
    monkeypatch.setattr(sys, "meta_path", list(sys.meta_path))
    monkeypatch.setitem(sys.modules, "docfixture", importlib.util.module_from_spec(
        importlib.util.spec_from_loader("docfixture", loader=None)
    ))

    with pytest.raises(RuntimeError, match="was imported during documentation rendering"):
        API.Render(root, installed)


def test_BuildFailsWithoutLockedEnvironmentTool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail closed rather than degrade to an unlocked global documentation interpreter."""

    root, _ = SmallProject(tmp_path)
    InitializeTrackedFixture(root)
    (root / "tools").mkdir()
    (root / "tools/locale_documentation.py").write_text(
        '\"\"\"Successful validator process fixture.\"\"\"\n'
    )
    monkeypatch.setenv("PATH", str(Path(shutil.which("git")).parent))

    if shutil.which("uv") is not None:
        pytest.skip("Git and uv share one system tool directory")

    with pytest.raises(RuntimeError, match="requires uv"):
        API.Build(root)


def FakeBuildExecutables(directory: Path) -> Path:
    """Provide process-level uv/interpreter fixtures for deterministic build failure scenarios."""

    directory.mkdir()
    interpreter = directory / "fixture_interpreter.py"
    interpreter.write_text(
        f"#!{sys.executable}\n" + '''"""Emulate build boundaries without network imports."""

import json
import os
import sys
from pathlib import Path

arguments = sys.argv[1:]
mode = os.environ.get("DOCUMENTATION_FIXTURE_MODE", "success")

if arguments[:2] == ["-m", "build"] or arguments[0] == "-I" and arguments[1] != "-c":
    assert os.environ.get("SOURCE_DATE_EPOCH", "").isdigit(), "Build dates must be fixed"

if arguments[:2] == ["-m", "build"]:
    wheels = Path(arguments[arguments.index("--outdir") + 1])
    wheels.mkdir(parents=True)

    if mode != "missing-wheel":
        (wheels / "fixture.whl").write_bytes(b"controlled wheel fixture")

    if mode == "multiple-wheels":
        (wheels / "extra.whl").write_bytes(b"ambiguous wheel fixture")

elif arguments[:2] == ["-I", "-c"]:
    print(Path(sys.executable).parent / "installed")

else:
    root = Path(arguments[arguments.index("--root") + 1])
    evidence = root / "_build/docs/api-build.json"
    changed = evidence.exists() and mode == "nondeterministic"
    (root / "_build/api-reference").mkdir(parents=True)
    evidence.write_text(json.dumps({"locales": {"en": {"files": {"page": str(changed)}}}}))

    if mode == "source-mutated":
        source = root / "src/docfixture/__init__.py"
        source.write_text(source.read_text() + "\\n# Unauthorized mutation.\\n")
''')
    executable = directory / "uv"
    executable.write_text(
        f"#!{sys.executable}\n" + '''"""Emulate uv provisioning and record process contracts."""

import json
import os
import shutil
import sys
from pathlib import Path

arguments = sys.argv[1:]
receipt = Path(os.environ["DOCUMENTATION_FIXTURE_RECEIPTS"])

with receipt.open("a") as stream:
    stream.write(json.dumps(arguments) + "\\n")

if arguments[0] == "venv":
    environment = Path(arguments[-1])
    (environment / "bin").mkdir(parents=True)
    shutil.copyfile(Path(__file__).parent / "fixture_interpreter.py", environment / "bin/python")
    (environment / "bin/python").chmod(0o755)
''')
    executable.chmod(0o755)

    return executable


@pytest.mark.parametrize("mode,diagnostic", (
    ("success", ""),
    ("missing-wheel", "exactly one newly built wheel"),
    ("multiple-wheels", "exactly one newly built wheel"),
    ("nondeterministic", "different outputs"),
    ("source-mutated", "modified tracked source inputs"),
))
def test_ExternalBuildOrchestrationRejectsAmbiguousOrMutableResults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str, diagnostic: str
) -> None:
    """Exercise actual subprocess boundaries and fresh-build/source-integrity guards."""

    if sys.platform == "win32":
        pytest.skip("Process fixture uses POSIX executable scripts")

    root, _ = SmallProject(tmp_path)
    InitializeTrackedFixture(root)
    (root / "tools").mkdir()
    (root / "tools/locale_documentation.py").write_text(
        '\"\"\"Validator process fixture for build orchestration.\"\"\"\n'
    )
    fake_uv = FakeBuildExecutables(tmp_path / "executables")
    receipts = tmp_path / "receipts.jsonl"
    monkeypatch.setenv("PATH", str(fake_uv.parent) + ":" + str(Path(shutil.which("git")).parent))
    monkeypatch.setenv("DOCUMENTATION_FIXTURE_MODE", mode)
    monkeypatch.setenv("DOCUMENTATION_FIXTURE_RECEIPTS", str(receipts))

    if diagnostic:
        with pytest.raises((ValueError, RuntimeError), match=diagnostic):
            API.Build(root)

    else:
        API.Build(root)
        evidence = json.loads((root / "_build/docs/api-build.json").read_text())

        assert evidence["reproducible"] and evidence["sourceUnchanged"], (
            "Two fresh deterministic renders must preserve all tracked source bytes"
        )
        assert evidence["sourceDateEpoch"] > 0, "Render dates must bind the input commit"
        assert len(evidence["wheelSha256"]) == 64, "Build evidence must bind the produced wheel"
        calls = [json.loads(line) for line in receipts.read_text().splitlines()]

        assert "--require-hashes" in calls[1], "Documentation dependencies require hash enforcement"
        assert "--no-deps" in calls[2], "Wheel installation must never resolve runtime dependencies"
        assert not Path(calls[0][-1]).exists(), (
            "The outside-checkout environment must be cleaned up"
        )


def test_InventoryCoversEverySourceModule() -> None:
    """Require explicit classification of every first-party Python module."""

    surfaces = API.ValidateInventory(ROOT, API.ReadManifest(ROOT))

    source_paths = {path.relative_to(ROOT).as_posix() for path in (ROOT / "src").rglob("*.py")}
    assert {surface["source"] for surface in surfaces} == (
        source_paths - {"src/fuzzy1337/__main__.py"}
    ), "API inventory must cover all source modules and exclude only the CLI entry point"
    assert all(surface["mode"] == "authored" for surface in surfaces), (
        "Authored source owns canonical symbol documentation without duplicate package aliases"
    )


def test_NewModuleRequiresManifestDecision(tmp_path: Path) -> None:
    """Fail rather than silently omit a newly introduced API source module."""

    (tmp_path / "src/fuzzy1337").mkdir(parents=True)
    (tmp_path / "src/fuzzy1337/new.py").write_text('"""New interface."""\n')
    (tmp_path / "docs/site").mkdir(parents=True)
    (tmp_path / "docs/site/api-coverage.toml").write_text("schemaVersion = 1\n")

    with pytest.raises(ValueError, match="every source module exactly once"):
        API.ValidateInventory(tmp_path, {"apiCoverageManifest": "docs/site/api-coverage.toml"})


def test_TripwireRejectsRuntimeImports() -> None:
    """Deny security package and submodule imports under the Python finder protocol."""

    tripwire = API.ImportTripwire(["fuzzy1337"])

    for name in ("fuzzy1337", "fuzzy1337.executors.local"):
        with pytest.raises(RuntimeError, match="attempted to import security runtime"):
            tripwire.find_spec(name)

    assert tripwire.find_spec("json") is None, (
        "Non-runtime documentation dependencies remain usable"
    )


def test_MissingPublicSymbolFailsClosed() -> None:
    """Reject one omitted method even when its containing module anchor is present."""

    expected = ["fuzzy1337.Module", "fuzzy1337.Module.Execute"]
    API.ValidateSymbolAnchors(set(expected), expected)

    with pytest.raises(ValueError, match="Module.Execute"):
        API.ValidateSymbolAnchors({"fuzzy1337.Module"}, expected)


def test_StaleWheelFailsSourceParity(tmp_path: Path) -> None:
    """Reject a clean-installed wheel that predates a reviewed source edit."""

    source = tmp_path / "src/fuzzy1337"
    installed = tmp_path / "installed/fuzzy1337"
    source.mkdir(parents=True)
    installed.mkdir(parents=True)
    (source / "module.py").write_text('"""Current contract."""\n')
    (installed / "module.py").write_text('"""Previous contract."""\n')

    with pytest.raises(ValueError, match="differ from the reviewed checkout"):
        API.ValidateWheelSources(tmp_path, tmp_path / "installed", ["fuzzy1337"])


def test_UnhandledTranslationStateFailsClosed(tmp_path: Path) -> None:
    """Refuse to silently replace an approved translation with English fallback."""

    (tmp_path / "units.toml").write_text(
        '[[units]]\nid = "page:index"\n[units.translations.ru]\nstate = "approved"\n'
    )

    with pytest.raises(ValueError, match="supports only missing translations"):
        API.ValidateFallbackState(tmp_path, {"unitManifest": "units.toml", "locales": ["en", "ru"]})


def test_OutputRejectsBrokenAnchorsAndEscapes(tmp_path: Path) -> None:
    """Reject missing anchors and directory traversal in generated local links."""

    (tmp_path / "search").mkdir()
    (tmp_path / "search/search_index.json").write_text("{}")
    page = tmp_path / "index.html"
    page.write_text('<h1 id="overview">Reference</h1><a href="#overview">Overview</a>')
    result = API.CheckOutput(tmp_path, [], "/1337/api/latest/en/")

    assert result["pages"] == 1, "Output evidence must include generated HTML page count"
    page.write_text('<a href="#absent">Broken</a>')

    with pytest.raises(ValueError, match="Broken generated anchor"):
        API.CheckOutput(tmp_path, [], "/1337/api/latest/en/")

    page.write_text('<a href="../outside.html">Escape</a>')

    with pytest.raises(ValueError, match="Broken generated local link"):
        API.CheckOutput(tmp_path, [], "/1337/api/latest/en/")


def test_PublicRendererOutputDropsOnlyGeneratedAuxiliaries(tmp_path: Path) -> None:
    """Preserve site bytes while excluding source maps and optional binary inventories."""

    names = (
        "index.html", "assets/theme.js", "assets/theme.js.map", "objects.inv",
        "sitemap.xml", "sitemap.xml.gz", "assets/mathjax/LICENSE",
    )

    for name in names:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"known generated bytes")

    API.PreparePublicOutput(tmp_path)
    remaining = {path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*")
                 if path.is_file()}

    expected = {"index.html", "assets/theme.js", "sitemap.xml", "assets/mathjax/LICENSE"}

    assert remaining == expected, (
        "Only generated maps, compressed sitemap and optional intersphinx inventory are excluded"
    )
    assert all((tmp_path / name).read_bytes() == b"known generated bytes" for name in remaining), (
        "Publication preparation must preserve every retained file byte"
    )
