# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Verify portable locale identity, source drift, and accountable review contracts."""

import json
import shutil
import tomllib
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import tomlkit

from tools import locale_documentation as LOCALE

ROOT = Path(__file__).resolve().parents[2]


def CopySources(destination: Path) -> Path:
    """Copy only the authored contracts needed for a deterministic mutation test."""

    for directory in ("src", "docs/i18n", "docs/site"):
        shutil.copytree(ROOT / directory, destination / directory)

    return destination


def test_MissingTranslationsRemainHonest() -> None:
    """Require missing translation state without fabricated approvals."""

    report = LOCALE.ValidateLocales(ROOT)

    assert not report.diagnostics, f"Canonical locale contracts failed: {report.diagnostics}"
    assert report.states, "Locale validator must inventory canonical documentation units"
    assert all(set(states.values()) == {"missing"} for states in report.states.values()), (
        "Initial translations must remain explicitly missing"
    )


def test_SourceDriftFailsClosed(tmp_path: Path) -> None:
    """Reject an English edit until its recorded hash is reviewed and refreshed."""

    root = CopySources(tmp_path)
    source = root / "docs/site/content/en/index.md"
    source.write_text(source.read_text() + "\nCanonical contract changed.\n")
    report = LOCALE.ValidateLocales(root)

    assert any("canonical source drift" in item for item in report.diagnostics), (
        "Changed English documentation must invalidate the canonical source hash"
    )


def test_ApprovalRequiresAccountableReview(tmp_path: Path) -> None:
    """Reject approved translations that omit required review roles."""

    root = CopySources(tmp_path)
    translated = root / "docs/site/content/ru/index.md"
    translated.parent.mkdir(parents=True)
    translated.write_text("Translated contract.\n")
    manifest = root / "docs/i18n/units.toml"
    manifest.write_text(manifest.read_text().replace(
        'state = "missing"',
        'state = "approved"\npath = "docs/site/content/ru/index.md"\nreviews = []', 1
    ))
    report = LOCALE.ValidateLocales(root)

    assert any("approved state lacks review roles" in item for item in report.diagnostics), (
        "Approved technical translations must require editorial and technical reviews"
    )


def test_HashIncludesIdentitySignatureAndBody() -> None:
    """Preserve versioned upstream hash semantics across independent contract changes."""

    unit = LOCALE.CanonicalUnit("symbol:fuzzy1337.Main", "symbol", "src/a.py", "def Main()", "A")
    baseline = LOCALE.CanonicalHash(unit)

    for changed in (
        LOCALE.CanonicalUnit("symbol:fuzzy1337.Other", "symbol", "src/a.py", "def Main()", "A"),
        LOCALE.CanonicalUnit(unit.identifier, "symbol", "src/a.py", "def Main(x)", "A"),
        LOCALE.CanonicalUnit(unit.identifier, "symbol", "src/a.py", unit.signature, "B"),
    ):
        assert LOCALE.CanonicalHash(changed) != baseline, "Contract changes must alter sourceHash"


FIXTURE_API = '''"""Controlled authored contracts; runtime must never execute."""
raise RuntimeError("static discovery must never import this module")


def Convert(value: int = 1) -> str:
    """Convert a controlled integer to text."""

    return str(value)


async def Fetch() -> str:
    """Return controlled data asynchronously."""

    return "fixture"


class Item(object, metaclass=type):
    """Hold an authored contract and one public property."""

    value: int = 1
    title = "item"
    _internal: int = 2

    def Apply(self) -> int:
        """Return the controlled stored value."""

        return self.value

    @property
    def Value(self) -> int:
        """Expose the controlled stored value."""

        return self.value

    @Value.setter
    def Value(self, value: int) -> None:
        """Set the controlled stored value."""

        self.value = value

    def _Internal(self) -> None:
        """Keep private implementation outside the declared authored surface."""

        return None
'''


def WriteToml(path: Path, value: dict[str, Any]) -> None:
    """Serialize independently authored fixture metadata for actual validator reads."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(tomlkit.dumps(value), encoding="utf-8")


def ReadToml(path: Path) -> dict[str, Any]:
    """Read fixture records before a scoped public-contract mutation."""

    return tomllib.loads(path.read_text(encoding="utf-8"))


def FixtureProject(root: Path) -> Path:
    """Create a tiny portable documentation project independent of product prose."""

    for directory in ("docs/content/en/guide", "docs/i18n", "package"):
        (root / directory).mkdir(parents=True, exist_ok=True)

    (root / "docs/content/en/index.md").write_text("# Controlled canonical page\n")
    (root / "docs/content/en/guide/topic_name.md").write_text("# Controlled topic\n")
    (root / "docs/reference.md").write_text("# Controlled concept reference\n")
    (root / "package/api.py").write_text(FIXTURE_API)
    (root / "package/__init__.py").write_text(
        '"""Controlled static export surface."""\n'
        'from package.api import Convert as ConvertAlias, Item as ItemAlias\n'
        '__all__ = ["ConvertAlias", "ItemAlias"]\n'
    )
    project = {
        "schemaVersion": 1, "projectId": "fixture", "projectName": "Fixture documentation",
        "sourceLocale": "en", "locales": ["en", "ru", "zh-cn"],
        "packageNames": ["package"], "contentRoot": "docs/content",
        "unitManifest": "docs/i18n/units.toml", "buildRoot": "_build/docs",
        "apiCoverageManifest": "docs/coverage.toml", "publicationPath": "/fixture",
        "branding": {"organization": "Fixture team", "assetRoot": "docs/content/en/assets"},
        "glossaries": {"ru": "docs/i18n/ru.toml", "zh-cn": "docs/i18n/zh-cn.toml"},
    }
    WriteToml(root / "docs/i18n/project.toml", project)
    WriteToml(root / "docs/coverage.toml", {
        "surfaces": [
            {"module": "package.api", "source": "package/api.py", "mode": "authored"},
            {"module": "package", "source": "package/__init__.py", "mode": "exports"},
        ],
        "exclusions": [{"symbol": "package.api.Fetch", "reason": "Explicit fixture exclusion"}],
    })

    for locale in ("ru", "zh-cn"):
        WriteToml(root / f"docs/i18n/{locale}.toml", {
            "schemaVersion": 1, "locale": locale,
            "terms": [{"id": "concept:unit", "english": "unit", "preferred": "approved term",
                       "avoid": ["discouraged term"], "references": ["docs/reference.md"]}],
        })

    units = LOCALE.DiscoverCanonicalUnits(root, project)
    WriteToml(root / "docs/i18n/units.toml", {
        "schemaVersion": 1,
        "units": [{"id": unit.identifier, "kind": unit.kind, "sourcePath": unit.source_path,
                   "sourceHash": LOCALE.CanonicalHash(unit), "reviewClass": "technical",
                   "translations": {locale: {"state": "missing"} for locale in ("ru", "zh-cn")}}
                  for unit in units],
    })

    return root


def ApprovePage(root: Path, *, review_class: str = "technical") -> dict[str, Any]:
    """Record accountable fixture reviews tied to the current canonical source hash."""

    path = root / "docs/i18n/units.toml"
    manifest = ReadToml(path)
    record = next(unit for unit in manifest["units"] if unit["id"] == "page:index")
    record["reviewClass"] = review_class
    translated = root / "docs/content/ru/index.md"
    translated.parent.mkdir(parents=True, exist_ok=True)
    translated.write_text("# Controlled translation\n")
    record["translations"]["ru"] = {
        "state": "approved", "path": "docs/content/ru/index.md",
        "reviews": [{"role": role, "reviewer": "fixture-reviewer",
                     "reviewedAt": "2026-01-02T03:04:05Z",
                     "reviewedSourceHash": record["sourceHash"]}
                    for role in sorted(LOCALE.REVIEW_ROLES[review_class])],
    }
    WriteToml(path, manifest)

    return manifest


def HasDiagnostic(report: Any, text: str) -> bool:
    """Match a public actionable diagnosis without binding tests to private branches."""

    return any(text in diagnostic for diagnostic in report.diagnostics)


def test_PortableDiscoveryPreservesAliasesExclusionsAndStableIDs(tmp_path: Path) -> None:
    """Prove AST inventory handles aliases/properties and never imports security runtime."""

    root = FixtureProject(tmp_path)
    report = LOCALE.ValidateLocales(root)
    assert not report.diagnostics, f"Portable fixture should validate: {report.diagnostics}"
    assert "symbol:package.ConvertAlias" in report.states, "Static alias contract was omitted."
    assert "symbol:package.api.Item.Value" in report.states, "Property getter was omitted."
    assert "symbol:package.api.Fetch" not in report.states, "Explicit exclusion was ignored."
    assert "symbol:package.api.Item._Internal" not in report.states, "Private API leaked."
    assert "page:guide.topic-name" in report.states, "Stable underscore page normalization changed."
    project = ReadToml(root / "docs/i18n/project.toml")
    units = LOCALE.DiscoverCanonicalUnits(root, project)
    value_units = [unit for unit in units if unit.identifier == "symbol:package.api.Item.Value"]
    assert len(value_units) == 1, "Property setter duplicated the getter's canonical unit."
    item = next(unit for unit in units if unit.identifier == "symbol:package.api.Item")
    assert "value: int = 1" in item.signature and "title = 'item'" in item.signature, (
        "Public field contracts must participate in canonical class signatures."
    )
    assert "_internal" not in item.signature, "Private fields entered canonical signatures."


@pytest.mark.parametrize(("field", "value", "diagnosis"), [
    ("schemaVersion", 2, "schemaVersion must be 1"),
    ("projectId", "", "projectId must be a non-empty string"),
    ("sourceLocale", "ru", "sourceLocale must be 'en'"),
    ("locales", ["en"], "locales must be a unique list"),
    ("locales", ["en", "ru", "ru"], "locales must be a unique list"),
    ("locales", ["en", "invalid-locale-too-long"], "locales must be a unique list"),
    ("packageNames", [], "packageNames must be a non-empty string list"),
    ("publicationPath", "relative", "publicationPath must be an absolute URL path"),
    ("publicationPath", "/fixture/", "publicationPath must be an absolute URL path"),
    ("publicationPath", "/fixture/../other", "publicationPath must be an absolute URL path"),
    ("branding", "invalid", "branding must be a table"),
    ("branding", {"organization": "", "assetRoot": "a"}, "branding.organization"),
    ("glossaries", {"ru": "one"}, "glossaries must match target locales"),
])
def test_MalformedPortableProjectContractsFailClosed(
    tmp_path: Path, field: str, value: Any, diagnosis: str
) -> None:
    """Reject manifest identities and locale/publication contracts before discovery."""

    root = FixtureProject(tmp_path)
    path = root / "docs/i18n/project.toml"
    manifest = ReadToml(path)
    manifest[field] = value
    WriteToml(path, manifest)
    report = LOCALE.ValidateLocales(root)
    assert HasDiagnostic(report, diagnosis), (
        f"Invalid {field} contract escaped: {report.diagnostics}"
    )
    assert report.states == {}, (
        "Invalid project contract must not produce misleading locale states."
    )


@pytest.mark.parametrize(("mutation", "diagnosis"), [
    ("schema", "schemaVersion must be 1"),
    ("duplicate", "duplicate unit ID"),
    ("remove", "missing canonical unit"),
    ("unknown", "unknown or retired-unmarked unit"),
    ("kind", "kind must be symbol"),
    ("source", "preserve the stable ID and update its canonical source path"),
    ("hash", "invalid sourceHash"),
    ("class", "invalid reviewClass"),
    ("locale", "unsupported locale"),
    ("missing", "missing ru translation state"),
    ("state", "invalid ru state"),
    ("missing-path", "missing state cannot carry a path or reviews"),
    ("retired", "active canonical unit cannot have retired ru state"),
    ("draft-file", "add the locale file or use state=missing"),
])
def test_UnitManifestIdentityAndStateFailuresAreActionable(
    tmp_path: Path, mutation: str, diagnosis: str
) -> None:
    """Require one exact canonical inventory and honest locale lifecycle states."""

    root = FixtureProject(tmp_path)
    path = root / "docs/i18n/units.toml"
    manifest = ReadToml(path)
    symbol = next(unit for unit in manifest["units"] if unit["kind"] == "symbol")
    translation = symbol["translations"]["ru"]

    if mutation == "schema":
        manifest["schemaVersion"] = 2

    elif mutation == "duplicate":
        manifest["units"].append(dict(symbol))

    elif mutation == "remove":
        manifest["units"].remove(symbol)

    elif mutation == "unknown":
        manifest["units"].append({**symbol, "id": "symbol:package.Removed"})

    elif mutation == "kind":
        symbol["kind"] = "unexpected"

    elif mutation == "source":
        symbol["sourcePath"] = "package/old.py"

    elif mutation == "hash":
        symbol["sourceHash"] = "sha256:invalid"

    elif mutation == "class":
        symbol["reviewClass"] = "unknown"

    elif mutation == "locale":
        symbol["translations"]["fr"] = {"state": "missing"}

    elif mutation == "missing":
        del symbol["translations"]["ru"]

    elif mutation == "state":
        translation["state"] = "pretend-approved"

    elif mutation == "missing-path":
        translation["path"] = "docs/not-written.md"

    elif mutation == "retired":
        translation["state"] = "retired"

    else:
        translation.update({"state": "draft", "path": "docs/not-written.md"})

    WriteToml(path, manifest)
    report = LOCALE.ValidateLocales(root)
    assert HasDiagnostic(report, diagnosis), f"Mutation {mutation} escaped: {report.diagnostics}"


@pytest.mark.parametrize("review_class", ["editorial", "technical", "mathematical"])
def test_ApprovedReviewsMatchTheDeclaredContract(tmp_path: Path, review_class: str) -> None:
    """Accept complete editorial/domain reviews bound to the exact English source."""

    root = FixtureProject(tmp_path)
    ApprovePage(root, review_class=review_class)
    report = LOCALE.ValidateLocales(root)
    assert not report.diagnostics, f"Complete accountable review failed: {report.diagnostics}"
    assert report.states["page:index"]["ru"] == "approved", "Valid approval was not preserved."
    assert report.states["page:index"]["zh-cn"] == "missing", "Approval leaked across locales."


@pytest.mark.parametrize(("mutation", "diagnosis"), [
    ("empty-reviewer", "reviewer must be non-empty"),
    ("bad-timestamp", "reviewedAt must be a UTC timestamp"),
    ("invalid-date", "reviewedAt must be a UTC timestamp"),
    ("duplicate-role", "duplicate review role"),
    ("missing-role", "approved state lacks review roles"),
    ("review-table", "reviews must be a list"),
    ("old-hash", "obtain new accountable human reviews"),
    ("changed-source", "canonical source drift"),
])
def test_ApprovalCannotConcealStaleOrUnaccountableEvidence(
    tmp_path: Path, mutation: str, diagnosis: str
) -> None:
    """Reject stale approvals, unauthenticated reviewers, and incomplete review roles."""

    root = FixtureProject(tmp_path)
    manifest = ApprovePage(root)
    page = next(unit for unit in manifest["units"] if unit["id"] == "page:index")
    translation = page["translations"]["ru"]
    reviews = translation["reviews"]

    if mutation == "empty-reviewer":
        reviews[0]["reviewer"] = " "

    elif mutation == "bad-timestamp":
        reviews[0]["reviewedAt"] = 123

    elif mutation == "invalid-date":
        reviews[0]["reviewedAt"] = "invalidZ"

    elif mutation == "duplicate-role":
        reviews.append(dict(reviews[0]))

    elif mutation == "missing-role":
        reviews.pop()

    elif mutation == "review-table":
        translation["reviews"] = {"role": "editorial"}

    elif mutation == "old-hash":
        reviews[0]["reviewedSourceHash"] = "sha256:" + "0" * 64

    else:
        (root / "docs/content/en/index.md").write_text("# Revised canonical contract\n")

    WriteToml(root / "docs/i18n/units.toml", manifest)
    report = LOCALE.ValidateLocales(root)
    assert HasDiagnostic(report, diagnosis), (
        f"Bad approval {mutation} escaped: {report.diagnostics}"
    )

    if mutation in {"old-hash", "changed-source"}:
        assert report.states["page:index"]["ru"] == "stale", "Old review hash retained approval."
        assert report.states["page:index"]["zh-cn"] == "missing", (
            "Stale review leaked into missing."
        )


@pytest.mark.parametrize(("mutation", "diagnosis"), [
    ("schema", "schemaVersion must be 1"),
    ("locale", "locale must be ru"),
    ("id", "invalid concept ID"),
    ("english", "english must be non-empty"),
    ("preferred", "preferred must be non-empty"),
    ("avoid-type", "avoid must be a string list"),
    ("avoid-preferred", "preferred term cannot be prohibited"),
    ("no-reference", "at least one reference is required"),
    ("bad-reference", "missing reference"),
    ("english-drift", "canonical English term differs across locales"),
    ("duplicate", "duplicate concept IDs"),
    ("concept-drift", "target locale concept IDs must match"),
    ("unreadable", "cannot load glossary"),
])
def test_GlossaryContractsPreventCrossLocaleTerminologyDrift(
    tmp_path: Path, mutation: str, diagnosis: str
) -> None:
    """Require stable shared concepts and traceable preferred terminology per locale."""

    root = FixtureProject(tmp_path)
    path = root / "docs/i18n/ru.toml"
    glossary = ReadToml(path)
    term = glossary["terms"][0]

    if mutation == "schema":
        glossary["schemaVersion"] = 2

    elif mutation == "locale":
        glossary["locale"] = "fr"

    elif mutation == "id":
        term["id"] = "unstable unit"

    elif mutation == "english":
        term["english"] = " "

    elif mutation == "preferred":
        term["preferred"] = " "

    elif mutation == "avoid-type":
        term["avoid"] = "discouraged"

    elif mutation == "avoid-preferred":
        term["avoid"] = [term["preferred"]]

    elif mutation == "no-reference":
        term["references"] = []

    elif mutation == "bad-reference":
        term["references"] = ["docs/absent.md"]

    elif mutation == "english-drift":
        term["english"] = "inconsistent unit"

    elif mutation == "duplicate":
        glossary["terms"].append(dict(term))

    elif mutation == "concept-drift":
        glossary["terms"] = []

    else:
        path.unlink()
        report = LOCALE.ValidateLocales(root)
        assert HasDiagnostic(report, diagnosis), "Unavailable glossary silently passed."

        return

    WriteToml(path, glossary)
    report = LOCALE.ValidateLocales(root)
    assert HasDiagnostic(report, diagnosis), f"Glossary {mutation} escaped: {report.diagnostics}"


@pytest.mark.parametrize(("mutation", "diagnosis"), [
    ("foreign-module", "outside declared packageNames"),
    ("invalid-mode", "invalid surface mode"),
    ("duplicate-surface", "duplicate discovered unit IDs"),
    ("missing-export", "missing literal __all__"),
    ("duplicate-export", "__all__ contains duplicate names"),
    ("invalid-export", "__all__ must be a literal string sequence"),
    ("unbound-export", "has no static import target"),
    ("missing-module", "cannot resolve project module"),
    ("missing-definition", "cannot find public definition"),
])
def test_StaticSurfaceContractsRejectUnresolvableInventories(
    tmp_path: Path, mutation: str, diagnosis: str
) -> None:
    """Reject ambiguous API discovery rather than importing code to guess its surface."""

    root = FixtureProject(tmp_path)
    path = root / "docs/coverage.toml"
    coverage = ReadToml(path)
    export_path = root / "package/__init__.py"
    exports = export_path.read_text()

    if mutation == "foreign-module":
        coverage["surfaces"][0]["module"] = "foreign.api"

    elif mutation == "invalid-mode":
        coverage["surfaces"][0]["mode"] = "dynamic"

    elif mutation == "duplicate-surface":
        coverage["surfaces"].append(dict(coverage["surfaces"][0]))

    elif mutation == "missing-export":
        export_path.write_text(exports.replace('__all__ = ["ConvertAlias", "ItemAlias"]', ""))

    elif mutation == "duplicate-export":
        export_path.write_text(exports.replace('"ItemAlias"]', '"ConvertAlias"]'))

    elif mutation == "invalid-export":
        export_path.write_text(exports.replace('["ConvertAlias", "ItemAlias"]', "[1]"))

    elif mutation == "unbound-export":
        export_path.write_text(exports.replace('"ItemAlias"]', '"Unbound"]'))

    elif mutation == "missing-module":
        export_path.write_text(exports.replace("from package.api", "from package.missing"))

    else:
        export_path.write_text(exports.replace("import Convert as", "import Missing as"))

    WriteToml(path, coverage)
    report = LOCALE.ValidateLocales(root)
    assert HasDiagnostic(report, diagnosis), f"Surface {mutation} escaped: {report.diagnostics}"


def test_StablePageIDsSurviveMovesButNotDuplicateOwnership(tmp_path: Path) -> None:
    """Preserve declared page identities across source moves and reject path collisions."""

    root = FixtureProject(tmp_path)
    path = root / "docs/i18n/units.toml"
    manifest = ReadToml(path)
    record = next(unit for unit in manifest["units"] if unit["id"] == "page:index")
    old_page = root / record["sourcePath"]
    new_page = root / "docs/content/en/renamed.md"
    old_page.rename(new_page)
    record["sourcePath"] = "docs/content/en/renamed.md"
    WriteToml(path, manifest)
    report = LOCALE.ValidateLocales(root)
    assert not report.diagnostics, f"Stable page move unexpectedly changed identity: {report}"
    duplicate = dict(record)
    duplicate["id"] = "page:duplicate-owner"
    manifest["units"].append(duplicate)
    WriteToml(path, manifest)
    assert HasDiagnostic(LOCALE.ValidateLocales(root), "already owned by"), (
        "One canonical page was accepted under conflicting stable identities."
    )


def test_BOMInvalidStableIDsAndCLIReportsFailHonestly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exercise inventory/validation evidence and explicit file/identity failures."""

    root = FixtureProject(tmp_path)
    argv = ["--project-root", str(root)]
    output = root / "reports/locales.json"
    assert LOCALE.Main(["validate", *argv, "--output", str(output)]) == 0, (
        "Valid portable project failed CLI validation."
    )
    evidence = json.loads(output.read_text())
    assert evidence["status"] == "pass" and evidence["schemaVersion"] == 1, (
        "Machine evidence did not describe the actual validation result."
    )
    assert LOCALE.Main(["inventory", *argv]) == 0, "Canonical inventory CLI failed."
    lines = capsys.readouterr().out.splitlines()
    assert any('"sourceHash"' in line for line in lines), (
        "Canonical hashes were absent from inventory."
    )
    units_path = root / "docs/i18n/units.toml"
    manifest = ReadToml(units_path)
    next(unit for unit in manifest["units"] if unit["id"] == "page:index")["id"] = "page:Invalid"
    WriteToml(units_path, manifest)
    assert HasDiagnostic(LOCALE.ValidateLocales(root), "invalid stable ID"), (
        "Manifest-controlled invalid page identity escaped stable ID validation."
    )
    assert LOCALE.Main(["validate", *argv, "--output", str(output)]) == 1, (
        "CLI silently accepted invalid stable identity."
    )
    assert json.loads(output.read_text())["status"] == "fail", "Failed evidence reported pass."
    project_path = root / "docs/i18n/project.toml"
    project_path.write_bytes(b"\xef\xbb\xbf" + project_path.read_bytes())
    assert LOCALE.Main(["inventory", *argv]) == 1, "BOM manifest silently passed CLI inventory."
    assert "byte-order marks are not allowed" in capsys.readouterr().err, "BOM diagnosis was lost."


def test_CustomManifestAndMissingUnitInventoryAreSupported(tmp_path: Path) -> None:
    """Resolve locale-specific project configuration explicitly without modifying hashes."""

    root = FixtureProject(tmp_path)
    project_path = root / "docs/i18n/project.toml"
    custom = root / "custom-project.toml"
    project_path.rename(custom)
    report = LOCALE.ValidateLocales(root, custom)
    assert not report.diagnostics, f"Explicit portable manifest was ignored: {report.diagnostics}"
    (root / "docs/i18n/units.toml").unlink()
    assert LOCALE.Main([
        "inventory", "--project-root", str(root), "--project-manifest", str(custom)
    ]) == 0, "Fresh project inventory must work before its unit manifest exists."


@pytest.mark.parametrize("state", ["draft", "review", "stale"])
def test_UnapprovedExistingTranslationsNeverGainApproval(tmp_path: Path, state: str) -> None:
    """Keep generated/review-stage text explicitly unapproved without fabricated reviews."""

    root = FixtureProject(tmp_path)
    manifest = ApprovePage(root)
    page = next(unit for unit in manifest["units"] if unit["id"] == "page:index")
    page["translations"]["ru"].update({"state": state, "reviews": []})
    WriteToml(root / "docs/i18n/units.toml", manifest)
    report = LOCALE.ValidateLocales(root)
    assert not report.diagnostics, f"Honest pending state failed: {report.diagnostics}"
    assert report.states["page:index"]["ru"] == state, (
        "Pending translation was promoted to approved."
    )


def test_CanonicalNewlinesNormalizeAndSourcePathsDoNotChangeHash(tmp_path: Path) -> None:
    """Preserve portable hashes across platform newlines and stable-ID file moves."""

    root = FixtureProject(tmp_path)
    project = ReadToml(root / "docs/i18n/project.toml")
    before = LOCALE.DiscoverCanonicalUnits(root, project)
    page = next(unit for unit in before if unit.identifier == "page:index")
    source = root / page.source_path
    normalized = source.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    source.write_bytes(normalized.replace(b"\n", b"\r\n"))
    after = LOCALE.DiscoverCanonicalUnits(root, project)
    updated = next(unit for unit in after if unit.identifier == page.identifier)
    assert LOCALE.CanonicalHash(updated) == LOCALE.CanonicalHash(page), (
        "Platform newline changes must not invalidate canonical documentation hashes."
    )
    relocated = LOCALE.CanonicalUnit(page.identifier, page.kind, "docs/moved.md", "", page.body)
    assert LOCALE.CanonicalHash(relocated) == LOCALE.CanonicalHash(page), (
        "Source relocation must preserve reviewed content identity under the v1 hash scheme."
    )


@pytest.mark.parametrize("location", [
    "contentRoot", "unitManifest", "apiCoverageManifest", "glossary", "surface",
    "sourcePath", "translation", "reference",
])
def test_ManifestPathsCannotReadOrApproveOutsideTheProject(tmp_path: Path, location: str) -> None:
    """Reject escaped metadata paths before reading or approving their external targets."""

    root = FixtureProject(tmp_path / "project")
    external = tmp_path / "outside"
    external.mkdir()
    (external / "en").mkdir()
    (external / "en/index.md").write_text("# Controlled external content\n")
    (external / "api.py").write_text(FIXTURE_API)
    (external / "reference.md").write_text("# Controlled external reference\n")
    WriteToml(external / "units.toml", ReadToml(root / "docs/i18n/units.toml"))
    WriteToml(external / "coverage.toml", ReadToml(root / "docs/coverage.toml"))
    WriteToml(external / "glossary.toml", ReadToml(root / "docs/i18n/ru.toml"))
    manifest_path = root / "docs/i18n/project.toml"
    manifest = ReadToml(manifest_path)

    if location in {"contentRoot", "unitManifest", "apiCoverageManifest"}:
        targets = {
            "contentRoot": "../outside", "unitManifest": "../outside/units.toml",
            "apiCoverageManifest": "../outside/coverage.toml",
        }
        manifest[location] = targets[location]
        WriteToml(manifest_path, manifest)

    elif location == "glossary":
        manifest["glossaries"]["ru"] = "../outside/glossary.toml"
        WriteToml(manifest_path, manifest)

    elif location == "surface":
        coverage_path = root / "docs/coverage.toml"
        coverage = ReadToml(coverage_path)
        coverage["surfaces"][0]["source"] = "../outside/api.py"
        WriteToml(coverage_path, coverage)

    elif location in {"sourcePath", "translation"}:
        units = ApprovePage(root)
        page = next(unit for unit in units["units"] if unit["id"] == "page:index")

        if location == "sourcePath":
            page["sourcePath"] = "../outside/en/index.md"

        else:
            page["translations"]["ru"]["path"] = "../outside/en/index.md"

        WriteToml(root / "docs/i18n/units.toml", units)

    else:
        glossary_path = root / "docs/i18n/ru.toml"
        glossary = ReadToml(glossary_path)
        glossary["terms"][0]["references"] = ["../outside/reference.md"]
        WriteToml(glossary_path, glossary)

    original_reader = LOCALE._ReadCanonicalText
    external_reads = []

    def ConfinedReader(path: Path) -> str:
        """Record attempted escape before any external fixture contents can be read."""

        if not path.resolve().is_relative_to(root.resolve()):
            external_reads.append(path)
            raise AssertionError("Validator attempted to read outside the selected project.")

        return original_reader(path)

    with patch.object(LOCALE, "_ReadCanonicalText", ConfinedReader):
        report = LOCALE.ValidateLocales(root)

    assert report.diagnostics, f"Escaped {location} path was accepted without a failing diagnosis."
    assert not external_reads, f"Escaped {location} path was read before rejection."


@pytest.mark.parametrize("location", ["source", "content", "translation", "root"])
def test_SymlinkedSourceOrTranslationCannotBypassTheProjectBoundary(
    tmp_path: Path, location: str
) -> None:
    """Refuse linked roots/source/translation files before following external read targets."""

    root = FixtureProject(tmp_path / "project")
    external = tmp_path / "outside"
    external.mkdir()
    target = external / "source.py"
    target.write_text(FIXTURE_API)
    selected_root = root

    if location == "source":
        link = root / "package/api.py"
        link.unlink()

    elif location == "content":
        link = root / "docs/content/en/index.md"
        link.unlink()
        target = external / "page.md"
        target.write_text("# Controlled external page\n")

    elif location == "translation":
        ApprovePage(root)
        link = root / "docs/content/ru/index.md"
        link.unlink()
        target = external / "translation.md"
        target.write_text("# Controlled external translation\n")

    else:
        link = tmp_path / "linked-root"
        target = root
        selected_root = link

    try:
        link.symlink_to(target, target_is_directory=location == "root")

    except (OSError, NotImplementedError):
        pytest.skip("Controlled symlink contracts require filesystem support and privileges.")

    original_reader = LOCALE._ReadCanonicalText

    def ConfinedReader(path: Path) -> str:
        """Fail immediately if the validator attempts to read a linked external source."""

        assert path.resolve().is_relative_to(root.resolve()), (
            "Validator followed an external symlink before rejecting its project path."
        )

        return original_reader(path)

    with patch.object(LOCALE, "_ReadCanonicalText", ConfinedReader):
        report = LOCALE.ValidateLocales(selected_root)

    assert report.diagnostics, (
        f"Linked {location} contract was accepted without a failing diagnosis."
    )
