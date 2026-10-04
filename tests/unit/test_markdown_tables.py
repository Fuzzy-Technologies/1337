# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Protect source content and tracked-file boundaries during table alignment."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tools.markdown_tables import AlignMarkdown, CheckMarkdownTables, Main, SplitRow

TOOL_PATH = Path(__file__).resolve().parents[2] / "tools/markdown_tables.py"
DRIFTING_TABLE = "| Short | Longer heading |\n| --- | --- |\n| Value | Result |\n"


def InitializeRepository(tmp_path: Path, name: str = "README.md") -> Path:
    """Create a tracked UTF-8 table fixture without requiring Git author settings.

    Args:
        tmp_path: Isolated directory for a disposable Git repository.
        name: Repository-relative Markdown filename, including Unicode if needed.

    Returns:
        Tracked source file whose original table deliberately needs formatting.

    Raises:
        pytest.skip.Exception: Git is unavailable in a runtime-only environment.
    """

    if shutil.which("git") is None:
        pytest.skip("Git-backed formatter tests require an installed Git executable")

    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    page = tmp_path / name
    page.write_bytes(DRIFTING_TABLE.encode("utf-8"))
    subprocess.run(["git", "add", "--", name], cwd=tmp_path, check=True)

    return page


def test_TableAlignmentPreservesEscapedPipesInsideCode() -> None:
    """GFM requires a pipe to be escaped even when it appears inside inline code."""

    text = "| Cell | Note |\n| :--- | ---: |\n| `left\\|right` | escaped \\| pipe |\n"
    aligned = AlignMarkdown(text)
    aligned_rows = [SplitRow(line) for line in aligned.splitlines()]

    assert aligned_rows[0] == ["Cell", "Note"], "Formatting must preserve header content"
    assert aligned_rows[2] == ["`left\\|right`", "escaped \\| pipe"], "Escapes must survive"
    assert aligned_rows[1] is not None, "The separator must remain a valid table row"
    assert aligned_rows[1][0].startswith(":"), "Left alignment must survive"
    assert aligned_rows[1][1].endswith(":"), "Right alignment must survive"
    assert AlignMarkdown(aligned) == aligned, "A second formatting pass must have no changes"


def test_UnescapedPipeInsideCodeRemainsASeparator() -> None:
    """Backticks cannot turn an unescaped GFM column delimiter into cell content."""

    assert SplitRow("| `left|right` | note |") == ["`left", "right`", "note"], (
        "Inline code alone must not escape a GFM delimiter"
    )


def test_FencedTablesAreNeverRewritten() -> None:
    """Markdown examples inside both supported fence styles remain byte-identical."""

    for marker in ("```", "~~~~"):
        example = (
            f"{marker}markdown\n{marker}not-a-closing-fence\n"
            f"| Short | Very long cell |\n| --- | --- |\n{marker}\n"
        )

        assert AlignMarkdown(example) == example, "Fenced literal content must remain untouched"


def test_IndentedCodeTablesAreNeverRewritten() -> None:
    """Table-looking literal code remains identical for spaces and tab indentation."""

    for prefix in ("    ", "\t", "  \t"):
        example = (
            f"{prefix}| Short | Very long cell |\n"
            f"{prefix}| --- | --- |\n"
            f"{prefix}| Value | Result |\n"
        )

        assert AlignMarkdown(example) == example, "Indented literal code must remain untouched"


def test_OptionalOuterPipesReceiveTheSameAlignment() -> None:
    """Valid tables without outer pipes must not bypass the source-readability gate."""

    text = "Short | Longer heading\n------------------------ | ---\nValue | Result\n"
    aligned = AlignMarkdown(text)

    assert aligned.startswith("| Short | Longer heading |\n"), "Outer pipes must be canonical"
    assert SplitRow(text.splitlines()[2]) == SplitRow(aligned.splitlines()[2]), (
        "Normalizing outer pipes must preserve row contents"
    )


def test_IncompleteTableStructureRemainsUntouched() -> None:
    """A pipe expression without a valid separator row is not an authored table."""

    for text in (
        "| a | b |\n| expression | value |\n", "| a | b |\n| --- |\n",
        "prose\n| --- | --- |\n", "| a | b |\n    | --- | --- |\n",
    ):
        assert AlignMarkdown(text) == text, "Invalid or literal separators are not tables"


def test_TrackedTableDriftIsReported(tmp_path: Path) -> None:
    """The gate reports source drift but does not rewrite it or inspect ignored output."""

    page = InitializeRepository(tmp_path)
    ignored = tmp_path / "_build/preview.md"
    ignored.parent.mkdir()
    ignored.write_text(DRIFTING_TABLE, encoding="utf-8")

    assert CheckMarkdownTables(tmp_path) == (
        "README.md: Markdown table columns need alignment",
    ), "Only tracked Markdown drift must be reported"
    assert page.read_bytes() == DRIFTING_TABLE.encode(), "Validation must remain read-only"


def test_RelativeRepositoryRoot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Library callers can supply a relative root and receive relative diagnostics."""

    page = InitializeRepository(tmp_path)
    monkeypatch.chdir(tmp_path)

    assert CheckMarkdownTables(Path(".")) == (
        "README.md: Markdown table columns need alignment",
    ), "Relative repository roots must preserve tracked-file diagnostics"
    assert page.read_bytes() == DRIFTING_TABLE.encode(), "Relative-root checks must be read-only"


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
@pytest.mark.parametrize("final_newline", [False, True])
def test_WritePreservesLineEndingsAndOtherSource(
    tmp_path: Path, newline: str, final_newline: bool,
) -> None:
    """The real CLI changes table padding while preserving surrounding source bytes."""

    page = InitializeRepository(tmp_path, "café.md")
    source = (
        "Intro: café and a trailing space. \n\n" + DRIFTING_TABLE
        + "\n```markdown\n" + DRIFTING_TABLE + "```\n\nLast line"
        + ("\n" if final_newline else "")
    ).replace("\n", newline)
    original = source.encode("utf-8")
    page.write_bytes(original)
    command = [sys.executable, str(TOOL_PATH), "--project-root", str(tmp_path)]
    check = subprocess.run(command, capture_output=True, text=True, check=False)

    assert check.returncode == 1, "The default CLI must fail on source drift"
    assert page.read_bytes() == original, "A CI check must never modify source"
    assert "--write" in check.stdout, "The failure must explain the local repair command"

    write = subprocess.run([*command, "--write"], capture_output=True, text=True, check=False)
    expected = AlignMarkdown(source).encode("utf-8")

    assert write.returncode == 0, "Explicit formatting must repair tracked table drift"
    assert expected != original, "The fixture must exercise an actual table edit"
    assert page.read_bytes() == expected, "The CLI must preserve exact source line endings"

    repeated = subprocess.run([*command, "--write"], capture_output=True, text=True, check=False)

    assert repeated.returncode == 0, "Repeated formatting must pass"
    assert page.read_bytes() == expected, "Repeated formatting must not change any bytes"
    assert repeated.stdout.strip() == "Markdown table alignment: PASS", (
        "A second write must report no changed paths"
    )


def test_MixedLineEndingsAndTableWithoutFinalNewline() -> None:
    """Pure formatting retains each row's newline convention and final EOF boundary."""

    source = "Intro\r\n" + DRIFTING_TABLE.replace("\n", "\r\n", 1).rstrip("\n")
    formatted = AlignMarkdown(source)

    assert [line.endswith("\r\n") for line in formatted.splitlines(keepends=True)] == (
        [line.endswith("\r\n") for line in source.splitlines(keepends=True)]
    ), "Each existing CRLF row must retain its own newline convention"
    assert not formatted.endswith(("\n", "\r")), "Formatting must not add a final newline"


def test_TableBoundaryAndAlignmentMarkers() -> None:
    """Centered columns and malformed or indented following rows keep their meaning."""

    for boundary in ("| unrelated |\n", "    | literal | code |\n"):
        source = "| A | B |\n| :---: | --- |\n| x | y |\n" + boundary
        formatted = AlignMarkdown(source)

        assert formatted.startswith("| A     | B   |\n| :---: | --- |\n"), (
            "Center alignment requires three dashes between its two colons"
        )
        assert formatted.endswith(boundary), "A non-table row must terminate formatting"


def test_EscapesAndLongerFenceClosing() -> None:
    """Escaped delimiters remain cells and fence endings obey marker type and length."""

    assert SplitRow("single\\|cell") == ["single\\|cell"], "An escaped final pipe stays content"
    assert SplitRow("|") is None, "An empty outer delimiter is not a table row"
    literal = "````markdown\n```\n~~~\n" + DRIFTING_TABLE + "`````\n"
    formatted = AlignMarkdown(literal + DRIFTING_TABLE)

    assert formatted == literal + AlignMarkdown(DRIFTING_TABLE), (
        "Shorter or different fences must not close a literal block"
    )


@pytest.mark.parametrize("mode,stage", [("120000", "0"), ("100644", "1")])
def test_UnsupportedIndexEntriesFailBeforeWriting(tmp_path: Path, mode: str, stage: str) -> None:
    """Tracked symbolic links and unresolved merge entries cannot become formatter input."""

    page = InitializeRepository(tmp_path)
    blob = subprocess.run(
        ["git", "hash-object", "README.md"], cwd=tmp_path,
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    entry = f"0 {'0' * 40}\tREADME.md\n{mode} {blob} {stage}\tREADME.md\n"
    subprocess.run(
        ["git", "update-index", "--index-info"], input=entry.encode("utf-8"),
        cwd=tmp_path, check=True,
    )
    indexed = subprocess.run(
        ["git", "ls-files", "--stage", "-z"], cwd=tmp_path,
        capture_output=True, text=True, encoding="utf-8", check=True,
    ).stdout

    assert indexed.startswith(f"{mode} {blob} {stage}\tREADME.md\0"), (
        "The fixture must create the intended Git entry on every platform"
    )

    assert Main(["--project-root", str(tmp_path), "--write"]) == 1, (
        "Unsupported index entries must fail the write command"
    )
    assert page.read_bytes() == DRIFTING_TABLE.encode(), "Rejected paths must not be rewritten"


def test_WorkingTreeSymbolicLinksAreRejected(tmp_path: Path) -> None:
    """A regular Git entry replaced by a working-tree link cannot redirect formatting."""

    page = InitializeRepository(tmp_path)
    target = tmp_path / "untracked.md"
    target.write_bytes(DRIFTING_TABLE.encode())
    page.unlink()

    try:
        page.symlink_to(target)

    except OSError:
        pytest.skip("This environment cannot create a symbolic link")

    assert Main(["--project-root", str(tmp_path), "--write"]) == 1, (
        "Working-tree symbolic links must be rejected"
    )
    assert target.read_bytes() == DRIFTING_TABLE.encode(), "Link targets must remain untouched"


def test_UnavailableTrackedSourceIsAnError(tmp_path: Path) -> None:
    """A missing tracked Markdown file fails explicitly instead of being silently omitted."""

    page = InitializeRepository(tmp_path)
    page.unlink()

    assert Main(["--project-root", str(tmp_path)]) == 1, "Missing tracked source must fail"


def test_NonRepositoryRootIsAnError(tmp_path: Path) -> None:
    """An unavailable Git index must not be mistaken for an empty successful check."""

    assert Main(["--project-root", str(tmp_path)]) == 1, "Unavailable Git ownership must fail"


def test_LocalRepairAndReadOnlyGate(tmp_path: Path) -> None:
    """Local repair fixes owned files while generated output stays outside both commands."""

    page = InitializeRepository(tmp_path)
    generated = tmp_path / "untracked.md"
    generated.write_bytes(DRIFTING_TABLE.encode())
    arguments = ["--project-root", str(tmp_path)]

    assert Main(arguments) == 1, "Unaligned tracked source must fail the check"
    assert Main([*arguments, "--write"]) == 0, "Explicit repair must succeed"
    assert page.read_bytes() == AlignMarkdown(DRIFTING_TABLE).encode(), (
        "The write command must apply the canonical table formatter"
    )
    assert generated.read_bytes() == DRIFTING_TABLE.encode(), "Untracked output must be ignored"
    assert Main(arguments) == 0, "Aligned tracked source must pass the read-only check"
    assert Main([*arguments, "--write"]) == 0, "An already aligned write must succeed unchanged"
