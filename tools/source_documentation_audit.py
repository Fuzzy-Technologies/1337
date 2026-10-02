# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0
"""Inventory authored Python documentation without importing inspected modules."""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
import re
import stat
import tokenize
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SOURCE_ROOTS = ("src", "tests", "tools")
OPTIONAL_ROOTS = ("tools",)
EXCLUDED_DIRECTORIES = ("__pycache__",)
COPYRIGHT_HEADER = "# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies"
LICENSE_HEADER = "# SPDX-License-Identifier: Apache-2.0"
LANGUAGE_PATTERN = re.compile(r"[\u0400-\u04ff\u3400-\u9fff]")
DEBT_PATTERN = re.compile(r"\b(?:TO" + r"DO|FIX" + r"ME|TE" + r"MP|HA" + r"CK)\b")
LIMITATIONS = (
    "Structural docstring checks do not prove semantic accuracy or completeness.",
    "Language review detects Cyrillic/CJK only; it cannot certify English prose.",
    "Comment review detects debt markers only; semantic staleness needs human review.",
    "Static export candidates do not declare API stability; computed exports need review.",
    "Annotation presence does not prove typing correctness; run the canonical type checker.",
)


@dataclass(frozen=True)
class Finding:
    """A stable diagnostic tied to source coordinates and a structural rule."""

    path: str
    line: int
    symbol: str
    rule: str
    detail: str
    severity: str = "error"


def Parameters(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[ast.arg, ...]:
    """Return parameters excluding implicit receiver objects.

    Args:
        node: Authored function or method syntax.

    Returns:
        Parameters in their declaration order, including variadic parameters.
    """

    arguments = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
    variadic = tuple(argument for argument in (node.args.vararg, node.args.kwarg) if argument)

    return tuple(
        argument for argument in (*arguments, *variadic) if argument.arg not in {"self", "cls"}
    )


def Sections(docstring: str) -> dict[str, list[str]]:
    """Parse Google-style section bodies without interpreting prose.

    Args:
        docstring: Cleaned AST docstring text.

    Returns:
        Recognized section headings and their indented source lines.
    """

    sections: dict[str, list[str]] = {}
    current = ""

    for line in docstring.splitlines():
        if line in {"Args:", "Returns:", "Yields:", "Raises:", "Attributes:"}:
            current = line[:-1]
            sections.setdefault(current, [])

        elif line and not line[0].isspace():
            current = ""

        elif current and line.strip():
            sections[current].append(line)

    return sections


def Symbols(tree: ast.Module) -> list[tuple[str, ast.AST]]:
    """Collect qualified authored scopes in deterministic declaration order.

    Args:
        tree: Parsed source module.

    Returns:
        Module, class, function, and nested callable scopes with qualified names.
    """

    symbols: list[tuple[str, ast.AST]] = [("<module>", tree)]

    def Visit(node: ast.AST, prefix: str) -> None:
        """Traverse lexical scopes without executing decorators or expressions.

        Args:
            node: Current syntax node.
            prefix: Enclosing scope name.
        """

        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                name = f"{prefix}.{child.name}" if prefix else child.name
                symbols.append((name, child))
                Visit(child, name)

            else:
                Visit(child, prefix)

    Visit(tree, "")

    return symbols


def AuditFile(path: Path, root: Path) -> dict[str, Any]:
    """Inspect one regular Python source using AST and comment tokens only.

    Args:
        path: Source path already checked for symlink traversal.
        root: Repository boundary used for relative diagnostics.

    Returns:
        Content digest, authored/exported inventory, and deterministic findings.
    """

    relative = path.relative_to(root).as_posix()
    findings: list[Finding] = []
    record: dict[str, Any] = {"path": relative, "symbols": [], "exports": [], "findings": []}

    def Add(line: int, symbol: str, rule: str, detail: str, severity: str = "error") -> None:
        """Append a stable finding without retaining arbitrary source content.

        Args:
            line: Source coordinate.
            symbol: Qualified authored scope.
            rule: Stable machine-readable rule identifier.
            detail: Bounded structural diagnosis.
            severity: Error for enforceable rules, review for uncertain applicability.
        """

        findings.append(Finding(relative, line, symbol, rule, detail, severity))

    try:
        raw = path.read_bytes()
        record["sha256"] = hashlib.sha256(raw).hexdigest()
        source = tokenize.detect_encoding(io.BytesIO(raw).readline)[0]
        text = raw.decode(source)
        tree = ast.parse(text, filename=relative)
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
        executable = bool(path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))

    except (OSError, UnicodeError, SyntaxError, LookupError, tokenize.TokenError):
        Add(1, "<module>", "SOURCE_UNREADABLE", "Cannot safely parse or tokenize source.")
        record["findings"] = [asdict(finding) for finding in findings]

        return record

    lines = text.splitlines()
    header_lines = lines[:5]

    if COPYRIGHT_HEADER not in header_lines:
        Add(1, "<module>", "SPDX_COPYRIGHT", "Required ownership header is absent or differs.")

    if LICENSE_HEADER not in header_lines:
        Add(1, "<module>", "SPDX_LICENSE", "Required Apache-2.0 header is absent or differs.")

    shebang = lines[0] if lines and lines[0].startswith("#!") else ""
    record["executable"] = executable
    record["shebang"] = bool(shebang)

    if executable and not shebang:
        Add(1, "<module>", "SHEBANG_MISSING", "Executable source needs an interpreter shebang.")

    if shebang and not executable:
        Add(1, "<module>", "SHEBANG_NONEXECUTABLE", "Shebang is reserved for executable scripts.")

    if shebang and shebang not in {"#!/usr/bin/env python3", "#!/usr/bin/python3"}:
        Add(1, "<module>", "SHEBANG_INTERPRETER", "Interpreter is outside the accepted Python set.")

    exports: list[str] = []
    authored_bindings: list[str] = []
    explicit_exports: list[str] | None = None
    export_declaration = "implicit-public-definitions"

    for statement in tree.body:
        if isinstance(statement, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            authored_bindings.append(statement.name)

        elif isinstance(statement, (ast.Import, ast.ImportFrom)):
            authored_bindings.extend(
                alias.asname or alias.name.split(".")[0] for alias in statement.names
            )

        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]

            authored_bindings.extend(
                node.id for target in targets for node in ast.walk(target)
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
            )

            if any(isinstance(target, ast.Name) and target.id == "__all__" for target in targets):
                export_declaration = "explicit-literal"

                try:
                    declared = ast.literal_eval(statement.value) if statement.value else None

                    if not isinstance(declared, (tuple, list)) or not all(
                        isinstance(name, str) for name in declared
                    ):
                        raise ValueError("Non-string export declaration")
                    explicit_exports = list(declared)

                except (ValueError, TypeError, SyntaxError, RecursionError):
                    export_declaration = "computed-unresolved"
                    Add(
                        statement.lineno, "__all__", "EXPORT_REVIEW",
                        "Computed exports need review."
                    )

    exports = explicit_exports if explicit_exports is not None else [
        binding for binding in authored_bindings if not binding.startswith("_")
    ]
    record["authored_bindings"] = sorted(set(authored_bindings))
    record["exports"] = sorted(set(exports))
    record["export_declaration"] = export_declaration

    symbols = Symbols(tree)
    scope_types = {name: type(node) for name, node in symbols}

    for name, node in symbols:
        line = getattr(node, "lineno", 1)
        docstring = ast.get_docstring(node)  # Only authored docstring syntax is inspected.
        kind = "module" if isinstance(node, ast.Module) else type(node).__name__
        record["symbols"].append({"name": name, "line": line, "kind": kind})

        if not docstring or not docstring.strip():
            Add(line, name, "DOCSTRING_MISSING", "Authored scope has no nonempty first docstring.")

        elif LANGUAGE_PATTERN.search(docstring):
            Add(
                line, name, "LANGUAGE_REVIEW",
                "Non-Latin script needs human language review.", "review"
            )

        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        is_interface = not relative.startswith("tests/") and all(
            not part.startswith("_") for part in name.split(".")
        ) and not any(
            scope_types.get(".".join(name.split(".")[:index])) in {
                ast.FunctionDef, ast.AsyncFunctionDef
            }
            for index in range(1, len(name.split(".")))
        )
        severity = "error" if is_interface else "review"
        parameters = Parameters(node)
        sections = Sections(docstring or "")
        documented = set()

        for entry in sections.get("Args", []):
            match = re.fullmatch(r"\s+\*{0,2}([A-Za-z_]\w*)(?:\s*\([^)]*\))?:\s*\S.*", entry)

            if match:
                documented.add(match[1])

        for parameter in parameters:
            if parameter.annotation is None:
                Add(parameter.lineno, name, "PARAMETER_ANNOTATION", parameter.arg, severity)

            if docstring and parameter.arg not in documented:
                Add(line, name, "ARGS_DOCUMENTATION",
                    f"No Google-style description: {parameter.arg}", severity)

        if node.returns is None:
            Add(line, name, "RETURN_ANNOTATION", "Explicit return annotation is absent.", severity)

        elif not (isinstance(node.returns, ast.Constant) and node.returns.value is None):
            if docstring and not (sections.get("Returns") or sections.get("Yields")):
                Add(
                    line, name, "RETURN_DOCUMENTATION",
                    "No nonempty Returns/Yields section.", severity
                )

    for token in tokens:
        if token.type != tokenize.COMMENT:
            continue

        if LANGUAGE_PATTERN.search(token.string):
            Add(token.start[0], "<comment>", "LANGUAGE_REVIEW",
                "Non-Latin comment needs review.", "review")

        if DEBT_PATTERN.search(token.string):
            Add(token.start[0], "<comment>", "COMMENT_DEBT_MARKER", "Unresolved debt marker.")

    record["findings"] = [asdict(finding) for finding in sorted(
        findings, key=lambda finding: (finding.line, finding.symbol, finding.rule, finding.detail)
    )]

    return record


def Audit(root: Path) -> dict[str, Any]:
    """Scan explicitly owned roots without following directory or file symlinks.

    Args:
        root: Existing repository boundary.

    Returns:
        Deterministic inventory, limitations, exclusions, and failing diagnostics.
    """

    files: list[dict[str, Any]] = []
    boundary_findings: list[dict[str, Any]] = []
    exclusions: list[str] = []
    absent_optional_roots: list[str] = []

    for source_root in SOURCE_ROOTS:
        directory = root / source_root

        if not directory.is_symlink() and not directory.exists() and source_root in OPTIONAL_ROOTS:
            absent_optional_roots.append(source_root)
            continue

        if directory.is_symlink() or not directory.is_dir():
            boundary_findings.append(asdict(Finding(
                source_root, 1, "<root>", "ROOT_UNSAFE", "Required root is missing or linked."
            )))
            continue

        def WalkError(error: OSError) -> None:
            """Record traversal failures instead of silently omitting unreadable source.

            Args:
                error: Filesystem traversal exception.
            """

            boundary_findings.append(asdict(Finding(
                source_root, 1, "<directory>", "TRAVERSAL_FAILED",
                f"Directory traversal failed with errno {error.errno}."
            )))

        for current, directories, filenames in os.walk(
            directory, followlinks=False, onerror=WalkError
        ):
            directories.sort()
            safe_directories = []

            for name in directories:
                candidate = Path(current) / name
                relative = candidate.relative_to(root).as_posix()

                if candidate.is_symlink():
                    boundary_findings.append(asdict(Finding(
                        relative, 1, "<directory>", "SYMLINK_REFUSED",
                        "Linked directory not scanned."
                    )))

                elif name in EXCLUDED_DIRECTORIES:
                    exclusions.append(relative)

                else:
                    safe_directories.append(name)

            directories[:] = safe_directories

            for name in sorted(filenames):
                if not name.endswith(".py"):
                    continue
                path = Path(current) / name

                if path.is_symlink() or not path.is_file():
                    boundary_findings.append(asdict(Finding(
                        path.relative_to(root).as_posix(), 1, "<file>", "SYMLINK_REFUSED",
                        "Linked or nonregular Python file not scanned."
                    )))
                    continue
                files.append(AuditFile(path, root))

    findings = boundary_findings + [finding for file in files for finding in file["findings"]]
    findings.sort(key=lambda finding: (
        finding["path"], finding["line"], finding["symbol"], finding["rule"], finding["detail"]
    ))
    counts = {rule: sum(finding["rule"] == rule for finding in findings)
              for rule in sorted({finding["rule"] for finding in findings})}

    return {
        "schema_version": 1, "status": "FAIL" if any(
            finding["severity"] == "error" for finding in findings
        ) else "PASS",
        "roots": list(SOURCE_ROOTS), "absent_optional_roots": absent_optional_roots,
        "optional_roots": list(OPTIONAL_ROOTS),
        "excluded_directory_names": list(EXCLUDED_DIRECTORIES),
        "excluded_paths": sorted(exclusions), "limitations": list(LIMITATIONS),
        "files": sorted(files, key=lambda file: file["path"]), "findings": findings,
        "counts": counts,
        "role_counts": {source_root: {
            severity: sum(finding["path"].split("/")[0] == source_root
                          and finding["severity"] == severity for finding in findings)
            for severity in ("error", "review")
        } for source_root in SOURCE_ROOTS},
    }


def Markdown(report: dict[str, Any]) -> str:
    """Render a compact review report without dumping arbitrary source prose.

    Args:
        report: Deterministic machine-readable audit output.

    Returns:
        Markdown summary with limitations and coordinate-linked findings.
    """

    lines = ["# Source documentation audit", "", f"Status: {report['status']}", "",
             f"Files: {len(report['files'])}; findings: {len(report['findings'])}.", "",
             "## Limitations", ""]
    lines.extend(f"- {limitation}" for limitation in report["limitations"])
    lines.extend(["", "## Findings", "", "| Path:line | Symbol | Rule | Severity | Detail |",
                  "|-----------|--------|------|----------|--------|"])

    for finding in report["findings"]:
        cells = [
            f"{finding['path']}:{finding['line']}", finding["symbol"], finding["rule"],
            finding["severity"], finding["detail"]
        ]
        cells = [str(cell).replace("|", "\\|").replace("\n", " ") for cell in cells]
        lines.append("| " + " | ".join(cells) + " |")

    return "\n".join(lines) + "\n"


def Main(argv: Sequence[str] | None = None) -> int:
    """Emit inventory or fail the structural contract with no scan-time imports.

    Args:
        argv: Optional explicit CLI arguments for deterministic invocation.

    Returns:
        Zero for inventory or clean checks, one for findings, two for I/O failure.
    """

    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--inventory", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, default=Path(".tmp/source-documentation-audit"))
    arguments = parser.parse_args(argv)

    try:
        if arguments.root.is_symlink():
            raise ValueError("Linked repository root is not accepted.")
        root = arguments.root.resolve(strict=True)
        output = arguments.output if arguments.output.is_absolute() else root / arguments.output
        relative_output = output.relative_to(root)
        cursor = root

        for component in relative_output.parts:
            cursor = cursor / component

            if cursor.is_symlink():
                raise ValueError("Linked report output is not accepted.")

        output = output.resolve()
        output.relative_to(root)
        report = Audit(root)
        output.mkdir(parents=True, exist_ok=True)
        (output / "inventory.json").write_text(
            json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8"
        )
        (output / "inventory.md").write_text(Markdown(report), encoding="utf-8")

    except (OSError, RuntimeError, ValueError):
        print("Source audit failed: repository or report output cannot be accessed.")

        return 2

    print(f"Source audit {report['status']}: {len(report['files'])} files, "
          f"{len(report['findings'])} findings; inspect inventory.json and inventory.md.")

    return 1 if arguments.check and report["status"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(Main())
