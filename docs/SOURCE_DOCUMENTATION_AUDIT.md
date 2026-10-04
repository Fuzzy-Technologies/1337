# Source documentation audit

1337 uses `tools/source_documentation_audit.py` to inventory the authored Python
surface and diagnose structural documentation/ownership gaps. It implements the
role boundary in [Source documentation](SOURCE_DOCUMENTATION.md). It parses source
with Python's AST and comment tokenizer; it never imports inspected modules,
evaluates decorators, resolves security plugins, or executes runtime code.

```bash
python tools/source_documentation_audit.py --inventory
python tools/source_documentation_audit.py --check
```

Both commands write deterministic `inventory.json` and `inventory.md` into the
ignored `.tmp/source-documentation-audit/` directory. `--root` selects an explicit
repository boundary; `--output` selects a report directory inside that boundary.
Relative output paths are resolved from the selected root. Linked root/output
paths and output paths escaping the root are refused. Output contains
relative source paths, content SHA-256 digests, declared scopes and bindings,
export candidates, source coordinates, stable rule identifiers, error/review
severity, per-root counts, limitations, and explicit exclusions. No timestamp or
host-specific absolute path enters the report.

`--inventory` exits zero when it successfully produces a report, even when the
report records existing errors. `--check` exits one for any enforcement error;
it exits zero only when the structural contract passes. Both modes exit two for
an inaccessible repository or unwritable report output. Parse, read, and traversal
failures are enforcement errors, never silently skipped files. A successful
inventory command does **not** mean the source contract passes.

## Scope and enforcement

| Area                  | Enforced structural checks                                       |
|-----------------------|------------------------------------------------------------------|
| `src/`, `tests/`      | Required roots; all authored scopes have nonempty docstrings     |
| `tools/`              | Scanned when present; legitimate absence recorded explicitly     |
| All inspected files   | Required SPDX ownership/license; executable/shebang consistency  |
| Public source/tool API| Parameter/return annotations; Google-style Args/Returns/Yields   |
| Private/nested/tests  | Contract section and annotation recommendations remain review    |
| Comments/docstrings   | Cyrillic/CJK detection flags human language review               |
| Comments              | Forbidden unresolved debt markers produce enforcement errors     |

Public interface candidates are top-level callables or class methods whose
qualified names have no private component, outside `tests/`. Nested callables
remain review suggestions even when their local names begin with capitals.
Implicit `self`/`cls` receivers do not need parameter annotations or Args entries.
All remaining parameters, including variadic parameters, need descriptions for
interface candidates. `None` return annotations need no Returns section; other
annotated returns need a nonempty Returns or Yields section. Missing return
annotations are diagnosed separately. Tests require concise purpose documentation;
redundant sections describing pytest parameters are **not** an enforcement gate.
Important private/callback contracts still need human assessment under the source
contract; name-based applicability cannot reliably identify their significance.

Files need these exact headers in their first five lines:

```python
# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0
```

The tool accepts `#!/usr/bin/env python3` or `#!/usr/bin/python3` for executable
Python scripts. Shebangs in files without any executable bit are diagnosed;
ordinary source modules use no shebang. Platform-specific file mode differences
must be resolved by the reviewer rather than silently normalized by the audit.

Only `*.py` files in the three declared roots are inspected. Non-Python assets and
other roots are outside this inventory. `__pycache__` directories are the sole
excluded directory names; every discovered exclusion is recorded. Directory/file
symlinks are refused even if their target is inside the boundary. There is no
allowlist suppressing existing first-party source failures.

## Human review remains necessary

AST checks prove structural presence, not correctness. Review API descriptions
against actual inputs, outputs, exceptions, side effects, lifecycle, security
constraints, and compatibility. Annotation presence cannot prove typing accuracy;
run the canonical type checker as well.

Cyrillic/CJK detection cannot certify English prose and misses other non-English
languages. Debt-marker detection cannot establish whether ordinary comments are
stale or useful. Review language and comment meaning separately. These limitations
are serialized in every report; the tool never labels semantic documentation or
language correctness as proven.

Static authored bindings include declared classes/functions, assignments, and
imports. Export candidates use literal `__all__` when present; otherwise they use
public top-level bindings. Computed `__all__` is an unresolved enforcement finding
and is not executed. Export candidates do **not** declare API stability. Static
analysis does not resolve dynamically created attributes, wildcard imports,
conditional rebinding, or decorator-generated signatures; compare the inventory
with the project's independently declared API/stability contract.

Use review findings to prioritize substantive hardening, not to generate signature
restatement or empty boilerplate. Existing baseline gaps remain visible until a
separate remediation change addresses them. This audit adds no runtime imports,
API renames, formatting rewrites, or first-party suppression list.
