# Python module-level naming audit

This checkpoint records a bounded audit for [#432](https://github.com/Fuzzy-Technologies/1337/issues/432)
at commit `1de7b2f65485135316d756407d7c806aca6cf241`. It covers all 19 Python files
under `tools/` and the first 24 files in Git tree order among direct
`src/fuzzy1337/*.py` entries smaller than 10,000 bytes. File content was checked
against the Git tree's blob IDs.

Python 3.13's module symbol table selects assigned snake_case names, including
names with a single leading underscore, while excluding imports, constants
and function or class definitions. The AST identifies names in literal
`__all__` assignments. A synthetic check confirmed that the audit reports an
exported module assignment and ignores imported names, uppercase constants,
class fields and function locals.

The sample contained one candidate, `_coverage_gate` in
[`dev_commands.py`](../src/fuzzy1337/dev_commands.py). In that file, its two
references are values in the developer command table. The command keys
`"unit"` and `"test"` are distinct from the binding. The binding also appears
at `4eecc4f91fb6de68137f2fe0163517022b766742`, the base of #433. The sample
does not establish which three names the original audit counted. Check external
references before renaming this candidate.
