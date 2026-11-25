"""Verify only the reviewed local-name cleanup against immutable Git objects."""
import ast
import json
import os
import subprocess
BASE = os.environ["STYLE_BASE"]
CANDIDATE = os.environ["STYLE_SHA"]
OWNED = "tests/unit/test_owned_response_parent.py"
RUNTIME = "tests/unit/test_runtime_commands.py"
BASELINE = "contracts/python-naming-baseline.json"
PAIRS = {
    OWNED: "observed_errors observedErrors original_append originalAppend original_capture originalCapture "
           "original_verify originalVerify original_path_info originalPathInfo path_observations pathObservations "
           "path_info pathInfo handle_info handleInfo expected_kind expectedKind original_put originalPut",
    RUNTIME: "handle_calls handleCalls path_calls pathCalls",
}
GROUPS = [
    ("custody_diagnostics", "observed_errors original_append original_capture original_path_info original_verify path_observations"),
    ("private_system", "handle_info path_info"),
    ("test_CoherentUnitViewStillRefusesExactCtimeOnlyMutation", "handle_info path_info"),
    ("test_FakeClockLateBudgetsNeverBecomeSuccess", "original_put"),
    ("test_FakePosixViewRepairsProvenCrossApiCtimeMismatchOnly", "handle_info path_info"),
    ("test_PortableDiagnosticsObserveFirstOriginalFailureBeforeOrDuringCustody", "expected_kind"),
]
REMOVED = {(OWNED, "local", "top." + scope, name) for scope, names in GROUPS for name in names.split()}
REMOVED |= {(RUNTIME, "local", "top.test_EveryOriginalReadViewRequiresOnePhysicalLink", name)
            for name in ("handle_calls", "path_calls")}
def Require(condition, message):
    if not condition:
        raise ValueError(message)
def Show(commit, path):
    return subprocess.check_output(["git", "--no-replace-objects", "show", commit + ":" + path])
class Reverse(ast.NodeTransformer):
    def __init__(self, mapping):
        self.mapping = mapping
    def visit_Name(self, node):
        Require(node.id not in self.mapping.values(), "Unconverted old Name remains")
        node.id = self.mapping.get(node.id, node.id)
        return node
    def visit_Nonlocal(self, node):
        Require(not set(node.names).intersection(self.mapping.values()), "Old nonlocal remains")
        node.names = [self.mapping.get(name, name) for name in node.names]
        return node
for path, pairs in PAIRS.items():
    words = pairs.split()
    reverse = dict(zip(words[1::2], words[::2], strict=True))
    before = ast.parse(Show(BASE, path), type_comments=True, optimize=0)
    after = ast.parse(Show(CANDIDATE, path), type_comments=True, optimize=0)
    Require(not set(reverse).intersection(node.id for node in ast.walk(before) if isinstance(node, ast.Name)),
            "A new local name already exists in the original module")
    Require(ast.dump(before, include_attributes=False) ==
            ast.dump(Reverse(reverse).visit(after), include_attributes=False), "Non-name AST change: " + path)
expected = Show(BASE, BASELINE)
Require(len(REMOVED) == 16, "Expected exactly sixteen local baseline records")
for row in sorted(REMOVED):
    line = ("  " + json.dumps(list(row)) + ",\n").encode()
    Require(expected.count(line) == 1, "Expected baseline record is missing or duplicated")
    expected = expected.replace(line, b"", 1)
Require(expected == Show(CANDIDATE, BASELINE), "Baseline contains another byte change")
print("PASS: complete ASTs equal after Name/Nonlocal reversal; exactly 16 local baseline lines removed")
