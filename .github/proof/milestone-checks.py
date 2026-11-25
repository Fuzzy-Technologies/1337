"""Exercise the proposed passive CI tool in a real locked Python environment."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from xml.etree import ElementTree

root = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
temp = Path(os.environ["RUNNER_TEMP"]).resolve()
tests = ["tests/unit/test_passive_test_gate.py","tests/unit/test_passive_integration.py",
         "tests/unit/test_passive_scope.py","tests/unit/test_python_naming.py",
         "tests/unit/test_python_style.py::test_RepositoryPythonSourcesFollowCompleteStyleContract",
         "tests/unit/test_source_documentation_headers.py::test_SourceDocumentationAndHeadersMatchContract"]
p = [sys.executable, "-I", "-m"]
subprocess.run([*p, "ruff", "check", "tools/passive_test_gate.py","tests/unit/test_passive_test_gate.py"], cwd=root, check=True)
subprocess.run([sys.executable, "-I", "tools/python_naming.py"], cwd=root, check=True)
out = temp / "p65-focused.xml"
subprocess.run([*p, "pytest", "-o", "addopts=", "--strict-config", "--strict-markers", "--no-cov",
                "-n", "2", "--dist=loadscope", "--timeout=150", "--rootdir", str(root), "-q", "--junitxml", str(out), *tests],
               cwd=root, check=True)
cases=ElementTree.parse(out).findall(".//testcase")
counts=Counter(case.attrib["classname"] for case in cases)
assert len(counts)>=6
assert all(not any(c.find(t) is not None for t in ("failure","error","skipped")) for c in cases)
receipt={"source":os.environ["APPROVED_SOURCE_SHA"],"tree":os.environ["PRODUCT_TREE"],"pass":len(cases),
         "junit_sha256":hashlib.sha256(out.read_bytes()).hexdigest(),"by_module":dict(counts)}
print("P65_CANDIDATE_TESTS",json.dumps(receipt,sort_keys=True))
