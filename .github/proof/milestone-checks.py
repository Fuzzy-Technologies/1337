"""Verify the AST/remaining naming debt and run every test in both physically changed modules."""
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from xml.etree import ElementTree

root = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
tmp = Path(os.environ["RUNNER_TEMP"]).resolve()
cmd = [sys.executable,"-I",str(tmp/"local-names.py"),"--gate-directory",str(root/"tools")]
proc = subprocess.run(cmd,cwd=root,check=True,capture_output=True,timeout=140)
assert not proc.stderr or b"Traceback" not in proc.stderr, proc.stderr[-2500:]
receipt=json.loads(proc.stdout)
(tmp/"unit-local-oracle.json").write_bytes(proc.stdout)
assert receipt["baseline_before"] == 2076 and receipt["baseline_after"] == 2072 and receipt["unit_local_remaining"] == 0
print("UNIT_LOCAL_AST", json.dumps(receipt,sort_keys=True),flush=True)
files = ["tests/unit/test_ci_local_image_product.py","tests/unit/test_release_finalize.py"]
xml = tmp/"unit-local-cases.xml"
subprocess.run([sys.executable,"-I","tools/python_naming.py"],cwd=root,check=True)
subprocess.run([sys.executable,"-I","-m","pytest","-o","addopts=","--strict-config","--strict-markers",
                "--no-cov","-n","2","--dist=loadscope","--timeout=120","--junitxml",str(xml),"-q",*files],
               cwd=root,check=True,timeout=220)
cases = ElementTree.parse(xml).findall(".//testcase")
counts = {p:len([c for c in cases if c.get("classname","").endswith(Path(p).stem)]) for p in files}
assert all(counts.values()) and sum(counts.values()) == len(cases)
assert all(not any(c.find(t) is not None for t in ("failure","error","skipped")) for c in cases)
print("UNIT_LOCAL_CASES",json.dumps({"source":os.environ["APPROVED_SOURCE_SHA"],"tree":os.environ["PRODUCT_TREE"],
      "by_file":counts,"unit_local_remaining":0,"sha256":sha256(xml.read_bytes()).hexdigest()},sort_keys=True))
