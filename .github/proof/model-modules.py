"""Use both non-editable wheels for the complete existing wire rejection suite."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
from xml.etree import ElementTree

tmp=Path(os.environ["RUNNER_TEMP"])
root=Path(os.environ["GITHUB_WORKSPACE"])
wire="tests/unit/test_model_save_wire_boundary.py"
actual={}
for label,venv,work,other in (("before","model-before-venv",tmp/"model-parent",[]),("after","retained-proof-runtime",root,
       ["tests/unit/test_model.py","tests/e2e/test_model_save_wire_boundary_cli.py"])):
    xml=tmp/("model-sorting-tests-"+label+".xml")
    args=[str(tmp/venv/"bin/python"),"-I","-m","pytest","-o","addopts=","--strict-config","--strict-markers","--no-cov",
          "-n","2","--dist=loadscope","--timeout","120","--junitxml",str(xml),"-q",wire,*other]
    subprocess.run(args,cwd=work,timeout=300,check=True)
    cases=ElementTree.parse(xml).findall(".//testcase")
    assert cases and all(all(c.find(k) is None for k in ("failure","error","skipped")) for c in cases)
    actual[label]={c.get("classname")+"::"+c.get("name") for c in cases if c.get("classname").endswith("test_model_save_wire_boundary")}
    print("MODEL_SORTING_TEST_CASES",json.dumps({"label":label,"cases_by_module":dict(Counter(c.get("classname") for c in cases)),
       "xml_sha256":hashlib.sha256(xml.read_bytes()).hexdigest()},sort_keys=True),flush=True)
assert actual["before"] and actual["before"]==actual["after"]
