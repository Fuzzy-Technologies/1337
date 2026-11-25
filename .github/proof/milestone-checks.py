"""Run the new local source-set, legacy single-source and disk persistence paths against an installed wheel."""
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from xml.etree import ElementTree

root=Path(os.environ["GITHUB_WORKSPACE"]).resolve()
tmp=Path(os.environ["RUNNER_TEMP"])
py=[sys.executable,"-I","-m"]
sources=["src/fuzzy1337/"+name+".py" for name in ("intelligence_set_commands","intelligence_commands","command_registry","shell")]
tests=["tests/unit/test_intelligence_sets.py","tests/e2e/test_intelligence_sets_cli.py",
       "tests/unit/test_intelligence.py","tests/unit/test_intelligence_acquisition.py","tests/unit/test_intelligence_commands.py",
       "tests/e2e/test_intelligence_cli.py","tests/integration/test_intelligence_acquisition_persistence.py","tests/integration/test_intelligence_persistence.py",
       "tests/contract/test_intelligence_contract.py","tests/unit/test_command_registry.py","tests/unit/test_shell.py",
       "tests/unit/test_python_style.py::test_RepositoryPythonSourcesFollowCompleteStyleContract",
       "tests/unit/test_source_documentation_headers.py::test_SourceDocumentationAndHeadersMatchContract",
       "tests/unit/test_api_reference.py::test_InventoryCoversEverySourceModule",
       "tests/unit/test_locale_documentation.py::test_MissingTranslationsRemainHonest"]
xml=tmp/"local-source-set.xml"
cov=tmp/"local-source-set-coverage.json"
cfg=tmp/"local-source-set.coveragerc"
cfg.write_text("[run]\nbranch = True\nparallel = True\npatch = subprocess\n[report]\nfail_under = 0\n",encoding="utf-8")
cmds={"ruff":[*py,"ruff","check",*sources,*[t.split("::")[0] for t in tests],"tests/intelligence_set_helpers.py"],
      "typing":[*py,"mypy",*sources],"names":[sys.executable,"-I","tools/python_naming.py"],
      "markdown-tables":[sys.executable,"-I","tools/markdown_tables.py"],
      "pytest":[*py,"pytest","-o","addopts=","--strict-config","--strict-markers","-n","2","--dist=loadscope",
                "--timeout","180","-q","--tb=short","--junitxml",str(xml),"--cov-config="+str(cfg),
                "--cov=fuzzy1337.intelligence_set_commands","--cov-branch","--cov-fail-under=0","--cov-report=json:"+str(cov),*tests]}
statuses={name:subprocess.run(cmd,cwd=root,timeout=400,check=False).returncode for name,cmd in cmds.items()}
cases=ElementTree.parse(xml).findall(".//testcase") if xml.exists() else []
failed=[c.get("name") for c in cases if any(c.find(k) is not None for k in ("failure","error","skipped"))]
counts=Counter(c.get("classname") for c in cases)
covered=None
if cov.exists():
    infos=json.loads(cov.read_bytes()).get("files",{})
    parts=[f["summary"] for p,f in infos.items() if p.endswith("/intelligence_set_commands.py")]
    if len(parts)==1:
        x=parts[0]
        covered=round(100*(x["covered_lines"]+x["covered_branches"])/(x["num_statements"]+x["num_branches"]),3)
record={"source":os.environ["APPROVED_SOURCE_SHA"],"tree":os.environ["PRODUCT_TREE"],"by_file":dict(counts),"total":len(cases),
        "failed":failed,"checks":statuses,"combined_coverage":covered,"wheel":json.loads((tmp/"hosted-proof-wheel.json").read_bytes()),
        "junit_sha256":sha256(xml.read_bytes()).hexdigest() if xml.exists() else None}
print("COMBINED_INTELLIGENCE_ACCEPTANCE",json.dumps(record,sort_keys=True),flush=True)
assert all(code==0 for code in statuses.values()) and not failed and covered and covered>80
assert "test_InstalledFourFeedSetReopensThenSavesOnePreviewedObservation" in {c.get("name") for c in cases}
