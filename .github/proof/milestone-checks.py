"""Exercise the installed RFC 5424 record parser, custody and transport with old IOC regressions."""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from xml.etree import ElementTree

root = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
tmp = Path(os.environ["RUNNER_TEMP"]).resolve()
sources = ["src/fuzzy1337/" + v + ".py" for v in ("syslog_records","syslog_artifacts","syslog_commands","ioc_commands","shell","command_registry","cli","bridge_commands","bridge_sarif")]
tests = ["tests/unit/test_syslog_records.py","tests/unit/test_syslog_artifacts.py","tests/unit/test_syslog_commands.py",
         "tests/e2e/test_syslog_cli.py","tests/unit/test_ioc_commands.py","tests/integration/test_ioc_command_workflow.py",
         "tests/unit/test_bridge_sarif.py","tests/unit/test_bridge_commands.py","tests/e2e/test_bridge_sarif_cli.py",
         "tests/unit/test_command_registry.py","tests/unit/test_shell.py","tests/unit/test_cli.py",
         "tests/unit/test_api_reference.py::test_InventoryCoversEverySourceModule",
         "tests/unit/test_python_style.py::test_RepositoryPythonSourcesFollowCompleteStyleContract",
         "tests/unit/test_source_documentation_headers.py::test_SourceDocumentationAndHeadersMatchContract",
         "tests/unit/test_locale_documentation.py::test_MissingTranslationsRemainHonest"]
p=[sys.executable,"-I","-m"]
commands=[("ruff",[*p,"ruff","check",*sources,"tests/syslog_helpers.py","tests/sarif_helpers.py",*[v.split("::")[0] for v in tests]]),
          ("mypy",[*p,"mypy",*sources]),("naming",[sys.executable,"-I","tools/python_naming.py"]),
          ("markdown-tables",[sys.executable,"-I","tools/markdown_tables.py"])]
xml=tmp/"saved-syslog-cases.xml"
coverage=tmp/"saved-syslog-coverage.json"
covcfg=tmp/"saved-syslog.coveragerc"
covcfg.write_text("[run]\nbranch = True\nparallel = True\npatch = subprocess\n[report]\nfail_under = 0\n",encoding="utf-8")
modules=("syslog_records","syslog_artifacts","syslog_commands","bridge_sarif","bridge_commands")
commands.append(("pytest",[*p,"pytest","-o","addopts=","--strict-config","--strict-markers","-n","2","--dist=loadscope",
                          "--timeout=150","--rootdir",str(root),"-q","--tb=short","--junitxml",str(xml),
                          "--cov-config="+str(covcfg),"--cov-branch","--cov-fail-under=0",
                          "--cov-report=json:"+str(coverage),*["--cov=fuzzy1337."+v for v in modules],*tests]))
statuses={}
for name,cmd in commands:
    statuses[name]=subprocess.run(cmd,cwd=root,check=False).returncode
print("SHARED_SAVED_SOURCE_CHECKS",json.dumps(statuses,sort_keys=True),flush=True)
cases=ElementTree.parse(xml).findall(".//testcase") if xml.exists() else []
counts=Counter(c.get("classname") for c in cases)
failures=[(c.get("classname"),c.get("name")) for c in cases if any(c.find(t) is not None for t in ("failure","error","skipped"))]
if failures: print("SHARED_SAVED_SOURCE_FAILED_CASES",json.dumps(failures),flush=True)
report=json.loads(coverage.read_bytes()) if coverage.exists() else {}
covered={}
for m in modules:
    matches=[s["summary"] for name,s in report.get("files",{}).items() if name.endswith("/"+m+".py")]
    if len(matches)==1:
        s=matches[0]
        covered[m]=round(100*(s["covered_lines"]+s["covered_branches"])/(s["num_statements"]+s["num_branches"]),3)
receipt={"source":os.environ["APPROVED_SOURCE_SHA"],"tree":os.environ["PRODUCT_TREE"],"collected":len(cases),
         "by_module":dict(counts),"combined_coverage":covered,"statuses":statuses,"failure_count":len(failures),
         "junit_sha256":hashlib.sha256(xml.read_bytes()).hexdigest() if xml.exists() else None,
         "wheel":json.loads((tmp/"hosted-proof-wheel.json").read_bytes())}
print("SHARED_SAVED_SOURCE_RESULT",json.dumps(receipt,sort_keys=True),flush=True)
assert all(v==0 for v in statuses.values()) and not failures and len(cases)>0
assert all(m in covered and covered[m]>80 for m in modules),covered
assert "test_InstalledConsoleReopensCopiedOriginalWithoutInputAndRefusesCorruption" in {c.get("name") for c in cases}

assert "test_InstalledSarifImportPreservesExternalFactsAfterSourceDeletionAndCopiedReplay" in {c.get("name") for c in cases}
