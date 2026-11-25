# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Exercise newly requested IDs through one clean installed wheel after original input deletion."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import venv
from pathlib import Path

import pytest

from tools.release_delivery import ProvisionLocalWheelRuntime

ROOT = Path(__file__).resolve().parents[2]
PROBE = r'''
"""Use only the installed product, an owned synthetic catalog and real saved custody."""

import hashlib
import io
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from fuzzy1337 import intelligence_cwe_commands as commands
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import LocalModelStore
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

consumer = Path.cwd()
assert Path(commands.__file__).is_relative_to(Path(sys.prefix)), "The probe imported a checkout."
assert hashlib.sha256(Path(commands.__file__).read_bytes()).hexdigest() == sys.argv[1], (
    "The installed command bytes differ from the selected wheel source."
)
console = Path(sys.executable).parent / ("1337.exe" if sys.platform == "win32" else "1337")
root = consumer / "owned workspace"
LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Installed CWE lookup"), "installed-cwe")
LocalModelStore(root).Create()
xml = (
    '<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-8" Name="Owned lookup" '
    'Version="5.0" Date="2026-11-03"><Weaknesses>'
    '<Weakness ID="79" Name="Originally selected" Status="Stable"/>'
    '<Weakness ID="20" Name="New source name é 😀" Status="Stable"/>'
    '</Weaknesses><Views><View ID="1000" Name="Owned view" Status="Stable"/>'
    '</Views></Weakness_Catalog>'
).encode()
buffer = io.BytesIO()
member = zipfile.ZipInfo("cwec_v5.0.xml")
member.create_system = 3
member.external_attr = 0o100644 << 16
member.compress_type = zipfile.ZIP_DEFLATED

with zipfile.ZipFile(buffer, "w") as archive:
    archive.writestr(member, xml)

raw = buffer.getvalue()
source = consumer / "caller original.zip"
source.write_bytes(raw)


def Call(arguments, expected=0):
    """Execute the actual installed console without a checkout on its import path."""

    result = subprocess.run([str(console), "intel", "cwe", *arguments, "--json"],
        cwd=consumer, capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == expected, result.stdout + result.stderr
    assert result.stderr == "", "Installed metadata lookup leaked a traceback."

    return json.loads(result.stdout)


def Files(directory):
    """Capture every saved owner byte independently of object deserialization."""

    return {str(path.relative_to(directory)): path.read_bytes()
            for path in directory.rglob("*") if path.is_file()}


arguments = ["import", str(root), str(source), "--catalog-version", "5.0",
    "--expected-sha256", hashlib.sha256(raw).hexdigest(), "--identifier", "CWE-79",
    "--scope", "scope:owned"]
original = Call(arguments)
record = LocalEvidenceStore(root / "evidence").Get(original["raw_id"])
assert LocalEvidenceStore(root / "evidence").Read(record.reference) == raw, (
    "Original product custody lost the complete owned ZIP."
)
assert original["selection"]["requested_ids"] == ["CWE-79"], "The original selection changed."
otherArguments = list(arguments)
otherArguments[otherArguments.index("--identifier") + 1] = "CWE-20"
otherArguments[otherArguments.index("--scope") + 1] = "scope:other"
other = Call(otherArguments)
beforeModel = LocalModelStore(root).Open()
beforeWorkspace = LocalWorkspaceStore(root).Open()
moved = consumer / "copied and reopened workspace"
shutil.copytree(root, moved)
shutil.rmtree(root)
source.unlink()
before = Files(moved)
lookupArguments = ["lookup", str(moved), "--selection", original["selection_id"],
    "--receipt", original["receipt_id"], "--identifier", "CWE-9999999",
    "--identifier", "CWE-20", "--identifier", "CWE-1000"]
looked = Call(lookupArguments)
assert looked["selection"] == original["selection"], "Lookup replaced the saved selection."
assert looked["selection_reference"] == original["selection_reference"], (
    "Lookup replaced the original acquisition-envelope reference."
)
assert looked["source"] == original["source"], "Lookup changed original source or notice facts."
assert looked["lookup"]["selection"]["matched_ids"] == ["CWE-20"], "New IDs were not selected."
assert looked["lookup"]["selection"]["records"][0]["name"] == "New source name é 😀", (
    "Installed lookup changed Unicode source data."
)
assert looked["lookup"]["selection"]["unsupported_entries"] == [
    {"identifier": "CWE-1000", "source_kind": "View"}
], "The lookup relabeled a known unsupported source kind."
assert looked["lookup"]["selection"]["unmatched_ids"] == ["CWE-9999999"], (
    "An absent source ID acquired an assertion."
)
assert looked["lookup"]["selection"]["raw_sha256"] == hashlib.sha256(raw).hexdigest(), (
    "The on-demand result lost its verified original ZIP identity."
)
assert looked["lookup"]["persistence"] == "not-attempted", "Lookup claimed a new publication."
assert looked["model_commit"] == "not-attempted", "Lookup claimed a model save."
assert LocalModelStore(moved).Open() == beforeModel, "Copied lookup changed saved model facts."
assert LocalWorkspaceStore(moved).Open() == beforeWorkspace, (
    "Copied lookup changed the owning workspace."
)
assert Files(moved) == before, "Read-only lookup changed saved owner bytes."

guarded = """
"Run the installed CLI with external actions and persistence denied."

import sys


def Guard(event, arguments):
    "Refuse network resolution, subprocesses and shell execution during lookup."

    if event in {"socket.connect", "socket.connect_ex", "socket.getaddrinfo",
                 "subprocess.Popen", "os.system", "os.exec"}:
        raise AssertionError("Offline saved-original lookup attempted an external action.")


sys.addaudithook(Guard)
from fuzzy1337 import intelligence_cwe_commands as commands
from fuzzy1337.cli import Main
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.model import LocalModelStore


def Refuse(*arguments, **options):
    "Refuse acquisition and owner writes after original custody verification."

    raise AssertionError("Saved-original lookup attempted acquisition or persistence.")


commands.AcquireLocalCweSelection = Refuse
commands.ReadLocalIntel = Refuse
LocalEvidenceStore.Put = Refuse
LocalModelStore.Save = Refuse
raise SystemExit(Main(sys.argv[1:]))
"""
result = subprocess.run([sys.executable, "-I", "-c", guarded, "intel", "cwe",
    *lookupArguments, "--json"], cwd=consumer, capture_output=True, text=True,
    timeout=30, check=False)
assert result.returncode == 0, result.stdout + result.stderr
assert json.loads(result.stdout) == looked, "Guarded installed Main changed console semantics."
assert Files(moved) == before, "Read-only lookup changed saved owner bytes."
reopened = Call(["inspect", str(moved), "--selection", original["selection_id"],
    "--receipt", original["receipt_id"]])
assert reopened["selection"] == original["selection"] and "lookup" not in reopened, (
    "On-demand lookup changed accepted exact-inspection behavior."
)
mixed = list(lookupArguments)
mixed[mixed.index("--receipt") + 1] = other["receipt_id"]
refused = Call(mixed, expected=4)
assert "lookup" not in refused and "selection" not in refused, (
    "Failed original custody emitted usable source assertions."
)
assert Files(moved) == before, "Read-only lookup changed saved owner bytes."
blob = moved / "evidence" / record.reference.locator
blob.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
corrupted = Files(moved)
refused = Call(lookupArguments, expected=4)
assert "lookup" not in refused and "selection" not in refused, (
    "Failed original custody emitted usable source assertions."
)
assert Files(moved) == corrupted, "Integrity refusal changed damaged saved owner bytes."
print(json.dumps({"status": "passed", "new_matched": ["CWE-20"],
                  "original_requested": ["CWE-79"], "guarded_module": True}))
'''


def Invoke(arguments, directory):
    """Return a completed child result while retaining every actual nonzero failure."""

    result = subprocess.run(arguments, cwd=directory, capture_output=True, text=True,
                            timeout=120, check=False)
    assert result.returncode == 0, result.stdout + result.stderr

    return result.stdout


@pytest.mark.integration
def test_CleanWheelLooksUpNewIdsFromCopiedOriginalCustodyWithoutExternalInput(tmp_path):
    """Prove installed source identity, new selection, copied replay and corruption refusal."""

    output = tmp_path / "wheel"
    Invoke([sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(output)],
           ROOT)
    wheels = list(output.glob("*.whl"))
    assert len(wheels) == 1, "The installed lookup selector requires exactly one newly built wheel."
    environment = tmp_path / "installed"
    venv.EnvBuilder(with_pip=True).create(environment)
    python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    consumer = tmp_path / "consumer"
    consumer.mkdir()
    Invoke([str(python), "-m", "pip", "--isolated", "install", "--no-index", "--no-deps",
            str(wheels[0])], consumer)
    ProvisionLocalWheelRuntime(wheels[0], python, consumer)
    expected = hashlib.sha256(
        (ROOT / "src/fuzzy1337/intelligence_cwe_commands.py").read_bytes(),
    ).hexdigest()
    result = json.loads(Invoke([str(python), "-I", "-c", PROBE, expected], consumer))
    assert result == {"status": "passed", "new_matched": ["CWE-20"],
                      "original_requested": ["CWE-79"], "guarded_module": True}, (
        "The independent installed consumer lost original custody or new-ID lookup semantics."
    )
