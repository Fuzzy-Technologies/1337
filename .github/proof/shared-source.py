"""Read two independent original artifact families after deleting both input files and the original workspace."""
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

console = Path(sys.executable).with_name("1337")
original_fixture = Path(sys.argv[1]).resolve()
sarif_raw = original_fixture.read_bytes()
sarif_pin = sha256(sarif_raw).hexdigest()
assert len(sarif_raw) == 1453 and sarif_pin == "d50cd7b2dc4ef6890c4ee5c905a2591fde69e8f5fee0e4c99dfceab0d947294d"
syslog_raw = b'<34>1 2026-11-25T18:35:10.100000-00:00 node1 audit 17 LOG1 - rotated'
syslog_pin = sha256(syslog_raw).hexdigest()
calls = 0

def invoke(home, *args, status=0):
    global calls
    calls += 1
    completed = subprocess.run([str(console), *map(str, args), "--json"], cwd=home, capture_output=True, timeout=30)
    assert completed.returncode == status and not completed.stderr, (args[:3],completed.returncode,completed.stderr[:1000],completed.stdout[:600])
    return json.loads(completed.stdout)

def inventory(root):
    return {str(p.relative_to(root)):sha256(p.read_bytes()).hexdigest() for p in root.rglob("*") if p.is_file()}

with tempfile.TemporaryDirectory(prefix="copied-shared-evidence-") as tmp:
    home = Path(tmp)
    root = home/"original workspace"
    copied = home/"relocated workspace"
    inputs = home/"owned inputs"
    inputs.mkdir()
    sarif, syslog = inputs/"verified original.sarif", inputs/"original.syslog"
    sarif.write_bytes(sarif_raw)
    syslog.write_bytes(syslog_raw)
    invoke(home,"workspace","create",root,"--id","saved-artifacts","--name","Saved artifact acceptance")
    invoke(home,"scope","create",root,"--id","owned")
    initial = inventory(root)
    one = invoke(home,"trace","syslog","import",root,"--file",syslog,"--source-id","fixture.syslog",
                 "--source-version","export-7","--source-locator","opaque:offline","--expected-sha256",syslog_pin,
                 "--framing","single","--scope","scope:owned","--owner","operator:owned","--read-consent-reference","read:archive")
    assert one["raw_ack"] == one["receipt_ack"] == "confirmed" and one["record_count"] == 1
    two = invoke(home,"bridge","sarif","import",root,sarif,"--scope","owned","--owner","operator:owned",
                 "--read-consent-reference","read:archive","--expected-sha256",sarif_pin)
    assert two["original_commit"] == two["receipt_commit"] == "confirmed"
    assert two["model_commit"] == two["workspace_commit"] == "not-attempted"
    current = inventory(root)
    assert {name:current.get(name) for name in initial} == initial
    assert len({one["raw_id"],one["receipt_id"],two["original_id"],two["receipt_id"]}) == 4
    shutil.copytree(root,copied)
    shutil.rmtree(root)
    shutil.rmtree(inputs)
    assert not root.exists() and not inputs.exists() and inventory(copied) == current
    def readsys(receipt,pin,code=0):
        return invoke(home,"trace","syslog","inspect",copied,"--receipt",receipt,"--expected-sha256",pin,status=code)
    def readsar(original,receipt,pin,code=0):
        return invoke(home,"bridge","sarif","inspect",copied,"--original",original,"--receipt",receipt,
                      "--expected-sha256",pin,status=code)
    first = readsys(one["receipt_id"],syslog_pin)
    second = readsar(two["original_id"],two["receipt_id"],sarif_pin)
    assert first["record_count"] == 1 and len(first["records"]) == 1
    record, = first["records"]
    assert (record["timestamp"],record["timestamp_offset"],record["offset_known"],record["timestamp_utc"]) == (
        "2026-11-25T18:35:10.100000-00:00","-00:00",False,"2026-11-25T18:35:10.100000Z")
    assert second["ack_basis"] == "verified-present" and two["projection"] == second["projection"]
    proj = second["projection"]
    run, = proj["runs"]
    fact, = run["results"]
    loc, = fact["locations"]
    assert proj["inline_result_count"] == 1 and proj["validation_scope"] == "consumed-fields-only"
    assert (run["tool_name"],run["tool_version"],run["column_kind"]) == ("ESLint",None,None)
    assert (fact["declared_rule_id"],fact["source_level"],fact["message_text"]) == ("no-unused-vars","error","'x' is assigned a value but never used.")
    assert (loc["artifact_index"],loc["start_line"],loc["start_column"],loc["end_line"]) == (0,1,5,None)
    assert loc["uri"] == "file:///C:/dev/sarif/sarif-tutorials/samples/Introduction/simple-example.js"
    refused = readsys(two["receipt_id"],syslog_pin,4)
    assert "records" not in refused and refused["status"] == "failed"
    for ids in ((one["raw_id"],one["receipt_id"],syslog_pin),(two["original_id"],one["receipt_id"],sarif_pin),
                (one["raw_id"],two["receipt_id"],sarif_pin)):
        refused = readsar(*ids,code=4)
        assert "projection" not in refused and refused["status"] == "failed"
    assert readsys(one["receipt_id"],syslog_pin) == first
    assert readsar(two["original_id"],two["receipt_id"],sarif_pin) == second
    assert inventory(copied) == current, "A read or refused cross-profile selection changed retained evidence"
    print("SHARED_SOURCE_REPLAY",json.dumps({"source_files_deleted":2,"deleted_original_workspace":True,
          "retained_files":len(current),"preserved_initial_files":len(initial),"distinct_evidence_handles":4,
          "cross_profile_refusals":4,"cli_calls":calls,"syslog_sha256":syslog_pin,"external_sarif_sha256":sarif_pin,
          "result":"passed"},sort_keys=True))
