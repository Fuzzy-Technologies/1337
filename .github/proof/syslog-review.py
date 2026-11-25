# UNEXECUTED independent selector. Run with the selected installed wheel's Python:
# /selected/venv/bin/python -I /tmp/p64_review.py /selected/venv/bin/1337
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

console = Path(sys.argv[1]).resolve()
python = console.with_name("python")
raw = (br'<13>1 2026-11-25T10:15:30.123456+05:30 h app 42 ID [x@32473 a="one" a="two" e="x\]y\"z\\"] '
       + b"\xef\xbb\xbf" + "café".encode()
       + b"\r\n<0>1 - - - - - -\n<191>1 2026-11-25T04:45:30.123456Z h app - ID - ")
pin = hashlib.sha256(raw).hexdigest()
assert len(raw) == 166 and pin == "816d37c01ab6c31459eec35ae611efa1d26eb9d4b8576db774310089991a82f2"

with tempfile.TemporaryDirectory(prefix="p64-independent-") as temporary:
    outside = Path(temporary)
    root = outside / "owned"
    source = outside / "original.log"
    source.write_bytes(raw)
    setup = ("from pathlib import Path; import sys; import fuzzy1337.syslog_artifacts as m; "
             "assert Path(sys.prefix).resolve() in Path(m.__file__).resolve().parents; "
             "from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration; "
             "LocalWorkspaceStore(Path(sys.argv[1])).Create(WorkspaceConfiguration('neutral'), 'review.syslog')")
    subprocess.run([str(python), "-I", "-c", setup, str(root)], cwd=outside, check=True)

    def inventory():
        return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in root.rglob("*") if p.is_file()}

    def invoke(arguments, expected=0):
        process = subprocess.run([str(python), "-I", str(console), "trace", "syslog", *map(str, arguments), "--json"],
                                 cwd=outside, capture_output=True, check=False)
        assert process.returncode == expected, (process.returncode, process.stdout, process.stderr)
        result = json.loads(process.stdout)
        assert result["exit_code"] == expected and not process.stderr
        return result

    def importer(path, digest, framing):
        return ["import", root, "--file", path, "--source-id", "fixture.syslog",
                "--source-version", "export-7", "--source-locator", "opaque:offline",
                "--expected-sha256", digest, "--framing", framing,
                "--scope", "collection:fixture", "--owner", "actor:synthetic",
                "--read-consent-reference", "read:synthetic"]

    initial = inventory()
    acquired = invoke(importer(source, pin, "lines"))
    assert all(inventory().get(name) == digest for name, digest in initial.items())
    assert acquired["record_count"] == 3 and "records" not in acquired
    assert acquired["raw_ack"] == acquired["receipt_ack"] == "confirmed"
    receipt = acquired["receipt_id"]
    before = inventory()

    def inspected(*extra):
        result = invoke(["inspect", root, "--receipt", receipt, "--expected-sha256", pin, *extra])
        assert inventory() == before
        return result

    default = inspected()
    exported = inspected("--export-records")
    assert inspected() == default
    records = exported["records"]
    assert [(r["byte_offset"], r["byte_length"]) for r in records] == [(0, 99), (101, 16), (118, 48)]
    assert [r["terminator"] for r in records] == ["CRLF", "LF", None]
    assert [r["record_index"] for r in records] == [1, 2, 3]
    assert records[0]["timestamp_utc"] == records[2]["timestamp_utc"] == "2026-11-25T04:45:30.123456Z"
    parameters = records[0]["structured_data"][0]["parameters"]
    assert [(p["name"], p["value"]) for p in parameters] == [("a", "one"), ("a", "two"), ("e", 'x]y"z\\')]
    assert all("value" not in p for r in default["records"] for e in (r["structured_data"] or []) for p in e["parameters"])
    assert records[1]["message"] is None
    assert records[2]["message"]["byte_offset"] == 166 and records[2]["message"]["byte_length"] == 0
    for r in records:
        if r["message"] is not None:
            assert set(r["message"]) == {"byte_offset", "byte_length", "content_byte_offset",
                                         "content_byte_length", "encoding", "sha256"}
    assert "café" not in json.dumps(exported, ensure_ascii=False)
    moved = outside / "relocated"
    root.rename(moved)
    root = moved
    source.unlink()
    assert inspected() == default
    for selected_receipt, selected_pin in [(acquired["raw_id"], pin), (receipt, "0" * 64)]:
        refused = invoke(["inspect", root, "--receipt", selected_receipt, "--expected-sha256", selected_pin], 4)
        assert refused["status"] == "failed" and "records" not in refused and refused["record_count"] is None
        assert inventory() == before

    unknown = outside / "offset.log"
    unknown.write_bytes(b"<13>1 2026-11-25T10:15:30-00:00 h app 42 ID -")
    unknown_pin = hashlib.sha256(unknown.read_bytes()).hexdigest()
    unknown_acquired = invoke(importer(unknown, unknown_pin, "single"))
    unknown_before = inventory()
    unknown_result = invoke(["inspect", root, "--receipt", unknown_acquired["receipt_id"],
                             "--expected-sha256", unknown_pin])
    stamp = unknown_result["records"][0]
    assert stamp["timestamp_offset"] == "-00:00" and stamp["offset_known"] is False
    assert stamp["timestamp_utc"] is None and stamp["utc_status"] == "unknown-offset"
    assert inventory() == unknown_before
    print(json.dumps({"result": "passed", "console_calls": 9, "source_sha256": pin,
                      "original_receipt_id": receipt,
                      "unknown_offset_receipt_id": unknown_acquired["receipt_id"]}, sort_keys=True))
