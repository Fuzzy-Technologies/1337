# Independent mutable content-response source

The original Phase 1 checkpoint was **source-only**. Subsequent installed
acceptance now covers eight SDK scenarios and one distinct IPv6 worker scenario;
see the current [capture contract](../../../docs/OWNED_CONTENT_RESPONSE_CAPTURE_CONTRACT.md).
This fixture oracle still supplies independently handwritten expectations: no
producer implementation supplies expected bytes, detections or record values.

`tests/contract/owned_content_response_oracle.py` handwrites 59 response cases:
18 admitted and 41 refused. Twenty raw URL spellings additionally require the
exact safe input refusal and zero contacts. The source bytes are reproducible
Python literals and bounded padding; `oracle.v1.json` freezes their exact lengths,
SHA-256 values, manual decisions and complete field-name truth. This manifest is
test truth only and is never production admission data. Expected worker stdout
uses independent standard-library canonical JSON, without IDs, jobs or ACKs.
The old catalog and every existing fixture remain byte-identical.

The mutable path is `/research/content`; `/alternate/plain` is a second arbitrary
concrete path. `/discover/owned` has exactly two handwritten links to those paths.
Two additional concrete paths exercise exactly 1024 bytes and 64 path segments.
All paths differ from the old three-path capture catalog. The later native pipeline
selects only the seed and its two links. Source mutation uses local `SetCase`,
changes actual headers/body at the identical URL, and requires all accepted
sockets, handlers and original dispatch slots idle. There is no HTTP control
route, generic proxy, outbound operation, session, credential or shell.

The matrix distinguishes missing/fixed/body-decoy originals, identical headers
with different UTF-8 bodies, Date/Server/ETag/custom values, raw header order/case/
OWS, empty field presence, an empty body and a valid UTF-8 BOM. It reaches inclusive
64 fields, 4096-byte lines, 16384-byte headers, 65536-byte bodies and 81920-byte
wires. Refusals cover overflow, duplicate/missing/noncanonical Content-Length,
invalid UTF-8, early EOF, one extra byte at maximum body, a second response,
withheld EOF, redirects, wrong statuses/media and every forbidden field family.

The explicit contract clarification is frozen: otherwise-canonical declared
Content-Length above 65536 is body-policy, checked before unbounded conversion or
body allocation. Missing/duplicate/noncanonical length and early/trailing EOF are
protocol. Header/line overflow is response-policy before value interpretation.
New refusal keys are exactly schema_version/profile/outcome/error. No refused
record includes original bytes, their digest, a fixture case ID or header truth.

`owned_content_response_target.py` reuses reviewed `CrawlGraphServer` dispatch,
slot, physical-close and join owners. Its accept registration keeps exact contact
counts even for invalid/partial/over-limit requests. Additional bounded facts
record actual accepted local/peer address and port. IPv4 and IPv6 bind only literal
`127.0.0.1` or `[::1]`, with held ephemeral ports at least 1024. It starts nothing
on import; the explicit context manager owns actual creation in a later phase.

Each original fixture connection has one seven-second deadline covering request,
send and held-peer observation. This exceeds the product's unchanged five-second
deadline so withholding EOF can genuinely force refusal. It never releases local
EOF while held; actual peer EOF or separately named known reset is recorded first.
Late or locally induced EOF cannot satisfy timely remote termination. Held full
sends are labelled `sent-peer-ended`, without claiming the fixture sent EOF.
Before teardown, one Event wait consumes at most three seconds and only the
remaining original deadline, including still-owned dispatch slots after physical
socket close. Physical admission/socket/handler cleanup is separately bounded at
three seconds and remains mandatory if that observation fails. There are at most
64 retained contacts, four simultaneous dispatches and 2048-byte complete requests.

The context manager always writes `content-source-final.json` after cleanup,
including failures. It preserves original counts, partial requests, actual sent
bytes, endpoint facts, unknown/late peer signals, errors, physical owner state and
separate cleanup-return/failure facts. An unavailable constructor stays unobserved,
never zero-contact success. This artifact contains test-owned source originals;
it is not product evidence and does not imply successful capture.

Rejection-marker and digest checks later apply only to the new product attempt's
stdout/diagnostics/stage/events/publications/model delta. Independent target facts,
this oracle and prior acknowledged originals may legitimately contain those
known test bytes/digests; they are not newly retained rejected product evidence.
No real secret is used. Old historical originals must never be deleted to satisfy
such a check. A connection-error case must later hold its own bound non-listening
socket; random ports or unrelated local services are never probed.

Pure checks use source rendering and finite fake descriptors/events only. The
fake handler tests exercise both address families, exact original GET/sends,
normal EOF versus held peer EOF, false-idle socket/handler/dispatch owners,
nonrenewing deadline waits and constructor/body/wait/cleanup failures. They prove
source invariants, not a working worker or scanner.

The wider acceptance objective uses frozen producer interfaces and source review.
Separate installed cohorts must cover live mutable bytes, IPv6, empty/BOM/boundary
framing and held EOF; do not repeat whole passing SDK/crawler cohorts. Then bind
actual worker execution and seven acknowledged roles through the new explicit
SAFE plus retention selection. A separately approved PASSIVE v2 header attempt
must use the explicit new source family and preserve the existing predicate/
Finding fingerprint. A joined native pipeline must keep structural crawler and
legacy exact-URL Endpoints distinct, preserve triage and reuse, remove the original
root, relocate canonical workspace/evidence, and replay/report offline without
Put/Save/contact. Cross-family tests need actual independently acknowledged old
and new receipts and must refuse foreign profile/receipt/provider/media bindings.
Missing capabilities fail required acceptance; failed or unexecuted work stays
unassessed. This wider objective is not a claim that every matrix row has already
executed. CLI enrollment itself still needs its own frozen reviewed contract.
