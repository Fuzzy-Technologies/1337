# Owned saved RFC 5424 logs

This development-wheel operation is an **Experimental version-one source-only**
profile for #85. It accepts one explicitly supplied non-secret original file and
retains its exact bytes using the existing local evidence owner. It does not
claim a Core Event, an authenticated identity, an incident, compromise,
applicability, risk or a timeline relationship. It does not contact a log
producer, run a daemon, execute a request or acquire data from a provider.

Use the wheel built from the reviewed source commit, with its declared runtime
dependencies installed; retain the full source commit and wheel checksum.
The published 0.3.0 wheel does not contain this development operation.

## Import and independently anchored reopen

Choose absolute physical paths to an existing workspace and an owned regular
file. The existing workspace command can initialize an empty workspace; no model
or scope document is required by this profile. The scope reference below is a
collection attribution string, not authorization. The owner and read-consent
references are declarations about reading the selected file, not authentication
or permission to assess any host named inside it.

First independently calculate the SHA-256 of the complete original with your
normal trusted local checksum tool. Do not take that checksum from the receipt
being checked. For an explicitly selected LF/CRLF export:

```text
1337 trace syslog import /absolute/workspace \
  --file /absolute/original.log \
  --source-id owned.saved-log --source-version export-7 \
  --source-locator opaque:owned-export \
  --expected-sha256 LOWERCASE_ORIGINAL_SHA256 --framing lines \
  --scope collection:review --owner actor:operator \
  --read-consent-reference read:original-file --json
```

The locator is descriptive and is never opened. Source version is your declared
export/source version. Optional `--source-tool-version DECLARED` records an
explicitly known original producer version; omitted remains unknown. Neither is
the actual parser ID `syslog-rfc5424` or parser version `1`.

Successful import returns exit `0`, count, actual source SHA-256, original
`raw_id`, original `receipt_id`, original provenance/read declaration and two
separate confirmed storage acknowledgements. Retain the receipt manifest ID
and independently calculated original checksum outside the workspace.

After deleting the caller's original file, copy the **complete** workspace
directory and reopen the copy:

```text
1337 trace syslog inspect /absolute/copied-workspace \
  --receipt sha256:ORIGINAL_RECEIPT_MANIFEST_SHA256 \
  --expected-sha256 LOWERCASE_ORIGINAL_SHA256 --json
```

This reads only the independently selected original chain. It checks the closed
receipt, original manifest identities, workspace/source/provenance, roles,
media, byte budgets, complete raw bytes and their hash, then reparses the same
original and compares the canonical normalized-document checksum. No record is
presented before all checks succeed. Repeated inspection of the same pins is
deterministic and does not refresh the acquisition clock or write any file.
Unrelated corrupt acquisitions are not selected automatically.

Default inspection shows source order, record/field byte coordinates, original
header values, timestamp/offset and unknown values. SD IDs and parameter names
are visible; SD parameter values are withheld. To explicitly expose the ordered
decoded SD values, use `inspect ... --export-records --json`. This option is
refused for human output. **No default or explicit record export includes MSG
text or MSG bytes.** Message metadata contains only original byte ranges,
encoding classification and raw message hash. Read the retained raw evidence
through `LocalEvidenceStore` only when you explicitly need the authorized original.

Terminal source fields are JSON escaped, including human record lines, so source
control characters cannot become terminal controls. Diagnostics contain fixed
categories and no rejected arguments, filenames, parameter values or MSG text.

## Admitted file and RFC profile

The grammar is [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424.html), version `1`.
RFC 5424 does not define saved-file framing. Select one explicitly:

| Framing | Saved-file contract |
| --- | --- |
| `single` | The entire file is exactly one RFC message. LF, CR, NUL and arbitrary unmarked MSG octets remain data. No final newline is trimmed. |
| `lines` | An explicit storage restriction: one message per byte LF or CRLF delimiter. Only that delimiter is excluded from the record span. No embedded LF is representable within a message. Final EOF without a delimiter is accepted. Unicode line separators are data. Blank frames are refused. |

NILVALUE `-` becomes JSON `null`; an absent MSG is `null`, while a present-empty
MSG after a significant final SP has a zero-length span. Headers remain opaque
source strings, preserving case. HOSTNAME is not DNS validation and PROCID is
not PID/identity validation.

PRI is exactly `0..191` without a leading zero; facility/severity remain original
numeric codes. Header bounds are HOSTNAME 255, APP-NAME 48, PROCID 128 and MSGID
32 printable ASCII bytes. Timestamps require uppercase `T`/`Z`, a valid calendar,
seconds `00..59`, and at most six fractional digits. Original spelling and
fractional precision are preserved. Following
[RFC 3339 section 4.3](https://www.rfc-editor.org/rfc/rfc3339.html#section-4.3)
as updated by [RFC 9557 section 2](https://www.rfc-editor.org/rfc/rfc9557.html#section-2),
known UTC is separate from the declaration of a local numeric offset:

| Original timestamp suffix | `offset_known` | UTC result when representable |
| --- | --- | --- |
| NILVALUE `-` | `null` | `null`, `utc_status: unknown` |
| `Z` | `false` | Same known UTC clock, `utc_status: available` |
| `-00:00` | `false` | Same known UTC clock, `utc_status: available` |
| `+00:00` | `true` | Same known UTC clock, `utc_status: available` |
| Other numeric offset | `true` | Convert the declared local time to UTC, `utc_status: available` |

`offset_known` means only that the source declares its local numeric offset;
it does not describe UTC availability, a geographic timezone, DST or clock
accuracy. `timestamp` and `timestamp_offset` retain exact source spelling.
For example, `10:15:30.123456Z`, `10:15:30.123456-00:00` and
`10:15:30.123456+00:00` all yield the known UTC `10:15:30.123456Z` while
their local-offset declarations remain distinct. No local timezone is inferred.

Zero-offset UTC spellings, including valid source year `0000`, can be represented
without a calendar conversion. A nonzero-offset conversion outside Python's
calendar range retains the original timestamp and local-offset knowledge, with
`timestamp_utc: null` and `utc_status: unrepresentable`. Acquisition time is
never substituted.

Structured-data elements and parameters keep source order. Duplicate SD IDs are
refused, while repeated parameter names are preserved. SD-NAME uses its RFC
printable-ASCII exclusions, including the permitted opening bracket. Private
SD IDs containing `@` require a decimal enterprise-number form with optional
decimal dot suffixes; no registry assignment or producer authenticity is checked.
Only `\"`, `\\` and `\]` are unescaped; an unknown escape preserves its
backslash and following character. Parameter values require valid UTF-8 and may
contain control characters. BOM-marked MSG must contain valid UTF-8 after the
BOM; unmarked MSG remains arbitrary octets and is not decoded or interpreted.

All offsets are zero-based **byte** offsets in the complete original; lengths
exclude framing delimiters. Record indexes and physical header line numbers are
one-based. Header and structured-data coordinates include the original NIL
tokens; parameter value spans address the escaped original lexeme, not the
decoded character count. Message raw spans include the BOM; content spans
exclude it. No normalization changes the retained raw source.

Independent profile ceilings are 1 MiB original, 256 records, 16 KiB per
message, 32 SD elements, 64 SD parameters per message, 4096 raw escaped bytes per
parameter, 4 MiB canonical document, 32 KiB profile receipt and 8 MiB ASCII-safe
terminal output. These are product storage/consumer ceilings, not RFC transport
limits. Empty files, unsupported versions, malformed consumed grammar and
over-limit inputs are explicit refusals; the parser never returns partial records.

## Storage, refusals and recovery

The existing `LocalEvidenceStore` owns immutable blobs and manifests.
The profile-specific original role is `syslog-rfc5424-original`; its separate
receipt role is `syslog-rfc5424-receipt`. Their metadata is not an IOC TSV
snapshot, IOC receipt v1 or a new global Core/custody type. Construction and
retained reads preflight role/media/size before the owner's eager blob read.

The canonical receipt binds the exact original raw manifest, source declarations,
actual parser/version, explicit framing, fixed limits, descriptive file-read
references, original parse state and normalized-document checksum. It stores no
new normalized snapshot or message body. Original read/acquisition times belong
to the existing evidence provenance; source-declared record time stays separate.

A checksum mismatch returns `digest-rejected`, exit `4`, with no publications.
A correctly hashed but malformed admitted-size original returns `parse-rejected`,
exit `4`, with verified original raw and refusal receipt, but no usable records.
Reopening that receipt reproduces the refusal. Empty or physically unsafe files
are rejected before publication. Invalid selections return `2`; integrity or
storage/presentation failure returns `4`; interruption returns `130`.

Raw and receipt publications are independently acknowledged, not one transaction.
Each ACK is `not-attempted`, `unknown` or `confirmed`. Earlier confirmed records
survive a later error; a failed response does not promise rollback. A lost reply
may leave valid immutable bytes or records. Retained recovery is possible only
if the original receipt actually committed and you independently retained its
manifest ID and source pin. If it did not commit, correct/repeat the explicit
owned-file operation with the original acquisition facts; do not invent a receipt.
Inspection reports `ack_basis: verified-present`, rather than rewriting what the
original caller observed. There are no automatic retries or orphan cleanup.

Existing owner filesystem checks reject observed links/reparse points and unsafe
kinds, and observe selected-file identity during the bounded read. They do not
provide hostile-writer OS isolation or cryptographic authenticity. Operators own
the physical storage and exclude hostile concurrent writers. Hashing is not
redaction or encryption: supply only authorized non-secret files.

## Python consumer

Public Experimental SDK version one consists of
`syslog_records.ParseSavedSyslog`, `syslog_artifacts.SyslogSource`,
`SyslogAcquisition`, `ImportSavedSyslogFile` and `LoadSavedSyslog` (including
`SyslogSource.ToDict`). Other symbols and all CLI transport helpers are Internal.

```python
import hashlib
import json
from pathlib import Path

from fuzzy1337.artifact_inputs import ArtifactReadConsent
from fuzzy1337.syslog_artifacts import ImportSavedSyslogFile, LoadSavedSyslog, SyslogSource

original = Path("/absolute/original.log")
expected = hashlib.sha256(original.read_bytes()).hexdigest()  # Independent original pin.
source = SyslogSource("owned.saved-log", "export-7", "opaque:owned-export", expected, "lines")
acquired = ImportSavedSyslogFile(
    Path("/absolute/workspace"), original, source,
    scopeReference="collection:review",
    consent=ArtifactReadConsent("actor:operator", "read:original-file"),
)
if acquired.state == "succeeded" and acquired.receipt is not None:
    receiptId = acquired.receipt.evidence_id  # Retain independently for later use.
    reopened = LoadSavedSyslog(Path("/absolute/copied-workspace"), receiptId, expected)
    if reopened.state == "succeeded" and reopened.document is not None:
        document = json.loads(reopened.document)
```

Copy the complete workspace before the example's reopen step. Production SDK
code must check the actual returned state and optional document before use.
The pure parser accepts bytes plus an independent hash and performs no I/O; its
canonical UTF-8 JSON document contains profile/parser/source/framing/limits and
source-order records. This is not a Core Event decoder. See
[ADR 0156](adr/0156-owned-saved-rfc5424.md) and the
[underlying owner contract](EVIDENCE.md).
