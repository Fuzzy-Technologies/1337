# Selected CWE ZIP/XML decoding

`fuzzy1337.intelligence_cwe_selection` is an Experimental pure decoder for one
complete supplied ZIP and an explicit selection of 1..64 canonical CWE IDs.
Its four exports are `CweSelectedRecord`, `CweUnsupportedEntry`, `CweSelection`
and `ParseCweSelection`. It performs no acquisition, storage, receipt handling,
replay, CLI inspection, model mutation or current-clock lookup. The ZIP/XML
helpers are Internal and do not supply a generic archive or XML API.

## Exact input modes and source meaning

| Explicit catalog version | Required XML namespace       | Descriptive schema | Sole ZIP member  |
| ------------------------ | ---------------------------- | ------------------ | ---------------- |
| `5.0`                    | `http://cwe.mitre.org/cwe-8` | `8.0`              | `cwec_v5.0.xml`  |
| `4.21`                   | `http://cwe.mitre.org/cwe-7` | `7.4`              | `cwec_v4.21.xml` |

The catalog root must have the exact namespace, Name, selected Version and a
valid `YYYY-MM-DD` Date. The retained `catalog_date` has `date_precision="day"`;
there is no invented midnight, timezone, `effective_at` or publisher instant.
Names and the six source status labels
Deprecated/Draft/Incomplete/Obsolete/Stable/Usable remain source assertions.
They do not establish severity, target applicability or risk.

Only direct namespace-qualified Weakness entries become selected records.
Selected Category, Grouping and View IDs remain separate known unsupported
entries with their exact `source_kind`. In mode 5.0, both Category and Grouping
are recognized; one is never renamed into the other. Mode 4.21 admits Categories
and Views but rejects a Groupings collection as unsupported grammar.

Truly absent IDs form `unmatched_ids`, meaning absent from recognized entry
kinds in these supplied bytes. Weakness, unsupported and absent partitions are
sorted, disjoint and cover the exact request. Zero Weakness matches is valid.
Unsupported and absent never become fabricated Weakness records or zero risk.
Every recognized entry's consumed ID/Name/Status is validated, including
unselected entries; duplicate IDs within or across kinds refuse the whole input.

This is consumed-field parsing, not full XSD validation. Rich schema fields,
relationships, lifecycle history and membership are not projected as mappings
or applicability. Their bytes and parser events still consume resource budgets.
The unchanged legacy `cwe-xml-7` reader, schema-one snapshots and shared limits
remain separate; filtered XML or a namespace substitution cannot supply legacy
source custody.

## Small owned example

This example creates explicitly fictional input in memory. It is not an
official catalog, publisher-source acceptance or a legal attribution statement.
The Unix regular-file type, zero ZIP flags and extraction version 20 are part
of the strict finite archive profile:

```python
from io import BytesIO
from stat import S_IFREG
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from fuzzy1337.intelligence_cwe_selection import ParseCweSelection

xml = b'''<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-8"
                  Name="Owned synthetic catalog" Version="5.0" Date="2026-11-03">
  <Weaknesses>
    <Weakness ID="1" Name="Owned synthetic weakness" Status="Draft"/>
  </Weaknesses>
  <Categories>
    <Category ID="2" Name="Owned synthetic category" Status="Stable"/>
  </Categories>
  <Groupings>
    <Grouping ID="3" Name="Owned synthetic grouping" Status="Stable"/>
  </Groupings>
</Weakness_Catalog>'''
info = ZipInfo("cwec_v5.0.xml", date_time=(2026, 11, 3, 0, 0, 0))
info.create_system = 3
info.create_version = 20
info.extract_version = 20
info.compress_type = ZIP_DEFLATED
info.flag_bits = 0
info.external_attr = (S_IFREG | 0o600) << 16
archive = BytesIO()
with ZipFile(archive, "w") as writer:
    writer.writestr(info, xml)

selection = ParseCweSelection(
    archive.getvalue(), ("CWE-1", "CWE-2", "CWE-3", "CWE-4"), catalog_version="5.0",
)
print(selection.ToDict())
print(selection.Reference())
```

The expected partitions are Weakness `CWE-1`, unsupported Category `CWE-2` and
Grouping `CWE-3`, and absent `CWE-4`. Inputs require exact bytes and an exact,
already lexically sorted immutable tuple of unique canonical IDs; the decoder
does not normalize spelling, sort the caller's request or accept mutable inputs.

## Complete validation and finite limits

No result is exposed until complete ZIP framing, actual DEFLATE EOF/size/CRC,
strict UTF-8 and full XML completion, all resource checks and the final selected
canonical-byte budget succeed. Finding all requested IDs before a corrupt tail
does not permit early success. A refusal raises `ValueError` without a partial
selection or warnings presented as acceptance.

The archive must contain one exact local/central/EOCD chain, one fixed ASCII
basename, method 8, flags zero, extraction version 20 and Unix creator host 3
with a regular file. Local and central facts must agree. No member is extracted
to a path. ZIP64, encryption, descriptors, multiple disks/members, comments,
nonregular types, stubs, gaps and trailing payload refuse. Independently bounded
extra metadata may differ, but never overrides filename, size or encoding.

| Resource                                         | Profile-only ceiling               |
| ------------------------------------------------ | ---------------------------------- |
| Original ZIP / actual expanded XML               | 4 MiB / 32 MiB                     |
| Selected canonical JSON / requested IDs          | 1 MiB / 64                         |
| Central directory / each local or central extra  | 16 KiB / 256 bytes, at most 8 TLVs |
| Compressed input / decoded output chunks         | 64 KiB each                        |
| Ordinary markup / comment or PI / live reference | 64 KiB / 64 KiB / 10 bytes         |
| Source entries / XML nodes / depth               | 10,000 / 1,000,000 / 32            |
| Parsed text / attribute bytes                    | 24 MiB / 4 MiB                     |
| Attributes per element / each attribute value    | 32 / 8192 UTF-8 bytes              |
| Raw lexical QName / namespace-expanded QName     | 256 UTF-8 bytes each               |
| Per-entry nodes / text plus attributes           | 65,536 / 1 MiB                     |

The lexical gate bounds unfinished markup and references before Expat receives
them. Raw lexical and namespace-expanded element/attribute names have separate
checks at the same 256-byte ceiling. DTD declarations, entity definitions,
external resolution and XInclude refuse; only bounded builtin escapes and
numeric character references are allowed. External schemas are never fetched.
XML 1.0 with UTF-8 or an omitted encoding declaration is required.

Counters include ignored/unselected content, XHTML, comments, processing
instructions and namespace declarations. Accounting remains cumulative across
decompression/parser chunks. Bounded buffers and retained selected fields avoid
an expanded XML tree; the 64-KiB chunk ceiling is not a total-memory or realtime
deadline guarantee.

## Identity and evidence limits

The immutable DTO retains original ZIP SHA-256/size, member facts, actual expanded
SHA-256/size/CRC, exact mode, catalog metadata, request, partitions and observed
resource counters. Detached `ToDict()` uses separate schema/profile version one
and `profile="cwe-zipped-xml-selected"`. The `cwe-selection:` reference hashes
the complete bounded canonical dictionary. XML attribute normalization does not
change the identity of the original escaped ZIP bytes. Direct DTO construction
validates structure; it does not verify hashes against unavailable source bytes.

[ADR 0131](adr/0131-bounded-selected-cwe-zip-xml.md) records actual retained
official-input research, XSD enumeration extracts and expanded XML/CRC checks.
That guarded research used separate tooling. It is not evidence that this new
decoder accepted an official source or that product acquisition/custody works.
Synthetic examples establish only their explicit owned inputs.

A separate clean installed pure-SDK exercise decoded both retained original
archives offline and verified their original hashes, actual expanded bytes and
CRC. It selected Weaknesses `CWE-79` and `CWE-89`, retained `CWE-1000` as an
unsupported View and `CWE-9999999999` as absent. Both inputs contained 984
Weaknesses and 62 Views, plus 431 Groupings in 5.0 or 431 Categories in 4.21.
These are observations of those exact inputs, not universal expected counts.
The exercise establishes those finite installed decoding cases without an
HTTPS SDK receiver, acquisition record, original-source custody or CLI workflow.

[CWE data terms](https://cwe.mitre.org/about/termsofuse.html) and applicable MITRE
copyright/license notices remain distinct from XSD and implementation licensing.
The pure decoder does not attach a publisher or legal grant to caller bytes.
A later source/custody profile must retain the applicable notices and explicit
attribution separately. Publisher authenticity, legal rights, full XSD/rich-field
support, original-source custody/replay, CLI and model integration remain outside
this slice; #43/#47 remain open.
