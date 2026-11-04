# Selected CWE HTTPS SDK

This experimental SDK profile extends the selected-CWE decoder with a distinct
HTTPS custody family. Its design is recorded in [ADR 0141](adr/0141-selected-cwe-https-custody.md).
Implementation and acceptance evidence must be checked on the corresponding PR;
this document does not establish a successful remote acquisition.

## Source and request

The profile admits only the fixed CWE `5.0` and `4.21` ZIP URLs derived under
`https://cwe.mitre.org/data/xml/`. A caller supplies the expected lowercase
SHA-256; the SDK binds the unchanged complete notice bundle. Arbitrary URLs, headers,
alternate notices, retries and local fallbacks are outside this profile.

Select 1..64 canonical CWE identifiers and an effective ZIP limit no greater
than 4 MiB. Timeout is bounded at 0.05..60 seconds; integers and floats normalize
to the same canonical float, while bool, nonfinite and huge out-of-range values
are refused before acquisition. Transport performs one isolated ZIP request with
identity HTTP encoding. Its observed status and explicit transport state remain
separate from decoding and evidence publication.

## Original evidence and replay

Retain original complete or actual partial response bytes. A complete response
with the wrong digest or malformed ZIP/XML is a failed acquisition with complete
raw evidence, not a normalized catalog. A successful selection preserves its
full source/notice declaration, requested/matched/unmatched partition, original
raw manifest, effective limits, canonical timeout, profile and decode facts.

Raw ZIP, selected envelope and receipt are separately published. Each publication
is `not-attempted`, `unknown` or `confirmed`; a failed call may already have
committed an object. Serialization precedes the publication attempt. A storage
failure preserves known earlier handles and orphan uncertainty, and cannot
return a usable successful selection.

Offline reopen validates exact original source, envelope and receipt joins and
reparses the retained raw ZIP. Relocation is supported; mixed acquisitions,
changed limits, altered notices and missing or corrupted originals fail closed.
Replay does not perform a GET, publish evidence or mutate a model.

## Resource and interpretation boundaries

The existing selected decoder retains its 32 MiB XML, 1 MiB normalized selection
and 64-ID bounds. Notice, source, envelope and receipt documents are bounded at
16 KiB, 32 KiB, 2 MiB and 64 KiB respectively. The shared receiver ceiling stays
16 MiB. Bounded JSON validates total bytes, UTF-8, duplicate keys, numeric tokens
and depth; separate node-count or per-string ceilings are not implied.

The transport profile records the selected ZIP media admission contract. The
existing transport result does not expose the literal observed HTTP Content-Type
value, so custody must not invent it. Raw artifact media describes the retained
artifact, not additional HTTP telemetry.

Unmatched identifiers remain unmatched; they are not zero-risk records. Catalog
selection, weakness membership and attributed source facts do not establish
target applicability or exploitation probability. Pins and preserved notices do
not prove publisher authentication, legal entitlement, full XSD conformance or
coverage of the complete normalized catalog.

SDK tests against synthetic responses or retained catalog bytes do not establish
a fresh HTTPS acquisition. Clean installed-wheel verification over retained bytes
is recorded in [source acceptance](INTELLIGENCE_SOURCE_ACCEPTANCE.md); it does not
establish remote availability. Actual HTTPS acceptance remains separate.
#43/#47 remain open until their broader source-profile and product acceptance
criteria are met.

## CLI acquisition and offline inspection

Use an existing workspace and provide an explicit pin for the selected catalog.
The example uses the retained CWE 5.0 source pin. Current availability of the
fixed source URL requires separate HTTPS acceptance.

```console
1337 intel cwe https fetch workspace --catalog-version 5.0 --expected-sha256 bcda44c9abf61ff977f50c3c6649eea5a97a7b0626b0396c2c3ec4bfb973a3dc --identifier CWE-79 --identifier CWE-1000 --scope review-cwe --json
```

Use the returned selection and receipt manifest IDs in the same workspace or
its relocated copy. Replace the two values below with those exact IDs.

```console
1337 intel cwe https inspect workspace --selection sha256:SELECTION_DIGEST --receipt sha256:RECEIPT_DIGEST --json
```

Fetch reports separate raw, selection and receipt publication acknowledgements.
Inspect reports verified-present custody after checking the original artifacts.
Both commands expose explicit matched, unsupported and unmatched partitions.
The CLI stages bounded ASCII-safe output while preserving the complete notice
and the original source bytes in evidence. Acquisition, integrity and rendering
failures suppress usable selection output and retain known custody facts.
