# Explicit local IOC artifact commands

`1337 trace ioc` is an Experimental version-one product interface over the
accepted offline ASCII TSV artifact profile. It records supplied candidates and
original evidence. It does not establish maliciousness, create Findings, mutate
Core or authorize a scan. Use only explicitly owned non-secret files.

## Import one selected file

Create the owning workspace through the existing `workspace create` command.
Supply an absolute physical source path and independently known lowercase byte
SHA-256. Every source/version/license field is declared, not authenticated.
Logical source/license locators are opaque data; they are never opened or fetched.

```bash
1337 trace ioc import /owned/case-workspace \
  --file /owned/case.tsv \
  --source-id owned.case --source-version export-1 \
  --source-locator owned:case.tsv \
  --license-name owned-permission --license-locator owned:permission-record \
  --expected-sha256 <64-lowercase-hex-byte-digest> \
  --scope scope:owned-collection --owner owner:collector \
  --read-consent-reference read:owned-non-secret \
  --max-bytes 65536 --max-lines 256 --max-items 256 \
  --max-line-bytes 512 --max-token-bytes 512 --json
```

Replace the digest placeholder with the exact source byte pin; it is not a
manifest identifier or proof of publisher authenticity. The five shown limits
are the accepted defaults and hard ceilings. Callers may reduce each limit but
cannot expand it. Oversize files fail before acquisition, without truncation.

The file must be physical, regular, singly linked, within the byte limit and
stable across observed path/handle reads. Relative paths, traversal, links,
reparse points and observed replacement/mutation are refused. The explicit owner
and read references declare selected-file permission; they are not signatures
or assessment grants. They do not add new fields to the unchanged acquisition
receipt. Collection `--scope` is opaque attribution, not a current target grant.

Each nonempty ASCII TSV line contains `kind<TAB>token`, optionally followed by
`<TAB>original-offset-bearing-timestamp<TAB>exact-timezone-suffix`. Supported
literal kinds are `ipv4`, unscoped `ipv6`, `dns` and `sha256`. There is no header,
blank line, comment, quoting, URL inference, IDNA conversion or DNS resolution.
Duplicates retain their separate original occurrences. Source-declared future
timestamps remain source facts and do not replace the receiver acquisition clock.

Successful import retains three immutable owning records: original raw bytes,
terminal acquisition receipt and derived snapshot. Keep the returned independent
`receipt_id` and `snapshot_id` from that original acquisition. Terminal JSON
contains only counts, observed source hash/length, acquisition times and evidence
identifiers. It excludes original tokens, physical paths and declared read/source
references. Supplied candidate data remains in the explicit evidence owner and
the existing `LoadIocArtifact` API.

## Inspect original evidence

```bash
1337 trace ioc inspect /owned/case-workspace \
  --snapshot sha256:<original-snapshot-manifest-digest> \
  --receipt sha256:<independently-retained-original-receipt-manifest-digest> --json
```

Both identifiers are mandatory original manifest identities, not raw byte hashes.
Never obtain the trusted receipt pin from a snapshot being inspected. Inspection
checks the owning manifests, role/media/size limits, complete original bindings
and independent original-byte reparse. Altered candidate metadata is refused
even when alternative public hashes are recomputed.

Inspection works after moving the owning workspace and deleting the source file.
It performs no save/acquisition, source rediscovery, network or process action.
It accepts no source/license/consent overrides. The same explicit commands work
in the foreground shell; the protected `trace` namespace is not retained for
history/replay, including malformed input.

## Outcomes

| Exit | Meaning                                                           |
| ---- | ----------------------------------------------------------------- |
| 0    | Acquisition or independently anchored replay verified             |
| 2    | Invalid explicit grammar, declarations, limits or selected file   |
| 4    | Refused acquisition, integrity/storage failure or unknown outcome |
| 130  | Interrupted operation                                             |

Digest/parse refusal retains original raw and terminal receipt identifiers,
reports `evidence_commit: confirmed`, and returns no usable snapshot. A storage
error/interruption after acquisition begins reports `unknown`: records may have
been published without acknowledgement. There is no rollback claim or atomic
three-record transaction. Inspect uses `not-attempted` because it does not write.
The command never changes workspace/Core state. Generic diagnostics do not copy
rejected argument values, physical names or source bodies.

This slice does not complete wider DFIR ingestion. Logs, process/entity evidence,
custody/collector contracts, Core investigation/timeline semantics and observed
attack paths remain separate work. See [ADR 0076](adr/0076-bounded-ioc-artifact-evidence.md)
and [ADR 0080](adr/0080-explicit-local-ioc-cli.md).
