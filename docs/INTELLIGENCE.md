# Verified offline vulnerability intelligence

`fuzzy1337.intelligence` is an Experimental schema-v1 library implementing
[ADR 0041](adr/0041-offline-vulnerability-enrichment.md). It enriches an existing
canonical finding with explicit source assertions; catalog presence never creates
a vulnerability or changes severity, confidence, remediation, or operator triage.
`IntelligenceFeed`, `IntelligenceRecord`, `IntelligenceSnapshot`,
`ParseIntelligenceSnapshot`, and `ApplyVerifiedEnrichment` are the documented
Experimental contract. Module-level parser/validation helpers remain Internal.

## Sources and identity

The caller supplies authorized uncompressed UTF-8 bytes, a typed feed, an exact
catalog/model revision, an existing raw `EvidenceReference`, and the reusable
`ReferenceSource` attribution. Publisher, source URL, exact source-byte SHA-256,
license name/URL, acquisition time, and importer/version remain explicit. The
pure parser checks the bytes against both source and evidence digests/lengths.
It performs no downloads, decompression, storage writes, live updates, or scans.
All checked-in intelligence fixtures are synthetic; no official corpus or claimed
official redistribution license is bundled.

| Feed       | Supported input                            | Exact revision supplied by caller                |
| ---------- | ------------------------------------------ | ------------------------------------------------ |
| CVE        | CVE Record JSON `5.0` / `5.1` / `5.2`      | Source-list revision or commit                   |
| CWE        | Namespace `http://cwe.mitre.org/cwe-7` XML | Exact XML `Weakness_Catalog` version             |
| CISA KEV   | KEV JSON catalog                           | Exact JSON `catalogVersion`                      |
| FIRST EPSS | Uncompressed daily CSV with model/date     | Exact `model_version`, distinct from API version |

Recognized CVE format revisions are `5.0`, `5.0.0`, `5.1`, `5.1.0`, `5.1.1`, `5.2`,
and `5.2.0`. CNA and ADP assessments remain separate. Source records must contain
an explicit full metadata update timestamp. CVE defines an omitted timezone as
GMT; only this publisher-defined default is applied, and no missing date is
invented. Other source and interpretation timestamps require full calendar/clock
syntax with `Z` or an explicit `HH:MM` offset. EPSS CSV additionally accepts its
publisher's historical explicit `HHMM` offsets, such as `+0000`; reduced clocks,
missing zones, and offset seconds remain invalid.

Records preserve exact uppercase CVE/CWE identifiers and effective source times.
`intel-record:<sha256>` identifies exact normalized version-bound assertions;
`intel-snapshot:<sha256>` additionally binds every source/license/import fact and
raw evidence reference. Neither hash changes canonical finding/Security Object
identity or authenticates a publisher. Canonical CVE/CWE URLs are generated from
exact IDs; those locators do not establish item existence.

`Serialize`/`Deserialize` use strict deterministic snapshot JSON. Source bytes are
limited to 16 MiB, records to 500,000, JSON/XML depth to 32, and number tokens to
32 characters. JSON rejects duplicate keys, unsupported/coerced schema versions,
nonfinite numbers and inconsistent references. XML rejects DTD/entity declarations,
unknown root namespaces and misplaced weakness records. CSV requires exact
columns and explicit model/date metadata. Unknown consumed formats fail; unconsumed
upstream fields remain in the verified raw artifact.
Normalized EPSS records require the same model version in their assertion data
and catalog identity. KEV entries cannot be added after their catalog release.
These joins apply to direct construction and portable decoding as well as parsers.

## Meaning of the source assertions

- CVE records retain `PUBLISHED` or `REJECTED`. Rejected records carry no positive
  vulnerability/weakness/severity assessment in normalized output.
- Supported CVSS `3.0`, `3.1` and `4.0` vectors and base scores retain their source
  assessor. Vector grammar is validated, including the fixed CVSS 4.0 metric order.
  Source scores are not recalculated, merged, converted between versions, or applied
  to finding severity. CVSS 2 and other metric formats remain visibly unsupported
  and recoverable from the raw artifact.
- CWE describes a catalog weakness, not the finding's verified applicability.
- KEV membership describes a source exploitation assertion for a CVE, not an
  observed attack against the finding. `Unknown` ransomware use remains unknown.
  Missing catalog membership never proves non-exploitation or absence of risk.
- EPSS probability and percentile remain separate values with a source model
  revision and score date. The probability concerns exploitation within the model's
  next 30 days; it is not the probability that the specific target is vulnerable.

Descriptions may be reduced to single-line printable prose for normalized metadata.
The unchanged raw source retains original paragraphs and unconsumed fields.
Byte-integrity verification does not authenticate source identity, confirm catalog
accuracy or redistribution rights, validate applicability, or grant execution authority.

## Verified finding integration

```python
from fuzzy1337.intelligence import ApplyVerifiedEnrichment

# state owns an existing finding; snapshots pin explicitly acquired source artifacts.
proposal, delta = ApplyVerifiedEnrichment(
    state, finding_reference, ("CVE-1900-9999",), snapshots, provenance,
    workspace_root, as_of="2026-10-12T13:00:00Z", max_age_seconds=86400,
)
model_store.Save(proposal, expected_revision=delta.previous_revision)
```

The example ID is synthetic. The finding owner supplies exact associations
explicitly; no identifier is inferred from a description, product, check ID,
CPE, version, fuzzy match, or another catalog relationship. All associations are
recorded as `candidate` with `review=None`. An importer never manufactures approval.

The verified boundary checks workspace ownership, all linked finding/caller
evidence, and every raw source. It reparses each source and rejects a forged
snapshot even if its public content hash was recomputed. Verification completes
before returning an in-memory proposal; the function writes nothing.

Only a `finding-intelligence` observation is added to the existing model.
Its source assertions retain record/snapshot references, canonical identifier
URL, source attribution, license/version/time, raw evidence reference, and honest
staleness. Unmatched requested IDs remain explicitly unmatched. Freshness uses
EPSS score time for score feeds and acquisition time for other feeds. The explicit
as-of time must match observation provenance and cannot precede source acquisition.
The freshness budget is a caller choice. At most 64 assertions may be selected,
and the existing model attribute limit still applies.

Operator dispositions and finding identity remain unchanged. Exact replay after
later triage adds no revision. Independent source revisions remain separate
attributed observations. The existing model CAS and workspace-relocation contracts
own persistence; there is no provider-specific or second authoritative findings store.

## Source specifications and delivery limits

- [CVE Record format](https://github.com/CVEProject/cve-schema).
- [CWE XML schemas](https://cwe.mitre.org/data/schema.html).
- [CISA KEV schema and source mirror](https://github.com/cisagov/kev-data).
- [FIRST EPSS data](https://www.first.org/epss/data) and its linked
  [official historical archive](https://github.com/empiricalsec/epss_scores).
- [FIRST CVSS 3.1 specification](https://www.first.org/cvss/v3.1/specification-document).
- [FIRST CVSS 4.0 specification](https://www.first.org/cvss/v4.0/specification-document).

This delivery covers explicitly supplied offline artifacts and verified observation
integration. Current-schema expansion, live acquisition/synchronization, publisher
signature authentication, license decisions, applicability/version/CPE matching,
risk calculations and CVSS 2 conversion are separate capabilities. No current
official-corpus completeness or production feed acquisition is claimed.

The separately versioned Experimental
[snapshot acquisition boundary](INTELLIGENCE_ACQUISITION.md) now imports explicitly
supplied bytes or one pinned official CISA KEV mirror revision into the owning
immutable evidence store. It
retains independent terminal receipts and observed receiver times, supports
verified portable replay, and never changes this pure parser or finding consumer.
Automatic live refresh, broader source providers, and live official-feed
acceptance remain separate scope.
