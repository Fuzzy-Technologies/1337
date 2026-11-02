# ADR 0123: Selected verified intelligence inspection

- Status: Accepted for the owner-authorized M3 implementation
- Date: 2026-11-02
- Decision owners: Fuzzy Technologies
- Related work: #43, #47; ADR 0041, ADR 0060, ADR 0069, ADR 0100,
  ADR 0104, ADR 0107

## Context

The local product commands already retain and verify original source evidence,
snapshots and receipts. Default inspection returns feed/version/count/digest
metadata but cannot explain selected source assertions. Additional source-bound
CVE product declarations, CVSS 2 inspection and exact base arithmetic are existing
independent Python APIs. Replacing normalized snapshots would change their
content identities and the exact reparse used by retained finding observations.

## Decision

Add repeated optional `--identifier` selection to `intel inspect`. Require one
through 64 unique exact CVE/CWE identifiers when selection is requested. Validate
selection before original-source verification. Keep default inspect output and
all existing import/apply behavior unchanged.

After complete original receipt/source/snapshot verification, add Experimental
terminal `details` profile `1`. Return source attribution once, original snapshot
reference, explicit requested/unmatched identifiers and only selected normalized
records. Limit the entire detail document to 1 MiB; refuse excessive results
without partial printing or implicit truncation. It is an ephemeral terminal
projection, not a persisted replacement snapshot, decoder or second source of
truth. Inspection changes no evidence, finding, model revision or triage.

For selected CVE formats `5.2`/`5.2.0`, call the original independent readers on
the same verified source bytes. Return ordered product/provider declarations and
separate CVSS 2 source assessments and derived base calculations. Link each
calculation by its existing assessment index and preserve its algorithm/version.
Do not repeat snapshots within profiles. CVSS 3/4 assertions remain in the
original record with independent assessor/version/vector/base score.

Older supported CVE formats report extra profiles as `unsupported-format` while
retaining their original base assertions. Each strict additional profile reports
`unsupported-content` when it cannot interpret the consumed declarations; it
returns no guessed assertions. Other independent profiles remain inspectable.
This distinction does not claim full source schema validation. Rejected records
have no positive product or scoring assertions; unmatched selection discloses no
unrelated profile. Human text escapes nonprintable terminal metadata.

Every detail result states `target_applicability="not-evaluated"` and
`publisher_authentication="not-assessed"`. A source's `affected`, `unaffected` or
`unknown` product status is not a target verdict. KEV membership is source-reported
exploitation, EPSS is a separate source probability/percentile with its score
date, and CVSS describes technical severity. Calculated CVSS 2 never overwrites
an asserted score. No automatic identifier association or combined risk follows.

## Finite source matrix

| Source     | Accepted document                                                              | Acquisition                                                                                   | Boundary                                                                         |
| ---------- | ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| CVE        | One uncompressed UTF-8 CVE Record 5.0/5.1/5.2 in the existing supported labels | Explicit local CLI/SDK bytes                                                                  | Source-list revision pinned; extra declaration/CVSS 2 profiles require 5.2/5.2.0 |
| CWE        | Uncompressed UTF-8 namespace `http://cwe.mitre.org/cwe-7` XML                  | Explicit local CLI/SDK bytes                                                                  | Exact catalog version; retained weakness name/status only                        |
| CISA KEV   | Uncompressed JSON with exact `catalogVersion`                                  | Explicit local CLI bytes, or existing SDK HTTPS receiver for one exact official mirror commit | Same-revision source/license attribution; no moving latest selection             |
| FIRST EPSS | Uncompressed UTF-8 daily CSV with explicit model/date metadata                 | Explicit local CLI/SDK bytes                                                                  | Exact model version; probability and percentile remain separate                  |

Each original source remains bounded to 16 MiB and the existing record, depth,
scalar and receipt limits. Full compressed CVE/CWE/EPSS corpora, automatic
refresh, latest discovery, generic provider URLs, decompression and incremental
catalog maintenance are unsupported. The FIRST daily CSV endpoint redirects and
serves gzip; the CISA receiver's identity-only, redirect-refusing contract does
not provide EPSS acquisition. CWE's ZIP delivery likewise needs a separately
specified bounded archive contract. No broad corpus completeness is claimed.

## Publisher prose and selected source acceptance

One real pinned KEV catalog exposed surrounding prose whitespace and U+202F
spacing separators that the strict normalized metadata validator rejects. At
the publisher-input boundary only, normalize Unicode category `Zs` to ASCII
spaces and remove surrounding whitespace in vendor/product/name/action prose.
Retain the original prose byte limit before normalization and preserve printable
internal spacing. Do not alter normalized record validation, identifiers,
dates, source attribution, scores, raw source bytes or evidence hashes. Internal
controls and directional formatting remain invalid. Existing accepted snapshots
continue to reparse identically; previously refused prose can now be imported.

[Selected official-source acceptance](../INTELLIGENCE_SOURCE_ACCEPTANCE.md)
records catalog `2026.10.30` at exact commit
`7ccba8e1223ccec82d12c7736bf3fae11e5bee86`: actual local product import succeeded
for all 1,766 records, inspection selected one record, and original bytes were retained.
The separately attempted isolated HTTPS receiver returned `transport-failed`
with zero bytes; live receiver acceptance remains pending. Do not merge these
two different evidence claims or relax the receiver's trust policy.

## Compatibility and evidence

The schema-v1 normalized snapshots, source hashes, immutable receipts, verified
finding observations, CAS behavior and default terminal fields stay unchanged.
The optional projection is Experimental and read-only. Source hashes establish
byte custody; they neither authenticate publishers nor prove applicability.

Focused deterministic unit and actual CLI/E2E checks cover all four source
families, selected/unmatched IDs, default output preservation, source statuses,
independent scores, rejected and unsupported content, count/byte ceilings,
read-only storage, relocation and safe text. Fixtures remain explicitly synthetic
and tests do not contact a live publisher. A separately recorded selected
official-source smoke is acceptance evidence only for its exact bytes/revision,
not a replacement for deterministic fixtures or a publisher-signature claim.

Source delivery references:
[FIRST EPSS data](https://www.first.org/epss/data),
[CWE downloads](https://cwe.mitre.org/data/downloads.html), and
[official CISA KEV mirror](https://github.com/cisagov/kev-data).
