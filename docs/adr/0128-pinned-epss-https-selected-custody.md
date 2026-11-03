# ADR 0128: Pinned EPSS HTTPS selected custody

## Status

Accepted for the additive Experimental profile-one boundary.

## Context

The pure bounded EPSS decoder and separate local selected-custody profile retain
explicit original gzip bytes. Importing downloaded bytes through that local
profile does not establish HTTPS custody. A network profile must record the
actual receiver's facts and reopen its own original artifacts after relocation.
FIRST's [data page](https://www.first.org/epss/data) links the historical archive;
its [FAQ](https://www.first.org/epss/faq) supplies attribution and explains the
source statements. The [service terms](https://www.first.org/about/policies/terms)
are preserved separately. These links establish neither an SPDX data license nor
publisher-signature authentication.

## Decision

Add `fuzzy1337.intelligence_epss_remote` as a distinct Experimental acquisition
family. `EpssHttpsSource` requires an exact lowercase 40-hex Git commit, exact
calendar day, explicit expected model and mandatory lowercase SHA-256. It derives
only `https://raw.githubusercontent.com/empiricalsec/epss_scores/<commit>/<year>/epss_scores-<day>.csv.gz`.
There is no caller URL, branch/tag/current alias, alternate host, query, fragment,
credential, port, traversal, payload callback or discovery surface.

`EpssHttpsRequest` requires an immutable canonical selection of one to 64 CVEs,
at most four MiB compressed bytes and a finite total receive timeout from 0.05
to 60 seconds. `AcquireHttpsEpssSelection` delegates one request to the shared
stdlib-only isolated receiver using `accept_kind="gzip"`. That owner provides
certificate verification, empty environment, total deadline, child termination,
bounded framing and redirect refusal. The resource body is gzip; HTTP content
encoding remains identity. There are no retries or API fallback. CISA request
admission and its existing wire contract remain separate.

Record actual start/finish around the isolated receive. The distinct version-one
`epss-https-selected-acquisition` envelope, `epss-https-selection:` reference,
`epss-https-selection-acquisition` importer and receipt, `epss-https-gzip-source`,
`epss-https-gzip-partial` and `epss-https-selected-snapshot` evidence roles bind
source identity, pin, limits, HTTP status, receiver terminal state, completeness,
original manifests and selected decoder output. Fixed attribution links state
`data_license="not-established"` and `publisher_authentication="not-assessed"`.
The unchanged decoder enforces sixteen MiB expanded bytes, 500,000 rows, complete
single-member gzip CRC/EOF and full original row validation. A source score clock
cannot follow the actual receive finish.

Raw, selected and receipt publications have independent `not-attempted`,
`confirmed` or `unknown` acknowledgements. A failed or lost acknowledgement may
leave immutable artifacts; it clears any usable returned success envelope and
never claims rollback. A generated receipt that exceeds its profile ceiling
returns storage failure with the actual earlier publication acknowledgements and
receipt publication not attempted. Complete wrong-hash/parse failures preserve original gzip
and a failure receipt when storage permits. Refusals and partial receives retain
bounded bytes as partial evidence, with honest incomplete network facts.

`LoadHttpsEpssSelection` selects exact envelope and receipt roots. Expected role,
media and byte ceilings precede the owning Get's implicit blob allocation.
Owning workspace/acquisition provenance joins precede nested interpretation.
Strict bounded JSON and canonical exact reconstruction bind receipt network
facts, source pin, request limits and manifests. Reopening requires original raw
manifest custody and a full gzip reparse equal to the stored selection. It makes
no network request, including after relocation. Local roots cannot be relabeled
or accepted by this HTTPS loader. Original local profile bytes, roles and loader
contracts remain unchanged.

## Consequences

This adds explicit pinned historical acquisition and offline inspection, without
latest discovery, generic URLs, publisher authentication, source signature
verification, applicability matching, scoring changes, model writes or automatic
Finding mutation. Caller pin trust and downstream legal rights remain outside
this boundary. SDK tests use owned fixtures; genuine public acquisition acceptance
must use the actual SDK receiver and exact selected public resource separately.
