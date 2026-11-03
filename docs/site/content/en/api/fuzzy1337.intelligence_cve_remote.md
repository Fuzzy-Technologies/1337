# Pinned selected CVE HTTPS custody

Experimental acquisition selects one canonical CVE, exact lowercase 40-hex
commit and mandatory raw SHA-256. `CveHttpsSource` derives one immutable official
archive locator. There is no caller URL, moving ref, supplied payload, redirect,
retry, batch or discovery surface. The unchanged shared JSON receiver supplies
actual HTTP status, bounded original/partial bytes and observed acquisition times.

Success requires complete HTTP 200, the exact pin, strict original JSON and one
requested `CVE_RECORD` with wire version `5.2` and state `PUBLISHED`. REJECTED,
RESERVED and other states refuse this profile; existing broader local readers
remain unchanged. Source assertion time cannot follow receiver completion.
Source assertions do not establish target applicability, correctness or risk.

The separate `cve-https-selection:` envelope binds the entire original raw
manifest, fixed data notices, complete nested snapshot and actual request limits.
Profile ceilings are one MiB of source, two MiB of normalized envelope and 32 KiB
of receipt; the finite total receive deadline is 0.05 through 60 seconds. Shared
limits remain unchanged. Raw, snapshot and receipt publication acknowledgements
are independent. A failure or unknown acknowledgement may leave immutable
artifacts and never establishes rollback or complete successful custody.

`LoadHttpsCveSelection` selects exact original envelope/receipt roots offline.
Role, media and byte limits precede content allocation; owning workspace and
acquisition provenance joins precede interpretation. Strict reconstruction binds
receipt facts to envelope-bound limits and source identity. Original raw custody
and complete reparse must reproduce the snapshot after workspace relocation.
Foreign profile roots or mixed acquisitions refuse. Neither acquisition nor
reopening applies Findings or saves the model.

Source identity retains the CVE Program data terms, complete required LICENSE
and DISCLAIMERS notices, observed copyright designation and fixed notice
provenance. These are distinct from the schema's CC0 license. Publisher
authentication and legal rights remain `not-assessed`; retaining notices does
not decide entitlement. ADR 0130 defines this additive Experimental profile.

::: fuzzy1337.intelligence_cve_remote
