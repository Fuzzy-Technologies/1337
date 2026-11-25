# Explicit selected CVE HTTPS commands

Internal `intel cve https fetch|inspect|inspect-set` consumer of the separate Experimental
pinned source family. Fetch requires an existing workspace, exact commit, one
canonical CVE, mandatory SHA-256 and explicit scope attribution. Typed source,
scope and finite limit checks precede acquisition. Repeated scalar flags,
abbreviations, arbitrary URLs and supplied payloads are unsupported.

Successful fetch requires complete observed HTTP 200 and confirmed raw, snapshot
and receipt publications with original handles. Terminal `selection_id` and
`selection_ack` represent the SDK's snapshot artifact and acknowledgement.
Versioned JSON distinguishes configuration, acquisition and integrity failures
and retains independent publication uncertainty. A failed fetch presents no
successful source assertions or rollback claim.

Inspect requires exact original selection and receipt manifests. It verifies
the saved source, full notices, original byte pin, acquisition facts and complete
snapshot by offline reparse, including after relocation. Inspection never starts
a receiver. The finite profile accepts PUBLISHED CVE JSON 5.2 only; unsupported
states do not become successful vulnerabilities or zero risk.

`inspect-set` accepts two to four explicit `--member SELECTION RECEIPT` pairs.
All identities pass finite preflight before storage reads; original loaders then
verify every member before returning an ordered terminal projection. Members
require distinct CVEs at one commit and retain independent source notices and
provenance. No persisted set identity or common historical batch is inferred.
The separate version-one saved-set terminal profile stages at most 8 MiB of
ASCII output and refuses the whole projection on a broken member, with no
partial assertions, receiver, storage write or new assessment.

Human and JSON output keep source assertions, target applicability, risk and
publisher authentication distinct. No model Apply/Save or automatic matching is
introduced. Data terms and retained required notices do not infer the schema's
CC0 license as a data license or establish legal rights. Existing local and
other remote profile commands retain their separate contracts.

JSON output keeps its original UTF-8 bytes when representable by the caller's
declared stream encoding. Narrow codecs use lossless standard JSON Unicode
escapes before publication; decoded notices and source assertions remain exact.
The fallback changes no saved content or custody identity.

::: fuzzy1337.intelligence_cve_https_commands
