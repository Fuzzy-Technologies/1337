# Pinned selected CVE HTTPS batch

`AcquireHttpsCveBatch` is an Experimental SDK operation over an existing owning
workspace and a tuple of two to four explicit `CveHttpsRequest` selections. It
requires unique CVE identifiers at one immutable commit and preserves caller
order. The sum of declared original-byte limits is at most 4 MiB, and the
sum of configured receive timeouts is at most 60 seconds. Each member uses the
existing single-record admission and independent evidence acknowledgements.

`CveHttpsBatchOutcome` reports succeeded, partial or failed from actual member
outcomes. Each member keeps its request and custody or structural stop facts.
If workspace ownership fails after receive, the result retains observed
transport facts and records publication as not attempted. Later members remain
not attempted. The result has no aggregate persistent receipt, and any accepted
selection and receipt reopen independently through `LoadHttpsCveSelection`.

The profile covers explicitly pinned wire-5.2 PUBLISHED records. It has no feed
discovery, archive or official delta processing, model save or Finding apply.
Timing budgets cover configured receives. Local storage and worker cleanup
can extend elapsed time.

::: fuzzy1337.intelligence_cve_batch
