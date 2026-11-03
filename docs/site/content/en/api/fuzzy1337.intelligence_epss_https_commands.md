# Explicit EPSS HTTPS commands

Internal `intel epss https fetch|inspect` consumer of the separate Experimental
pinned acquisition family. Fetch requires an existing workspace, exact commit,
day, expected model, raw SHA-256, explicit requested CVEs and scope attribution.
Malformed or repeated scalar options and invalid finite limits are rejected
before acquisition. Scope attribution is retained without granting execution
authority. There is no caller URL or source/terms override.

Successful fetch requires complete observed HTTP 200 and confirmed raw,
selection and receipt publications with their original handles. JSON retains
transport state, completeness, independent acknowledgements and distinct
configuration, integrity and acquisition failures. Failed acquisition does not
present source assertions as a successful selection.

Inspect requires the exact original selection and receipt manifests. It verifies
saved HTTPS custody and reparses original gzip without starting a receiver,
including after relocation. Source probability, percentile, clock and unmatched
IDs remain source facts; target applicability is not evaluated. Neither command
saves model state or authenticates the publisher. The local `intel epss
import|inspect` and legacy snapshot families remain separate.

::: fuzzy1337.intelligence_epss_https_commands
