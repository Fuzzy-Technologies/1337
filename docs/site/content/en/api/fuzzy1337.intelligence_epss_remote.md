# Pinned EPSS HTTPS custody

Experimental selected-ID EPSS acquisition derives one fixed official archive
URL from an exact lowercase 40-hex commit and calendar day. The expected model
and SHA-256 are mandatory. There is no arbitrary URL, current alias, alternate
host, query, redirect, payload injection or retry surface. FIRST attribution and
terms links are retained with `data_license="not-established"` and
`publisher_authentication="not-assessed"`.

One to 64 canonical CVEs select assertions from one complete gzip body. The
profile permits at most 4 MiB compressed, 16 MiB decoded and 500,000 original
rows; callers may lower the compressed bound. A finite total receive deadline
is between 0.05 and 60 seconds. The isolated receiver's actual HTTP status,
terminal state, bytes and acquisition times are recorded before source parsing.
The decoder validates the entire corpus, single-member EOF/CRC and original
model/score clock while retaining only selected records and unmatched IDs.

Distinct raw, selection and receipt roles bind original HTTPS custody under the
`epss-https-selection:` family. Their publication acknowledgements are independent;
unknown acknowledgement does not prove rollback. A publication failure may leave
immutable records and cannot establish complete successful custody. Oversized
generated receipts return storage failure while retaining earlier observed
acknowledgements.

Reopening requires exact original selection and receipt manifests in the owning
workspace. Role, media and finite budgets precede content reads; provenance and
receipt joins precede interpretation. The loader verifies original raw custody
and reparses the complete gzip, including after workspace relocation. It does
not access the network, accept local-family roots, modify the model, infer target
applicability or authenticate the publisher. Legacy snapshot contracts remain
separate. ADR 0128 defines this additive profile.

::: fuzzy1337.intelligence_epss_remote
