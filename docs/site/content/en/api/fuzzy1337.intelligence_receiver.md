# Shared isolated HTTPS process owner

This Internal helper owns one bounded standard-library receiver process for the
CISA KEV and selected EPSS acquisition profiles. Source admission belongs to
those typed profiles; structural URL validation here does not grant a new public
source or execution authority. The existing transport ceiling is 16 MiB, while
each owning profile may impose a lower ceiling. Total deadlines are finite,
between 0.05 and 60 seconds, and include child startup.

The owner uses an argument array, an empty environment and isolated Python. It
kills and drains the child on timeout or caller interruption. The result retains
bounded original or partial bytes, an explicit transport-state token and the
observed HTTP status, which may remain unknown. JSON is the default resource
preference; the fixed gzip mode changes only `Accept`. HTTP content encoding
remains identity, and source parsing, custody and publisher trust are separate.

::: fuzzy1337.intelligence_receiver
