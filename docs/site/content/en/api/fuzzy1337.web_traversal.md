# Bounded owned-page traversal

Experimental `OwnedTraversalPage`, `WebTraversalLimits` and
`LocalWebTraversalProvider` compose the existing governed page provider over a
finite reviewed loopback catalog. Independent acquisitions run in bounded sorted
breadth waves; model commits remain deterministic and require current consent,
scope and policy. Original evidence and partial committed state survive failure.

Discovered links never authorize a request. Redirects remain refused, cancellation
drains owned workers and waiters, and reported progress reflects acknowledged
pages. This module introduces no general crawler, browser or CLI registration.
ADR 0062 and `docs/WEB_TRAVERSAL.md` define the exact Experimental contract.

::: fuzzy1337.web_traversal
