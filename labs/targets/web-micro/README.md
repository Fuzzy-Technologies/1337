# Web micro-target

`web-micro` is the first-party known-answer HTTP target for 1337 functional
tests. It is intentionally small, has no host-published port, and runs only on
the repository-owned internal Compose network.

The target provides deterministic routes for discovery, redirects, headers,
cookies, HTML forms, query and JSON inputs, upload handling, and selected HTTP
status responses. Its command-execution, file-inclusion, SSRF, and upload
routes are labelled simulation canaries only: they never execute commands,
read files, make outbound requests, or persist uploaded data.

The scenario contract in `tests/functional/scenarios.py` is the source of
truth for expected observations and simulation markers. Future scanners use
those explicit known answers to calculate TP, FP, FN, and TN; this target alone
does not claim scanner accuracy.
