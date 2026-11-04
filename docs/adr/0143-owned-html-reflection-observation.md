# ADR 0143: Owned HTML reflection observation

## Status

Experimental design — 2026-11-04, first slice of #412.

## Decision

Expose `scan web --check html-reflection` through the existing native worker,
policy confirmation and evidence pipeline. Select only exact literal-loopback
fixture URLs. The worker makes one bounded GET with no redirects. Its complete
HTTP 200, UTF-8 HTML response can establish a lexical observation of one exact
inert marker in ordinary element content. Escaping, comments, inert contexts
and duplicate markers do not qualify.

The result retains the original worker record, response digest, size and
observation. This profile does not create a Finding or execute JavaScript.
Browser-confirmed XSS requires a separately authorized isolated session with
its own canary event and evidence.

## Verification

Exercise the installed worker via the governed scan command against independent
raw, escaped and comment controls. Admit explicit local fault routes for
invalid status and header syntax, contradictory framing, truncated bodies and
a service unavailable response. Keep failed acquisition out of the set of
assessed controls and retain its original worker error. Reuse the existing
job, scope, evidence and model owners.
