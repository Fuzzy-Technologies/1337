# ADR 0136: Bounded 1337Scope directory-index observation

## Status

Accepted design — 2026-11-03, partial implementation of #53 and #59.
Actual implementation and runtime acceptance require separate evidence.

## Decision

Add the Experimental `native.directory-index` check and explicit
`scan web --check directory-index` selection to the existing 1337Scope native
web workflow. Its capability is `web.directory-index-check`.

The pure `fuzzy1337.adapters.directory_listing` predicate recognizes one finite
classic HTML index format from at most 4096 transient response bytes. A matching
title, body heading and supported entry-link structure must agree. Complete
lexical consumption, valid UTF-8 and finite token, nesting and event counts are
required. Tutorial text, comments, unrelated links and unfinished HTML cannot
establish an index observation. Unsupported formats remain unassessed by this
predicate; a negative does not prove directory indexing is disabled.

Execution reuses the existing exact literal-IP, query-free URL profile,
current consent/scope checks, STANDARD impact policy and exact planned-intent
confirmation. It makes one bounded GET, refuses redirects and follows no entry.
The check-specific `text/html` classification leaves existing Git, file-canary
and Prometheus record categories unchanged.

A complete supported positive produces an attributable LOW exposure Finding.
The original worker report retains response status, size, hash and check outcome.
Listed filenames, link values and response bodies are not retained by the check.
This does not prove file contents, confidential information or a general file
disclosure vulnerability. Failed or truncated acquisition remains a failed
operation and cannot become a successful negative.

## Verification

Use an independently defined local filesystem-backed directory fixture and
positive, fixed, tutorial/comment, redirect, wrong-media, malformed and bounded
transport controls. Exercise the installed native worker and product interfaces,
deny before contact, preserve exact original job/report evidence and reopen the
saved Finding offline. Existing native profiles require focused regressions.

The new parser and integration require direct failure-path tests and the
repository's per-module branch-enabled coverage contract. Synthetic acceptance
does not establish Juice Shop `/ftp`, arbitrary web-server formats or complete
legacy-scanner migration. Genuine external-app acceptance is separate.
