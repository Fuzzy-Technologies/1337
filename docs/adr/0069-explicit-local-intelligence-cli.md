# ADR 0069: Explicit local intelligence CLI

Status: Accepted

## Context

The acquisition and enrichment APIs already support bounded CVE, CWE, KEV and
EPSS source bytes, immutable evidence, original-source replay and attributed
finding observations. Operators need a product command that exercises these
owners without adding another snapshot database or treating import as approval.

## Decision

Add the experimental `1337 intel` namespace and matching foreground shell
command. `import` reads one explicitly selected local regular file, with physical
parent checks and a finite byte ceiling. Feed, catalog version, synthetic or
external origin, publisher, source locator, license attribution and collection
scope are explicit. An optional SHA-256 pin checks exact bytes. URLs are metadata;
this command never retrieves them. Acquisition time comes from the existing
receiver clock and has no caller-supplied override.

`inspect` requires an exact snapshot manifest and successful local terminal
receipt. The consumer checks bounded record reads, common owning workspace and
original acquisition provenance, receipt/source/snapshot consistency, and the
existing loader's original raw-manifest and reparse checks. Inspection never
creates or changes model/evidence state. Receipt integrity establishes consistency
with the selected retained artifacts; it does not authenticate a publisher or
prove the declared license is authoritative.

`apply` makes enrichment a separate explicit action. It selects one existing
finding, exact CVE/CWE identifiers, one verified snapshot/receipt pair, the
expected saved model revision, an offset-aware interpretation time, a freshness
budget and interpretation scope/run attribution. The existing verified consumer
appends candidate source assertions; finding identity, severity, confidence and
operator disposition remain unchanged. The receipt is retained as interpretation
evidence. The existing model owner commits with compare-and-save; exact replay is
a no-op. A busy or competing writer remains authoritative.

Terminal output is a bounded summary with an experimental schema-v1 JSON mode.
It omits source bodies, local filenames and arbitrary exception diagnostics.
Acquisition failures retain their actual states and original bounded evidence;
some publication failures can leave immutable artifacts. Failed model-save
acknowledgements report `model_commit: unknown` and require reopening state,
without inventing rollback or successful publication. Shell history retains only
`intel`, and an empty line cannot repeat its state-changing arguments.

## Boundaries

This slice has no remote acquisition command, bulk import, latest-source
discovery, implicit finding matching, automatic enrichment, applicability
approval, risk/triage rewrite, or license/publisher authentication. Existing
remote acquisition SDK contracts remain separate. The CLI accepts explicit local
source selection, not an ambient directory scan. Portable checks reject observed
symlinks, reparse points and input hard links; they do not claim protection against
hostile concurrent filesystem replacement beyond the existing owners' contract.

## Verification

Pytest runs actual CLI subprocesses over all four owned synthetic formats,
verifies retained raw/snapshot/receipt bytes and receiver timestamps, reopens a
moved workspace, applies intelligence to a persisted triaged finding and checks
exact replay. Negative scenarios exercise digest, parse and size failures,
missing/corrupt raw records, foreign or rehashed receipts, foreign workspace,
invalid association/time, stale revision, real writer locks, actual competing CAS
saves and lost acknowledgements. The shared PR gate remains the full validation
checkpoint.
