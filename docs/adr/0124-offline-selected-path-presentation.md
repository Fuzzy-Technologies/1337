# ADR 0124: Offline selected-path presentation

- Status: Accepted
- Date: 2026-11-03
- Decision owners: Fuzzy Technologies
- Related work: #121, #119; ADR 0066 and ADR 0083

## Context

The existing `paths analyze` command verifies the exact saved model and original
selected evidence, then asks the reachability and path-analysis owners for their
actual results. Its bounded explanation has no inspectable graph view. The
canonical M4 business scenario and wider graph object families remain unfinished;
a renderer must not supply the missing reasoning or promote structural candidates
into validated attacks.

## Decision

Add Experimental `paths analyze --html` as a presentation of the same successful
analysis and exact schema-one JSON outcome. Preserve every existing model pin,
original evidence admission, final basis reread, budget, uncertainty and no-write
contract. `--html` and root `--json` are mutually exclusive. Failure produces the
existing fixed-category text outcome, never a partial successful HTML artifact.

Render only selected original transition endpoints and the explicit source and
target. Display their existing object kinds and canonical references; do not read
arbitrary attributes or infer extra nodes/edges. The profile admits at most 64
selected nodes and 128 transitions, refusing larger graphs rather than silently
partitioning or truncating them. The final UTF-8 HTML ceiling is four MiB; the
unchanged JSON explanation remains capped at one MiB.

Use deterministic standalone SVG with full state words and distinct line patterns,
directed transitions, explicit source/target and verified structural-cut markers.
Each node/edge links to a keyboard-accessible explanation retaining original
references, reasons, individual claim/proof attribution and the independent
search/cut completeness results. Never compose confidence or claim physical
access, remediation efficacy or global completeness. Static SVG and the exact
JSON outcome are downloadable from the same file without fetching a resource.

A fixed inline script enhances pan, zoom, reset and evidence inspection. Embed no
caller text in executable code. Escape text/attributes and JSON script terminators;
use fixed local anchor references and fixed data download media types. A CSP admits
only the exact script hash, inline presentation styles and no network, frame,
object, base or form action. The original static graph and explanation remain
readable when script is disabled.

## Verification and remaining work

Exercise the actual owning handler and installed console over independently
produced saved graphs and original six-phase attestations. Compare embedded and
downloaded JSON exactly to ordinary `--json`; check original states, barriers,
cuts, unknowns, separate truncation, relocation and no writes. Refuse stale pins,
corrupt proof, conflicting output modes and presentation limits without partial
HTML. Adversarial context text must not create executable markup or external links.

The existing opt-in genuine Chromium acceptance job additionally exercises the
rendered product artifact, keyboard inspection, zoom/pan/reset, downloads and CSP.
Its V8 precise block-range coverage must exceed 80% for this fixed presentation
script; missing browser prerequisites fail that required job. Ordinary runs may
skip the explicitly optional browser check and must not call that acceptance.
Python statement/branch coverage follows the existing per-module contract.

This slice advances #121 and leaves it open. Canonical scenario integration from
#119, other object/relation families, grouping and a reproducible remediation
before/after comparison remain separate work. It does not implement the full M5
graph UX, change schemas, create evidence or add execution authority.
