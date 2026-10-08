# ADR 0018: Oracle-derived functional metrics

## Status

Accepted — 2026-10-04

## Context

Task #96 requires explainable accuracy and regression evidence. A count of
findings cannot distinguish missed positives, false alarms, or an interrupted
assessment. True negatives require a finite set of explicitly declared negative
checks. Realistic applications without a complete oracle cannot supply that set.

## Decision

Introduce a Development-stability functional report contract, schema version 1,
in `fuzzy1337.functional_metrics`. Scenario metadata owns target provenance,
version, check identifiers, capabilities, applicability, expected outcomes, and
required evidence roles. Run records add scanner and release identifiers without
changing the oracle, and preserve raw textual evidence and discovered objects.

Completed runs against a complete, closed-world oracle are scored by unique
check identifiers. Confusion counts use only the fixed declared check population.
Unknown detections remain a separate anomaly count and list. Only declared,
applicable negative checks contribute true negatives. Duplicate detections and
objects do not inflate counts. Failed runs and incomplete oracles expose their
observations but withhold confusion counts and accuracy ratios. A missing ratio
denominator is represented by JSON `null`, never zero or a non-finite number.
An empty oracle withholds accuracy with an explicit empty-oracle reason.

| Condition                    | Confusion counts | Accuracy ratios | Raw evidence |
| ---------------------------- | ---------------- | --------------- | ------------ |
| Complete oracle, completed   | Available        | Defined or null | Preserved    |
| Incomplete oracle, completed | Withheld         | Withheld        | Preserved    |
| Crash or timeout             | Withheld         | Withheld        | Preserved    |
| Scenario without a run       | Absent           | Absent          | Absent       |

One report builder produces JSON data and a capability matrix from the same
scenario/check metadata. Markdown and escaped HTML render that matrix; they do
not maintain independent expected-result tables. Columns identify target pack,
scenario, scanner, and release. Undeclared capability/scenario intersections are
explicitly not applicable. Missing runs remain not run. Raw evidence remains in
JSON rather than executable HTML.

The initial consumer is the repository web-micro contract probe. It records
bounded simulation markers and a negative missing-route control. This validates
the report pipeline and target oracle; it is not evidence of production scanner
accuracy. Docker tests consume the report builder, and a localhost contract test
uses the actual first-party HTTP handler when Docker is unavailable.

## Consequences

Runs can be compared across releases or scanners without rewriting the oracle.
Future target packs may declare an incomplete oracle and receive qualitative
matrix cells without false absolute-accuracy claims. Reports are generated local
state under `functional-evidence/` and are retained by existing CI evidence
upload. This decision introduces no external scanner execution, target access,
CLI command, persistence backend, or new runtime dependency.
