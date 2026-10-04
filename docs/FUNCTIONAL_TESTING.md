# Functional testing

## Purpose

Functional tests execute an assembled 1337 behavior against repository-owned,
isolated targets. They do not use Internet demo systems or authorize testing of
any target outside the repository synthetic lab.

## Running the suite

Run the suite from the repository root:

```bash
uv run --locked --extra dev pytest tests/functional
```

Docker Compose is required for target-backed scenarios. When Docker Compose is
not available, target-backed tests are explicitly skipped; they are not reported
as passed. Ubuntu CI must run the same tests with Docker available.

## Scenario contract

Each container-backed scenario is declared in `tests/functional/scenarios.py`. It records:

- target identifier, provenance, version, and Compose service;
- required capabilities;
- setup and cleanup commands;
- deterministic health check;
- assessment command and impact profile;
- expected observations and findings;
- timeout.

`web-safe.health` proves the harness against the safe M0 target. It is not a
scanner-accuracy claim. `web-micro.contract` is the first known-answer pack:
its routes and simulation markers supply a finite TP/FP/FN/TN oracle for the
contract probe. Its canaries never execute commands, access files, make outbound
requests, or persist uploads.

`attack-path-mini` keeps a data-only graph scenario as its versioned contract and
adds a repository-owned executable lab. Five isolated containers realize the exact
Internet-to-business-event identifiers through controlled HTTP service hops. The
functional suite confirms the canonical path, proves the signing-key path remains
policy-blocked, applies identity hardening, verifies the resulting path break, and
resets the state. No host port or external target is used. This proves the lab and
oracle boundary without claiming that the later production graph engine is already
implemented.

Target-backed tests own a shared Compose lifecycle and are marked `serial`.
They execute after the independent pytest worker pool rather than competing for
containers, ports, or generated functional evidence.

## Lifecycle and evidence

Pytest fixtures own startup, health checks, teardown, and raw command evidence.
Each Compose command writes a JSON record under `functional-evidence/`; this is
generated local state and must not be committed. CI retains the directory when
available so a failed lifecycle can be investigated from its actual stdout,
stderr, argv, and exit status.

## Oracle metrics and capability matrix

`fuzzy1337.functional_metrics` is a Development-stability report contract,
schema version 1, defined by [ADR 0018](adr/0018-oracle-derived-functional-metrics.md).
`ScenarioOracle` declares check identifiers, capabilities, positive/negative
expectations, applicability, target provenance/version, and required evidence
roles. `FunctionalRun` preserves scanner/release identity, measured duration,
terminal state, normalized detections/discovered objects, and exact textual raw
evidence. Multiple scanner or release results reuse the same target oracle.

`BuildReport` derives metrics and matrix cells from those declarations;
`SerializeReport`, `RenderMarkdown`, and `RenderHtml` expose the same report as
JSON, an aligned Markdown table, and escaped standalone HTML. Each matrix cell
retains expected and detected state per check, including unknown expectations,
non-applicability, missing runs, crashes, and timeouts. Reports are generated,
ignored evidence rather than hand-maintained capability claims.

Completed runs against a complete oracle use unique check identifiers: TP and
FN come from declared positives; FP comes from detected declared negatives;
TN comes only from declared negatives that were not
detected. Duplicate detections do not inflate counts. FPR is `FP / (FP + TN)`,
recall/TPR is `TP / (TP + FN)`, precision is `TP / (TP + FP)`, and accuracy is
`(TP + TN) / (TP + FP + FN + TN)`. Unexpected detections are retained separately
as a count and identifier list; they never alter the fixed oracle denominator
between scanner releases. Undefined denominators produce JSON `null`. Empty
oracles withhold accuracy with an explicit reason. Evidence completeness is the
fraction of
required roles actually preserved; empty stderr is present evidence.

Crashes/timeouts and incomplete target oracles withhold confusion counts and
accuracy ratios while retaining observations, duration, failure counts, and
evidence completeness. Realistic apps without a complete oracle therefore stay
qualitative regression targets.

The Docker web-micro contract writes `report.json`, `matrix.md`, and `matrix.html`
under `functional-evidence/web-micro-metrics/`. Existing CI retains these files
alongside raw lifecycle commands. Its four safe simulation markers and one
missing-route negative control validate the target/report pipeline; these are
contract-probe results, not production scanner accuracy. A contract test starts
the actual repository HTTP handler on an ephemeral localhost port and exercises
the same mapper/scorer when Docker is unavailable:

```bash
uv run --locked --extra dev pytest tests/contract/test_functional_metrics.py \
  tests/contract/test_web_micro_metrics.py
```
