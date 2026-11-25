# ADR 0150: Development compatibility profiles and shared full test coverage

## Status

Accepted for implementation. Refs #118; incorporates the workflow-only macOS
profile proposed in #512. This decision does not change the owner-controlled
development protocol.

## Context

Ready PRs previously repeated the complete repository test selection in four
native Python/platform jobs and in a Python 3.13 Linux container. The container
must establish its actual runtime and installed-package boundaries, while the
native Ubuntu Python 3.13 job already owns complete branch and per-module
coverage on that Python version. The existing macOS full-suite timeout has
separate measured evidence in #512. Local implementation checks already select
only the changed feature and its regressions.

## Decision

Keep existing required job names, readiness and draft cancellation semantics.
Ordinary integration and stable/master routes retain their complete native and
container gates. Only an independently admitted Ready passive batch to `develop`
uses these profiles:

| Job                           | Test responsibility                                            |
| ----------------------------- | -------------------------------------------------------------- |
| Ubuntu / Python 3.13          | Units/boundaries or verified test-only files; scoped coverage  |
| Ubuntu / Python 3.14          | Runner, report, and workspace compatibility units              |
| Windows / Python 3.13         | Compatibility units and actual owned TLS lifecycle boundary    |
| macOS / Python 3.13           | Offline runner/progress portability selection from #512        |
| Linux container / Python 3.13 | Clean wheel/runtime installation and actual worker execution   |

The authoritative Linux unit job retains compile, lint, typing, performance and
build phases. The macOS and container profiles also retain those phases. The
container runs bounded runner, progress and package unit tests plus the actual
packaging and progress-execution integration tests in two workers. Its clean
install resolves runtime dependencies from existing local material; tests do
not fetch missing dependencies. Focused compatibility profiles disable
repository-wide coverage and retain their actual JUnit outcomes. They do not
claim complete repository coverage. Failures propagate; no retries or successful
placeholders replace an executed required check.

The passive gate invokes the real process-isolated pytest runner for all units,
then appends the 14 reviewed contract/integration/E2E files for the actual batch.
The supplemental coverage configuration enables subprocess measurement so the
installed CLI children participate. The global project coverage configuration is
unchanged. Each parallel/serial partition is independently collected and its
JUnit must contain every case exactly once. Missing tests, errors and unexpected
skips fail the gate. The only declared deferrals are the 11 exact documentation
fixtures that require the separate hashed docs lock; the documentation job runs
those fixtures with that lock. Their general-unit skips are recorded explicitly.

The passive coverage claim is strictly scoped to every surviving Python
production module changed by the actual base/head diff. A temporary explicit
inventory reuses the existing coverage validator without changing any measured
counts or its strict combined statement/branch >80% threshold. Raw whole-source
coverage and the scoped receipt are retained; the receipt explicitly declines a
global all-module claim. Removed/aliased modules and missing branch measurements
refuse acceptance. Ordinary full checkpoints and master retain their complete
all-layer, all-module coverage gate.

The required Python workflow verifies the complete batch against a separately
reviewed manifest in a captured immutable registry commit. A branch prefix requests passive verification and
never earns acceptance. A missing, failed, skipped or held routing decision
fails required checks; the container guard runs before any Docker action.
Optional active/external workflows reject every requested passive branch
without allocating duplicate router jobs. A passive marker cannot launch an old
active draft diagnostic. The required synthetic lifecycle instead verifies
benign isolated startup, health and cleanup; it does not run attack scenarios.

The saved-report base-owned acceptance from #522 remains an independent
additional requirement. Its failure reaches the required container check. The
external-target lane additionally requires both the integration `full` profile
and the saved-report classifier's `full` result, preserving ordinary report-only
suppression. No rejected passive request falls back to active acceptance.

Routine feature work uses focused selections; an owner-requested full unit run
may execute locally. Reuse that exact measured checkpoint rather than duplicating
it across agents or after integration into `develop`. A final admitted Ready
passive batch is the shared full-unit checkpoint; platform and package
compatibility establish their own narrower boundaries.

### Independent policy registry migration

The initial bootstrap stored one `PASSIVE_POLICY_COMMIT` literal in the shared
routing workflow. Independent product PRs therefore conflicted while selecting
different reviewed policies. The accepted successor fetches the actual upstream
`feature/ci-batch-policies` ref once, captures its immutable commit and selects
one `contracts/passive-batches/<sha256>.json` blob. The SHA-256 key frames the
actual base commit, exact head branch and complete raw full-object diff with
NUL delimiters. Independent batches use separate manifests in one registry
snapshot without editing a shared product file or adding another CI action.

Policy registry contents are data only. The isolated classifier is extracted
from the actual base commit, never the candidate or policy registry. Every
record binds all five raw fields exactly; the new loader rejects the historical
normalized-workflow exception. Missing, crossed, malformed, oversized or
nonregular policy blobs remain held. Ordinary/master routes and optional active
vetoes are unchanged.

The migration can be admitted using the existing base-owned raw classifier.
Its final workflow blob is already known when the separate registry manifest
is prepared, so no normalized content or self-referential commit pin is needed.
Previously started checks remain bound to their original revisions. See
[`PASSIVE_ROUTING.md`](../PASSIVE_ROUTING.md) for the exact key and reproducible
entry construction.

Keep the existing `loadscope` scheduler and bounded automatic worker cap.
Independent cases run in process-isolated workers; declared `serial` cases run
afterwards with `-n 0` and append branch coverage. Serial discovery accepts only
pytest exit status 0 or the explicit no-tests status 5; collection failures must
fail rather than silently omit the serial partition.

### Verified test-only unit selection

The existing passive/develop Linux invocation may use a smaller test-only
selection. This is a selection optimization inside an already admitted batch,
not another integration profile or a way to obtain passive admission. The
workflow, optional/active job decisions, master/full gates and platform worker
settings are unchanged. The original event must identify the exact Ready
develop PR base and checked-out head on the existing passive request branch.

Capture the complete raw base/head diff once, with full blob IDs, modes and no
rename inference. Reuse it for changed-production coverage. Narrow only when
every change modifies an existing regular `tests/unit/test_*.py` file, with an
optional exact removal of naming-baseline rows. No additions, deletions,
renames, mode changes, configuration, product, shared helpers or unknown paths
qualify. A tooling change, including this optimizer's own implementation, keeps
the complete existing all-unit and offline-boundary selection.

Inspect tracked Python consumers through a bounded, status-checked Git search
and AST inspection. A selected module's explicit `pytest_plugins` registration at either endpoint
refuses narrowing. Visible imports, plugin names, module references, dynamic
calls and reads using the module name refuse narrowing. Declarative pytest
parameter data may name an existing test selector without importing its
fixtures. Inspection errors and ambiguity retain the existing all-unit passive
gate. This conservative dependency check does not prove semantic independence
of arbitrary Python code; the independently reviewed full raw diff remains
the passive admission boundary.

A changed baseline may only remove the exact existing `local` findings that
disappeared from those selected source files. Compare compiler-derived naming
findings before/after, the complete baseline multiset and the original bytes
with only those rows removed. Added debt, other row kinds, unrelated removals
and formatting changes retain the complete passive selection.

Run every case in each affected file, plus the complete Python style,
source-documentation/header, naming-regression, passive-gate and passive-profile
regression files. The existing preceding naming command still checks the
whole repository; it is not replaced by its fixture regressions. Preserve
independent collection, exact JUnit identities with cases from every selected file, parallel/serial separation,
timeouts, worker caps and failure propagation. Do not accept selectors from
a PR body, label or input file.

Retain the true collected counts and explicit selected files in the receipt,
along with base/head and every changed blob/mode record. Test-only acceptance
records no changed production modules and declines a global module claim.
Raw branch coverage remains available. Every product or other ineligible
change retains all units, all existing offline boundaries, subprocess
measurement and the unchanged strict changed-module coverage algorithm.
Several eligible leaf test modules may share one short run; a mixed product
batch cannot.

## Validation

Workflow tests interpret the actual profile conditions across 128 combinations
of event, base branch, draft state, matrix cell and admitted profile. Each admitted route must execute
exactly one real profile. Draft routes execute neither.

A real runner regression uses two independent synthetic modules and a bounded
rendezvous to require two simultaneously active OS worker processes. Eight
independent cases and one later serial case create exclusive receipts. JUnit
counts prove the disjoint complete partition; branch data prove serial coverage
was appended rather than replacing the parallel measurement. No elapsed-time
speedup is inferred from that scheduling proof.

The compatibility selections must pass in their actual macOS/container GitHub
Actions jobs before merge. Local success cannot establish those environments.
