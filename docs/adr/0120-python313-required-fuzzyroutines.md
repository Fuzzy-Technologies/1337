# ADR 0120: Python 3.13 baseline and required FuzzyRoutines dependency

- Status: Accepted for implementation under the owner's M3 plan
- Date: 2026-11-02
- Related issue: #392
- Supersedes: the minimum interpreter and dependency-free runtime parts of
  [ADR 0001](0001-python-toolchain.md), and the interpreter family in
  [ADR 0002](0002-container-first-development-baseline.md)

## Context

M3 introduces explainable five-level interpretations using the released
FuzzyRoutines library. The owner selected an ordinary required dependency and
Python 3.13 or newer. Keeping a separate optional integration or copying the
library's mathematics into 1337 would contradict that decision.

## Decision

- Declare `requires-python = ">=3.13"` and exactly `fuzzyroutines==2.1.0` in the
  package metadata and committed uv lock. The published 2.1.0 distribution requires
  Python 3.13 or newer and carries the Apache-2.0 license. Its NumPy extra is not
  selected.
- Exercise Python 3.13 on Linux, Windows and macOS, and Python 3.14 on Linux.
  Tool configuration, doctor, developer and documentation workflows, and current
  release evidence names follow that same baseline.
- Keep existing public identifiers, saved-state formats, explicit approval and
  evidence controls. The interpreter support change does not authorize a model
  schema change or a new risk calculation.
- Use FuzzyRoutines through its installed public API. Subject-specific inputs,
  explanatory labels and interpretation policy belong to 1337; scale mathematics
  remains in the pinned library.
- Test built-wheel dependency metadata and actual isolated library import.
  Installed-package tests provision the exact requirement offline from the uv
  cache populated during locked setup, then run `pip check`. A cold cache or
  missing provisioner fails; test execution does not fetch a dependency.
- The public CI Docker image prepares a hash-locked runtime wheelhouse in its
  builder and installs its app and dependencies without an index in the final
  image. Update the owned GitLab test image to an explicitly recorded 3.13 image
  digest; a changed digest is not a claim that native acceptance has run.
- Preserve fixed v0.3.0 publication-recovery identities and its actual historical
  Python 3.11/3.12 gate evidence. The fixed recovery selects that historical
  matrix explicitly instead of reinterpreting it through current lane names.

## Consequences and validation

Python 3.11 and 3.12 cannot install newly built 1337 distributions. Their retained
historical releases are unchanged. Clean installations now require the pinned
library, so dependency-free runtime claims must be removed from current setup
instructions. Publication remains paused: this change performs dependency setup,
builds and local package tests, with no publisher configuration or upload.

Focused verification includes doctor denial/acceptance, interpreter workflow
contracts, actual sdist/wheel installation, unsupported-interpreter rejection,
installed demo/onboarding execution, and historical release-recovery contracts.
Full integration evidence remains the final PR's shared CI responsibility.
The existing public-index smoke remains the retained dependency-free release
profile while publication is paused; dependency-aware public-index acceptance
must be addressed before publishing a new dependency-bearing release.

## Measured Linux 3.13 integration budget

On 2026-11-03, [run 41588423164](https://github.com/Fuzzy-Technologies/1337/actions/runs/41588423164)
used the complete gate selection on the same proposed revision. The
[Ubuntu 3.13 job](https://github.com/Fuzzy-Technologies/1337/actions/runs/41588423164/job/125759231198)
exceeded the 600-second pytest subprocess deadline at 600.299 seconds and retained
no original JUnit report. Its partial diagnostic remains timing evidence only,
not passing acceptance. The
[Ubuntu 3.14 job](https://github.com/Fuzzy-Technologies/1337/actions/runs/41588423164/job/125759231482)
completed with original JUnit evidence: 13,589 passed, 77 skipped, zero failures,
and 455.336 seconds across the parallel and serial invocations.

Both jobs used four workers. Their retained diagnostic protocols summed to
2,120.955 worker-seconds on 3.13 and 1,290.704 on 3.14, with individual worker
sums of 522.698–534.694 and 314.530–334.713 seconds respectively. The additional
time was distributed across several CPU-intensive modules; no single stalled
test was established. Matching retained protocol hashes do not substitute for
the missing 3.13 JUnit report.

The pinned coverage 7.17.0 `env.py` and `core.py` select CTracer for branch
coverage on 3.13 and default to SysMonitor on 3.14, where the required branch
monitoring events are available. Instrumentation overhead contributing to the
runtime difference is an inference from that source and these timings, not a
controlled benchmark proving causality.

Give only the Ubuntu 24.04 / Python 3.13 matrix entry a 900-second subprocess
budget and a 20-minute job ceiling. Preserve the CLI's 600-second default,
120-second per-test deadline, all other matrix profiles, complete test selection,
branch coverage and failure behavior. The new revision must still produce
successful original JUnit evidence in shared CI before integration.
