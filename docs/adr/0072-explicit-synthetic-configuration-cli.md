# ADR 0072: Explicit closed synthetic configuration CLI

## Status

Accepted bounded consumer decision — 2026-10-14. Advances Task #158 and Feature
#138; native configuration scanner acceptance remains separate.

## Decision

Expose the existing configuration workflow through Experimental
`1337 scan config <workspace> --profile synthetic`. Require `--type dockerfile`
or `--type kubernetes` to select only the corresponding registered synthetic
artifact profile. The existing governed SDK still admits exactly the five
reviewed source/material cases and unchanged worker. The command supplies no
additional source parser, executor, grant issuer, policy or model writer.

The operator explicitly selects the initialized workspace, existing current
ARTIFACT scope, owner, logical source name, absolute source, current trusted
CPython, reviewed worker, material policy and selected-file read-consent record.
`--approve-safe-configuration` is a separate explicit SAFE capability opt-in.
Neither that flag, source selection nor read consent replaces current recorded
owner/scope authority or the SDK's fresh acceptance checks. The canonical scope
command already accepts explicit manifest allow/exclusion rules and consent.
No automatic scope creation or target discovery is introduced.

The adapter directly calls `RunSyntheticConfigurationScan`, preserving its
SCAN-only original execution, four original evidence roles, model/workspace CAS
saves and failure/cancellation semantics. Integer `--timeout` retains its actual
one-through-sixty-second deadline, default thirty. Paired `--report-format` and
`--report-output` select the existing exact-snapshot JSON/SARIF export; export
failure remains distinct from a completed scan and an actual saved model.

`--json` emits the original versioned workflow summary. `--events-json` preserves
ordered canonical job events before one terminal summary. The two modes cannot
be combined. Human presentation labels the workflow `Synthetic Configuration
Scan`. Existing CLI scan routing and foreground shell consume the same adapter;
shell lens/object selection supplies no authority, and history retains only the
`scan` namespace. Missing or unsupported arguments fail before source access,
without reflecting untrusted values in diagnostics.

Exit statuses remain zero for completed scan/requested export, two for invalid
setup, three for authorization denial, four for execution/storage/export failure
and 130 for cancellation. Failed durable publication exposes the actually saved
model revision and acquired process facts without a successful model-delta event.
Confirmed report publication remains visible after acknowledgement failure.

## Acceptance and limits

Contract tests cover explicit required inputs, unsupported profile/type/options,
absolute selection, read consent, deadlines and output-mode pairing. Isolated
unit tests cover precise SDK delivery and safe setup-error presentation. Actual
subprocess E2E tests create the workspace/scope through the CLI, execute all five
unchanged source cases, compare source coordinates to the independent oracle,
reopen/verify the four acquired roles, replay original acceptance and check saved
JSON/SARIF output. Foreground shell, current denial, cooperative cancellation,
model CAS conflict, lost model/workspace acknowledgements and separate report
publication failures use real workflow/executor/store boundaries.

Every configuration identity and Finding remains in the closed synthetic family.
Summary/report completeness stays `not-assessed`, including zero Findings. This
adds no native scanner or arbitrary Dockerfile/YAML acceptance, worker/oracle
change, Core schema change, fixture/runtime installation, PyPI publication or
Task #158 closure.
