# Bounded Quick Scan

The current development candidate adds `1337 scan quick` for native SAFE HTTP(S)
endpoint discovery. It uses the existing scope/policy, governed executor, owned
jobs, immutable evidence and durable Security Object Model. This command is not
present in the immutable v0.2.1 release. See
[ADR 0037](adr/0037-bounded-quick-scan-cli.md) and the native discovery contract.

## Run an owned localhost example

Use an installed current development candidate or the accepted development
checkout (`uv run --locked 1337` in place of `1337`). In one terminal start a
service you own:

```bash
python -m http.server 8000 --bind 127.0.0.1
```

In another terminal create a new workspace and explicitly record the local URL,
its actual IP destination, your authority and the consent validity interval:

```bash
1337 workspace create quick-demo --id quick-demo --name "Owned localhost demo"
QUICK_FROM=$(python -c 'from datetime import UTC,datetime; print(datetime.now(UTC).isoformat())')
QUICK_UNTIL=$(python -c 'from datetime import UTC,datetime,timedelta; print((datetime.now(UTC)+timedelta(minutes=10)).isoformat())')
1337 scope create quick-demo --id local \
  --allow-url http://127.0.0.1:8000/ --allow-ip 127.0.0.1 \
  --grant-consent --owner operator:demo --consent-reference consent:owned-local-demo \
  --valid-from "$QUICK_FROM" --valid-until "$QUICK_UNTIL"
1337 scan quick quick-demo --scope local --owner operator:demo \
  --target http://127.0.0.1:8000/ --approve-safe-http --events-json
1337 workspace open quick-demo --json
```

Stop the service in its owning terminal when finished. No external service is
needed. The first scan reports one host, port, service and endpoint. Reopen verifies
retained immutable evidence and the saved model without contacting the endpoint.
Repeating the scan retains the same logical object identities and adds actual
acquisition provenance. Workspace creation rejects an existing root.

Consent is unknown without `--grant-consent`. A grant requires the owning operator,
non-secret consent-record reference and both explicit time bounds. Registration
and allow rules do not imply consent. `--approve-safe-http` separately opts into
only native SAFE endpoint discovery; it never approves STANDARD or higher-impact
work. A different operator, expired consent, exclusions, missing destination rules
or missing capability approval prevents process launch. Consent references are
operator-recorded metadata; the local CLI is not an identity-provider login flow.
The declared operator must still match the current consent actor at each new grant
and at the final governed launch. Replacing the actor between endpoints prevents
the previous operator's job from continuing, while preserving earlier acquired state.

Use repeatable `--allow-url`/`--allow-ip` and `--exclude-url`/`--exclude-ip` rules
when creating scope. Select each endpoint explicitly with repeatable `--target`.
Discovery accepts literal-IP HTTP(S) URLs with paths. DNS names, queries,
credentials, fragments, inferred endpoints and redirect following are unsupported.
The worker never collects response bodies or cookies. Native scope/policy checks
are repeated at each exact governed launch.

## Bounds and live updates

| Option | Default | Supported bound |
| --- | --- | --- |
| `--max-endpoints` | 8 | 1–16 explicit endpoints |
| `--request-timeout` | 3 seconds | Native provider's finite 0.05–10 second request range |
| `--interval` | 0.2 seconds | 0.05–10 seconds between sequential endpoints |
| `--timeout` | 30 seconds | 0.05–60 second total job/provider deadline |

Starting a job publishes `queued` immediately, before target contact. Real
heartbeat, progress and already-saved model deltas follow while discovery runs.
The summary records `first_model_update_seconds` only when a model delta occurs,
plus the native provider's `first_update_budget_seconds` (request timeout plus one
second nominal local startup allowance, capped by total timeout). Operating-system
scheduling and storage are not a hard real-time guarantee. No useful update is
fabricated on denial or failure.

Default terminal output streams state, progress and model deltas. `--json` prints
one terminal summary. `--events-json` streams schema-v1 JSON lines with `type: event`
and an unchanged owned-job event, followed by `type: summary`. The summary includes
measured times, capabilities, model counts/revision, the job snapshot and exact
ordered events. Raw process output remains in evidence, outside presentation.
The strict outer summary envelope is defined by
[`quick-scan-summary.schema.json`](../contracts/quick-scan-summary.schema.json);
nested acquisition/observation/model payloads retain their existing typed job contracts.

Ctrl+C requests cancellation, awaits owned cleanup and returns a cancelled
summary. SDK callers can cancel the `RunQuickScan` presentation coroutine with the
same behavior. The foreground interactive shell exposes `workspace`, `scope` and
`scan` with the same explicit arguments and live output. A complete concurrent
split-pane TUI remains a separate work item.

| Exit status | Meaning |
| --- | --- |
| `0` | The declared discovery workflow completed; no vulnerability or security-posture claim |
| `2` | Invalid command arguments or authoritative local configuration |
| `3` | Authorization/scope/capability denial |
| `4` | Provider, timeout, normalization, evidence or storage failure |
| `130` | Owned cancellation after cleanup |

A later endpoint failure retains earlier committed model/evidence data and reports
whole-job failure. Workspace references are verified and saved before terminal
success. Storage failure remains explicit even if the native provider completed.
Every earlier retained acquisition is verified before new work and again before
terminal persistence. Missing, corrupted or foreign prior evidence blocks success
and is independently detected by reopen.
Lost process state never implies job success; job/event history is in memory,
while the authoritative model and raw acquisitions remain independently reopenable.

## Scope of this first workflow

This first SAFE path performs endpoint discovery. Optional Nmap/Nuclei/Trivy
enrichment and vulnerability checks are not run or represented as completed.
M2 release acceptance, clean PyPI installation, full TUI and the broader #40
onboarding/CI acceptance are separate gates. Deterministic product E2E tests under
`tests/e2e/test_quickscan_cli.py` own their local target lifecycle and verify allowed,
denied, expired, excluded, timeout, failure, cancellation and repeat/reopen paths.
