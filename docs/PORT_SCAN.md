# Governed TCP-connect port discovery

The Experimental `fuzzy1337.portscan` SDK and `1337 scan ports` command compose
the existing optional [Nmap adapter](NMAP_ADAPTER.md), policy, jobs, evidence and
canonical model owners under
[ADR 0092](adr/0092-governed-finite-tcp-connect-product-workflow.md).

Select one literal IP and an explicit set of 1–1024 unique TCP ports. The
product exposes only `native.nmap` / `network.tcp-connect` at STANDARD impact.
The operator supplies a trusted absolute Nmap executable and explicit policy.
No tool is installed automatically. There is no default port set, DNS/CIDR
expansion, service probe, NSE, UDP, OS detection or arbitrary command flag.

## Consent and exact confirmation

Create a workspace and record current consent for the exact owned IP before
planning. The scope must allow that IP; URL-only permission is insufficient.
Current scope is IP-based. The selected ports are additionally bound by the
exact invocation and its separate confirmation intent.

The policy must explicitly permit `network.tcp-connect` from `native.nmap` at
STANDARD impact. `--policy` reads the existing bounded typed policy JSON format.
Planning may run only the bounded local `--version` health observation; it does
not contact the selected target or grant scan authority.

```bash
1337 scan ports owned-workspace --scope local --owner operator:owned \
  --target 127.0.0.1 --ports 18080,18443 --executable /opt/nmap/bin/nmap \
  --policy owned-workspace/port-policy.json --plan --json

1337 scan ports owned-workspace --scope local --owner operator:owned \
  --target 127.0.0.1 --ports 18080,18443 --executable /opt/nmap/bin/nmap \
  --policy owned-workspace/port-policy.json --confirm-plan EXACT_SHOWN_INTENT \
  --confirmation-reference approval:owned-exact-port-plan --json
```

The example assumes the operator owns the two local services and has recorded
that consent. The default timeout is 30 seconds; an explicit integer `--timeout`
must be within 1–3600 and bounds the approved Nmap host scan and executor.
The owning job adds a fixed five seconds for bounded termination, original
stream custody and persistence. This prevents its outer deadline from discarding
already produced output when the inner execution times out.
`--events-json` uses the existing ordered job-event stream.
The foreground shell dispatches the same product command.

`PlanPortScan` returns the exact fixed unprivileged TCP-connect invocation and
confirmation intent. `RunPortScan` accepts the same selection plus a matching
`PolicyConfirmation`. Fresh scope, consent actor, policy, destination and grant
validity are checked immediately before launch and canonical model Save. A
changed selection or authority cannot inherit an earlier approval.

## Observations, original evidence and reopen

Actual stdout/stderr have immutable acquisition records with invocation digest,
observed tool version, execution outcome, times and owning workspace/scope. The
existing parser verifies the exact retained XML before admitting observations.
Canonical Host, Port and reported Service identities match native discovery;
repeated runs preserve logical identities and unrelated operator data.

Only explicit reported ports become individual Port objects. Nmap can group
closed ports into `extraports`; those original groups stay attributable Host
facts, with omitted individual ports unassessed. A completion marker does not
prove every selected port was assessed. Open ports and service names do not
become vulnerability Findings.

Failed, timed-out, cancelled, oversized or malformed execution cannot create a
successful canonical assessment. Available raw acquisitions and job/workspace
references remain attributable. Storage or final authority failures remain
explicit. Exit codes retain the product convention: 0 completed, 3 denied,
4 failed and 130 cancelled. `workspace open` independently verifies saved
evidence and model state, including after workspace relocation without rerunning
Nmap or contacting the old target.

## Deterministic acceptance

Focused SDK/CLI tests use an explicitly synthetic owned executable with no
network activity and retain its synthetic provider version. Genuine acceptance
uses only two pytest-owned sockets on `127.0.0.1`: one listening and one bound
without listening. It independently requires the first to be explicitly open,
the second never falsely open, faithful explicit/grouped output, zero Findings,
original custody, stable repeat identities, installed-console execution and
reopen after target shutdown and workspace relocation.

Required provider CI verifies the official Nmap 7.992 source archive against its
published SHA-256, installs it into a runner-owned prefix, records actual build
and version provenance, and runs
`tests/functional/test_nmap_product_loopback.py` with
`FUZZY1337_RUN_NMAP_ACCEPTANCE=1` and an explicit absolute
`F1337_NMAP_TEST_EXECUTABLE`. Missing or incompatible software fails that job.
An unrequested optional local skip supplies no genuine-provider acceptance.
Original streams, summaries, model, oracle and relocated-reopen facts are retained
under `functional-evidence/nmap-product/` for CI artifact collection.
