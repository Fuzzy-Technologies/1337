# fuzzy1337.raw_cli_workflow

Experimental SDK entry points `PlanRawCli`, `RunRawCli` and `ReplayRawCli` provide
the governed Nmap-only native workflow from ADR 0111. `RawCliPlan` and
`RawCliSummary` expose its exact invocation and independent wrapper outcomes.
`RawCliWorkflow` and `ReadRawRecord` are Internal implementation helpers, rather
than additional execution or evidence authorities.

Planning checks current recorded scope, actor and typed policy before the existing
bounded local health/version observation. That metadata is not retained raw
version-probe custody and grants no target authority. Execution requires separate
confirmation of the exact native invocation and fresh current authority at launch
and persistence boundaries; an equivalent reordered command needs a new intent.
The existing governed process, job, evidence, model and workspace owners remain
authoritative.

Original stdout, stderr and a bounded `raw-cli-receipt` retain actual argv,
observed version, execution/termination, historical plan digest and original
context/stream identities. Successful original XML produces attributed Host,
Port and Service facts through the existing normalizer. Grouped counts do not
invent individual ports, and discovery facts do not become vulnerability Findings.
Failed or partial output cannot create positive canonical model facts.

The summary returns native exit status only after complete custody and required
persistence acknowledgement. Usage, denial, wrapper failure and cancellation
retain codes 2, 3, 4 and 130; native zero cannot mask a wrapper failure. Native
signal status maps to `128 + signal`. Inspect native status, termination and job
failure separately when numeric statuses overlap.

Each canonical Save is attempted once against its original revision basis. A lost
acknowledgement remains unconfirmed without retry, repair or rebase. The receipt
is acquired before final workspace reference acknowledgement and records that
ordering as `reference_persistence: not-yet-acknowledged`; the final summary reports
the independently observed acknowledgement.

`ReplayRawCli` independently verifies an attached original receipt, bounded
original stream identities/bytes and historical invocation context. It runs no
tool, reads no current policy or target, and performs no Put or Save. Relocated
replay verifies historical custody rather than current execution permission.

See the [raw CLI guide](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/RAW_CLI.md).

::: fuzzy1337.raw_cli_workflow
