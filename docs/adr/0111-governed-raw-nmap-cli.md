# ADR 0111: Governed raw Nmap CLI with original evidence

## Status

Accepted for implementation — 2026-10-29. Task #34.

## Context

Expert users need to retain familiar native arguments and output when invoking a
tool through 1337. An unparsed arbitrary command line cannot prove its actual
destinations, impact, filesystem effects or privilege requirements. The existing
Nmap adapter already owns two finite STANDARD capabilities and original XML
normalization, while PolicyEngine, the governed executor, Jobs, Evidence and the
Security Object Model own their respective boundaries.

## Decision

Add the Experimental `1337 raw plan|run|replay` route and a dedicated SDK. M2
supports the `nmap` tool with its existing `network.tcp-connect` and
`network.service-discovery` profiles. This is a supported-profile matrix, not a
claim of unrestricted Nmap, Nuclei, Trivy or arbitrary tool support.

The operator supplies an absolute trusted executable and passes native argument
tokens after `--`. Preserve every accepted token and its order in the actual
shell-free invocation, exact confirmation intent and retained receipt. Do not
execute a reformatted high-level `scan ports` command or authorize a canonical
substitute for the command that actually launches.

Require `--unprivileged`, `-n`, `-Pn`, `-sT`, an explicit `-p` comma-separated
unique port set, `--host-timeout Ns`, `-oX -`, one canonical literal unicast IP,
and `-6` exactly when that IP is IPv6. Optional `-sV --version-light` selects the
existing service-discovery capability. Permit option-group reordering; reject
duplicate, combined, unknown or extra options and targets. There is no NSE,
DNS/CIDR expansion, UDP/OS detection, input file, credential, caller environment,
output pathname, shell command or privilege expansion.

A dedicated adapter preserves the original native argument tuple after the
existing Nmap adapter validates the derived request. Its inherited normalizer
must validate the same actual invocation and independently verified original XML
bytes. It must not consume output attributed to a rewritten command. Existing
Host, Port and Service identities and grouped/unassessed port semantics remain
unchanged; discovery does not create vulnerability Findings.

Planning checks current recorded scope, owner and typed capability policy before
the existing bounded local version observation, then binds the observed version
into a fresh exact intent. Health metadata does not claim retained version-probe
streams or grant scan authority. Run requires a separate confirmation of that
exact intent. Fresh scope, policy, actor and fixed grant validity are checked at
launch and before canonical persistence. A changed token order changes the
invocation and requires a new confirmation even if its parsed meaning is equal.

The original stdout/stderr acquisitions and a bounded JSON receipt retain actual
arguments, version, exit/termination, hashes, workspace/scope/policy/job context
and original evidence IDs. Failed, cancelled, timed-out, oversized or malformed
output cannot become a successful model assessment. Partial custody, lost Save
acknowledgement and reference-retention failure remain explicit; no automatic
retry, repair or rebase is introduced.

Default execution writes actual native stdout and stderr to their corresponding
terminal streams after bounded collection. Explicit `--json` instead emits one
structured outcome containing the original references and separate native exit
status. Return the native 0–255 status only after complete original custody and
acknowledged required persistence. Usage, denial, wrapper failure and cancellation
retain 2, 3, 4 and 130 respectively; a native zero never masks a wrapper failure.
Negative native signal status maps to `128 + signal`. The receipt distinguishes
native status from the wrapper outcome when numeric codes overlap.

Historical replay verifies the selected original receipt, actual invocation and
all original streams in the same or relocated workspace. It launches no tool,
reads no current policy or target, and performs no Put, Save or repair.

## Acceptance

- Pure contracts exercise both profiles, ordering, literal address/port/time
  limits and explicit rejection of unmodeled flags and authority expansion.
- Actual installed-console tests prove exact original arguments, native output,
  exit status, failed/denied outcomes, evidence hashes, normalized objects and
  offline reopen. Controlled stand-ins remain explicitly synthetic.
- Genuine optional-provider acceptance reuses the pinned Nmap installation and
  pytest-owned loopback listeners. Missing required native software fails that
  requested lane; an unrequested local skip is not acceptance.
- Independent source/evidence review and final shared integration precede merge.

## Consequences

This provides one useful raw expert route with two existing tool capabilities.
Additional tools or native options require their own destination, impact,
artifact and normalization contracts. The route does not authorize arbitrary
Internet targets, silently expand scope, install Nmap or change its license.
