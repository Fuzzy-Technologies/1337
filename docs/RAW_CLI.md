# Governed native Nmap CLI

`1337 raw` retains native argument tokens, original stdout/stderr and process status while
using the existing scope, policy, confirmation, process, evidence and canonical model owners.
It is an experimental M2 expert interface described by [ADR0111](adr/0111-governed-raw-nmap-cli.md).

The initial supported matrix is deliberately finite:

| Tool | Profile                 | Native selection                          | Existing capability         |
| ---- | ----------------------- | ----------------------------------------- | --------------------------- |
| Nmap | TCP connect             | Required flags below                      | `network.tcp-connect`       |
| Nmap | Light service discovery | Required flags plus `-sV --version-light` | `network.service-discovery` |

Other tools and Nmap features are outside this initial matrix. The wrapper does not invoke a
shell, install a tool, request elevated privileges or expand the selected scope.

## Explicit native arguments

Use one canonical literal IP and one through 1024 unique explicit TCP port integers.
The following native flags are mandatory, each exactly once:

```text
--unprivileged -n -Pn -sT -p 443,80 --host-timeout 15s -oX - 127.0.0.1
```

Port ranges, DNS names, CIDRs, scripts, credentials, arbitrary extra flags, output file paths,
environment injection and shell command strings are rejected. IPv6 requires `-6` and a canonical
literal IPv6 address. The timeout is an integer from `1s` through `3600s`. Option groups may be
reordered, and port order is retained in the actual invocation. Light service discovery requires
both `-sV` and `--version-light`. The native separator `--` is mandatory; flags after it belong
only to the native grammar and cannot become wrapper options.

First create a workspace and a currently authorized scope using the existing `workspace` and
`scope` commands. Supply a trusted absolute Nmap executable and an explicit existing policy JSON
allowing the selected STANDARD capability for `native.nmap`. The owner must match recorded current
consent; native CLI access supplies no implicit permission.

```sh
1337 raw plan ./owned-workspace --tool nmap --scope local --owner operator:owned \
  --policy ./owned-policy.json --executable /opt/nmap/bin/nmap -- \
  --unprivileged -n -Pn -sT -p 443,80 --host-timeout 15s -oX - 127.0.0.1
```

Planning checks current scope and policy before observing the selected local executable's bounded
health/version metadata. It does not run the target invocation. Its JSON includes the exact
native invocation, observed version and `intent_sha256`; it does not grant execution. The version
basis is the existing bounded local adapter health probe, rather than retained raw version-probe
streams or authority to contact the target.

Confirm the displayed intent separately with a non-secret approval reference:

```sh
1337 raw run ./owned-workspace --tool nmap --scope local --owner operator:owned \
  --policy ./owned-policy.json --executable /opt/nmap/bin/nmap \
  --confirm-plan PLAN_SHA256 --confirmation-reference approval:owned-session -- \
  --unprivileged -n -Pn -sT -p 443,80 --host-timeout 15s -oX - 127.0.0.1
```

Changing executable, observed version, original token order or current authority invalidates the
original confirmation. Policy and consent are checked again at launch and persistence boundaries.
The actual argv digest, rather than a canonical substitute command, binds authorization and evidence.

## Output, status and evidence

By default, the bounded collected original stdout and stderr are delivered separately, byte for
byte, after owned process collection. They are tool data explicitly requested by the operator;
they can contain details reported by that target and tool. This is collected passthrough, not an
interactive terminal or an unlimited streaming channel. Add `--json` before the separator to
request one structured wrapper outcome instead of native stream delivery. Plan and replay always
return JSON. Diagnostics never echo rejected argument values or underlying exception details.

A complete attempt records original stdout, stderr and a `raw-cli-receipt` acquisition. The receipt
binds exact argv, observed version, original execution/termination, confirmation intent, job,
workspace, scope, actor, policy, original stream IDs and the observed model persistence outcome.
It contains no policy document, approval secret or reconstructed provider output. The receipt is
published before workspace reference acknowledgement and truthfully records that ordering as
`reference_persistence: not-yet-acknowledged`; the final outcome independently reports the actual
workspace acknowledgement.

| Outcome                                                                                     | Process exit status           |
| ------------------------------------------------------------------------------------------- | ----------------------------- |
| Complete original custody and required persistence acknowledged                             | Native exit `0` through `255` |
| Native signal termination after complete custody                                            | `128 + signal`                |
| Invalid usage or unsupported native grammar                                                 | `2`                           |
| Current authority or separate confirmation denied                                           | `3`                           |
| Provider availability, timeout, output limit, normalization, custody or persistence failure | `4`                           |
| Cancellation after owned cleanup                                                            | `130`                         |

Native status and wrapper state are separate JSON fields. A native nonzero value may coincide
with a wrapper code; inspect `native_exit_code`, `termination` and `job.failure` to distinguish
them. Native zero cannot mask a wrapper failure. A process that never returned an actual executor
result receives no invented native status or receipt. A lost persistence acknowledgement remains
unconfirmed and is never automatically retried or repaired.

Only successful complete original XML is interpreted through the existing Nmap normalizer.
Individual Host, Port and Service facts preserve original evidence attribution; grouped closed
counts do not invent individual ports, and discovery facts do not become vulnerability Findings.
Normalization consumes the original bytes under the original invocation digest. Failure or partial
output remains evidence rather than positive canonical model facts.

## Offline verification

Obtain the original receipt ID from an explicit JSON run outcome or the workspace's retained
acquisitions, then verify the attached original receipt and both original streams:

```sh
1337 raw replay ./owned-workspace --receipt sha256:ORIGINAL_RECEIPT_ID
```

Replay verifies original manifest identities, bytes, bounded roles, exact native argv, historical
confirmation digest and provenance. It uses no current policy reader, executable, network target
or Save operation. It works after relocating the workspace and shutting down the owned target.
Successful replay establishes historical custody and interpretation, not current execution consent.
Corrupt, unattached, incomplete or context-mismatched original acquisitions fail verification.

## Verification scope

Unit tests exercise exact token grammar, current denial, native and wrapper failures, original
custody, model/workspace acknowledgement loss and rehashed forged receipts. Installed isolated CLI
tests use an explicitly synthetic no-network executable for success, denial, native seven and
relocated replay. These synthetic tests do not establish genuine Nmap behavior.

`tests/functional/test_raw_cli_nmap.py` separately requires the explicitly selected pinned genuine
Nmap used by the existing Nmap acceptance lane. Both profiles exercise the installed product CLI
against pytest-owned loopback listener and bound non-listener sockets, verify original native XML
and hashes, compare individual model port states, and replay a relocated workspace after target
shutdown. Without that opt-in provider, those two acceptance cases remain skipped, not passed.
