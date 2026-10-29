# Explicit saved-graph path analysis

`1337 paths analyze` exposes the existing attributed reachability and path-analysis
owners over one existing local workspace. The Experimental product profile is
version 1. `fuzzy1337.path_commands` and its parser/handler/helpers are Internal.
It reads explicitly selected original evidence and the exact saved model. It
writes no workspace, model, evidence or hidden output file and runs no acquisition,
scanner, network request or execution. It creates no scope, target or grant.

## Required selections

```text
1337 paths analyze WORKSPACE --json \
  --expected-revision MODEL_REVISION \
  --expected-snapshot-sha256 LOWERCASE_64_HEX_DIGEST \
  --source object:SOURCE_DIGEST --target object:TARGET_DIGEST \
  --transition relation:TRANSITION_DIGEST \
  --no-assessments \
  --context CONTEXT_REFERENCE --scope-reference SCOPE_REFERENCE \
  --as-of 2026-10-14T01:00:00Z --max-age-seconds 3600 \
  --max-depth 16 --max-paths 64 --max-work 4096 \
  --max-frontier 1024 --max-cut-work 100000
```

Replace every placeholder with original current owner references. The snapshot
digest is the SHA-256 of the existing model's canonical `ToDict()` JSON, without
a `sha256:` prefix. The required revision and content digest jointly pin the
complete existing schema-one model and workspace identity. Equal-revision content
substitution is refused. Source and target must be distinct eligible current model
objects. Repeat `--transition` for every selected existing directed `RELATED_TO`
relation; the command discovers no omitted edge or target. Eligible node kinds are
DOMAIN, HOST, ASSET, PORT, SERVICE, ENDPOINT and TECHNOLOGY. Selected transitions
must have eligible existing endpoints. The original projection owner admits at
most 512 eligible objects in the entire pinned model, including unselected or
isolated eligible objects, and 2048 distinct selected transitions. The command
does not partition a larger saved model to bypass this existing profile limit.

Use `--no-assessments` to request an explicitly unassessed graph, or replace it
with one or more `--assessment sha256:ORIGINAL_MANIFEST_DIGEST` arguments. The two
forms are mutually exclusive and one is mandatory. Select at most 32 distinct
original assessment manifests. No file import, URL, reconstructed sealed JSON,
automatic source discovery or semantic grouping grammar is accepted.

Context and scope are explicit non-secret offline attribution, not authentication
or permission to contact any target. The required offset-aware `--as-of` timestamp
is an analysis/replay clock. The command reads no current clock and derives no
current execution authority from that timestamp or retained acquisition metadata.
Context/scope use the existing bounded nonempty, single-line UTF-8 profile.

| Required budget     | Inclusive range | Meaning                                                     |
| ------------------- | --------------- | ----------------------------------------------------------- |
| `--max-age-seconds` | 0..604800       | Original support/assessment freshness at the supplied clock |
| `--max-depth`       | 1..32           | Maximum simple candidate depth                              |
| `--max-paths`       | 1..256          | Returned simple candidate ceiling                           |
| `--max-work`        | 1..20000        | Search successor examinations                               |
| `--max-frontier`    | 1..4096         | Search pending-prefix ceiling                               |
| `--max-cut-work`    | 1..2000000      | Separate shared witness/removal-check work ceiling          |

## Original evidence admission

The command first opens the actual owning workspace/model and verifies the exact
pin and selected graph. It checks every selected original assessment manifest
before reading any selected assessment raw bytes. Each must retain its exact
canonical manifest identity, workspace/scope, `reachability-claims` role,
`application/json` media type and source version `1`, with no invocation/execution
substitution. Original source/provider identity remains explicit and unchanged.
Assessment envelopes use the existing supplied-transition-attestation profile,
exact context/scope and owning workspace. At most 2048 declarations are admitted.

Before any support blob read, validate all declared original support manifests,
their exact workspace/scope and any existing retained observation's subject,
complete evidence-reference set and source/provider/time/execution joins. Original
support roles and format versions remain SDK-owned; no product role relabelling
occurs. Support is limited to 256 distinct manifests, 16 identities per basis entry
and 64 KiB per original support blob. Assessments are limited to 256 KiB each;
manifest metadata retains its existing one-MiB schema ceiling. Check actual blob
size as well as its declared size before reading it. Reject observed symlinks,
reparse points, nonregular selected files and multiply linked selected artifacts.
Original metadata/assessment reads additionally check bounded bytes and stable
path/handle identities, including the existing Windows cross-view allowance.
Unselected same-blob aliases are not enumerated through a generic report reader.

The unchanged owning `ReadReachabilityClaims` then reconstructs and verifies the
actual original records/bytes and source joins. Its sealed result is passed to
`ProjectReachability`, then `AnalyzeReachabilityPaths`; supplied JSON never replaces
any sealed owner output. The actual saved model/workspace is reread before success
presentation. Retained replay survives relocation of the complete owning workspace.
Concurrent hostile directory replacement remains outside the existing local
pathname storage contract; this command adds no alternate storage authority.

Missing evidence/basis, stale model/support, future or failed support and other
original unusability reasons remain attributed UNKNOWN inputs when the SDK permits
that outcome. A stale assessment model pin is not silently updated or rejected
solely for staleness. Corrupt bytes or substituted identity/context/source joins
are refused. Failed analysis preserves original stored artifacts without repair.

## Bounded explanations

JSON output is one schema-one `paths.analyze` outcome on stdout, capped at one MiB
including the terminal newline. It contains the complete current model pin, exact
offline context/scope/clock, sorted original assessment manifest pins and a detached
safe explanation. It includes original transition states/reasons and supplied claim
provenance, returned original node/hop references, individual confidence estimates,
named barrier claim references, admission coverage, participation by original path
state and single-removal structural counts. Original unusable estimates retain
their declared values with no effective confidence. Raw witnesses, observation
attributes and private SDK seals are excluded.

Participation and removal counts concern the returned candidates. Already BLOCKED
paths do not inflate the additional removal denominator. Source/target endpoints
are excluded from node-removal suggestions. Counts are not calibrated risk,
probability, cost ranking or mitigation efficacy. No source claim is promoted into
measured physical access or inferred automatically from findings/cooccurrence.

`analysis.search.complete`, search limits and reasons describe the simple-path
enumeration. `analysis.cuts.complete`, its separate work limit/reasons and
`candidate_route_exists` describe independent reachability/removal checks over the
full explicitly selected nonblocked graph. The latter existence value is true,
false or null when its check is unfinished. Verified cuts, checked alternatives
and unverified candidates remain separate. A depth-limited search with no returned
path cannot establish route absence or manufacture a choke point. Even complete
selected-graph checks establish no network-global completeness or effective access.

DTO construction accounts for repeated explanation records incrementally and
checks the final serialized ceiling. An oversized explanation is refused instead
of silently truncating fields. Plain text presents the returned-path count and
separate search/cut completeness; `--json` retains the detailed original reasons.

| Exit code | Result                                                                   |
| --------- | ------------------------------------------------------------------------ |
| 0         | Completed bounded analysis, possibly with explicit search/cut truncation |
| 2         | Invalid or omitted explicit configuration/selection                      |
| 4         | Model/proof/integrity/read/output failure; no partial analysis DTO       |
| 130       | Interrupted analysis; no partial analysis DTO                            |

Failures expose fixed categories without original exception bodies or rejected
input literals. Every outcome reports no Core/evidence mutation and no authority.
Static `1337 paths --help` reads no workspace. Shell invocation is foreground;
the registered command retains only the existing protected command-name history.

## Verification and remaining work

An independent handwritten six-node graph has two exact original paths, one shared
interior pivot and one shared relation: two verified structural single-element
cuts. Tests compare the real handler and installed console against those counts,
then independently vary enumeration and cut bounds. Actual existing source
producers exercise six original attestation phases, named barriers, conflicting
claims, stale/future/failed or missing support, relocation, model/byte tampering,
typed-manifest and physical-alias refusals, output limits and no-write/network
tripwires. Existing SDK oracle tests continue to own broader algorithm semantics.

This slice advances #55/#56 without closing their remaining work. Automatic
semantic grouping, large-environment partitioning, validated sensor/attack
semantics, multielement remediation, scores/probability, source producers beyond
the existing accepted profile and new authority contracts need separate accepted
decisions. PyPI and release behavior are unchanged.

See [original reachability](REACHABILITY.md), [pure path analysis](PATH_ANALYSIS.md)
and [ADR 0083](adr/0083-explicit-saved-graph-path-cli.md).
