# fuzzy1337.path_commands

Experimental `1337 paths analyze`, product profile version 1, is implemented by
this Internal module. All its Python classes, functions, methods and helpers are
Internal, including `PathParser`, `PathEvidenceStore`, `PreflightProof`,
`PreflightAssessments`, `OutputBudget`, `PathDocument` and `RunPathCommands`.
Importability and authored API discovery do not establish a supported Python SDK.

The command requires an existing local workspace, complete schema-one saved-model
revision/content pin, distinct original source/target, explicit existing directed
`RELATED_TO` transitions and original assessment manifest IDs or explicit
`--no-assessments`. Context/scope, offset-aware `--as-of`, freshness and every
finite search/cut budget are mandatory. Snapshot SHA-256 uses 64 lowercase hex
characters without `sha256:`; original evidence IDs retain that prefix. The
unchanged SDK ceiling applies to all eligible objects in the entire saved model:
at most 512, including isolated/unselected objects. Check this before proof I/O;
at most 2048 selected transitions are allowed. No implicit partition, source/edge
discovery or semantic grouping is introduced.

Selected original canonical manifests are metadata/profile/context preflighted
before their raw reads. Assessment role/media/source version remain
`reachability-claims` / `application/json` / `1`, with no execution/invocation
substitution, at most 32 original manifests and 2048 total declarations. Actual
assessment bytes are bounded at 256 KiB each. Every declared support manifest and
existing retained observation join is preflighted before support blobs are read:
exact workspace/scope, subject, full original reference set and source/provider/
time/execution attribution. Support role/format versions stay SDK-owned, with at
most 256 distinct manifests, 16 IDs per basis entry and 64 KiB per support blob.
Manifest metadata retains the existing one-MiB ceiling. Reject physical size
mismatch/overflow, observed links/reparse points, nonregular selected files and
multiply linked selected artifacts. Bounded metadata/assessment reads check full
same-view identities and the existing Windows cross-view path/handle allowance.
No generic report reader eagerly enumerates unrelated same-blob aliases.

Call unchanged `ReadReachabilityClaims`, `ProjectReachability` and
`AnalyzeReachabilityPaths` in that order. Actual original owning records and
sealed outputs are mandatory; caller-reconstructed JSON cannot substitute for
them. The actual full saved model pin is checked before consumption and current
workspace/model is reread before success. Original records/bytes and complete
workspace relocation remain intact; the existing cooperative local pathname
storage contract is unchanged.

The one-MiB schema-one terminal DTO excludes raw witnesses, observation attributes
and private seals. It retains original selected transition states/reasons and
proof references, original paths/hops/barriers, individual supplied/effective
confidence estimates, admission coverage, participation and structural
single-removal counts. Unusable stale/future/failed/missing proof remains
attributed UNKNOWN where the SDK permits it; original declared confidence is
preserved without effective confidence. A stale assessment model pin is not
rewritten to the current model. Substituted identities/context/joins or corrupt
bytes are refused without rewriting any original stored artifact.

Search completeness, limits and truncation reasons remain separate from
independent cut-work completeness, verified cuts, checked alternatives, unverified
candidates and true/false/unknown selected-graph route existence. Removal counts
concern returned nonblocked candidates; they are not probability, cost/risk,
physical exploitability, global completeness or validated mitigation efficacy.
Repeated DTO records are charged incrementally and the final serialized ceiling
includes its newline. Oversized results fail without partial analysis output.

Exit statuses are `0` for completed bounded analysis, including honest truncation;
`2` for invalid configuration/selection; `4` for basis/proof/integrity/read/output
failure; and `130` for interruption. Failures keep generic categories without
original exception bodies or rejected literals. Every outcome reports no
Core/evidence mutation and no authority. Static help reads no local state.

Optional `--html` presents the same successful original schema-one outcome through
the Internal `path_rendering` owner. It is mutually exclusive with root `--json`.
All admission/basis checks remain before rendering. The HTML profile refuses more
than 64 selected nodes, 128 transitions or a final four-MiB artifact; it does not
partition the graph or alter the existing JSON limits. Failures preserve ordinary
fixed-category text without partial HTML. The offline graph, original inspection,
exact JSON/static SVG downloads and fixed-script CSP are described in
[the renderer reference](fuzzy1337.path_rendering.md).

The additive Experimental `paths compare` route delegates to the Internal
`path_comparison_commands` owner. It invokes ordinary original analysis for two
explicit assessment selections on the same pinned saved basis and permits only
the selected focus transition's state label to differ. The separate bounded pair
retains both complete outcomes without implying chronology, causal control
effectiveness or risk. See [comparison commands](fuzzy1337.path_comparison_commands.md)
and [static comparison presentation](fuzzy1337.path_comparison.md). Ordinary
`paths analyze` admission, output and rendering limits remain unchanged.

Installed-console and foreground-shell routes share this owner. Shell context
supplies no omitted selections or grants, and protected local/native history and
empty-line replay keep only `paths`. The module acquires nothing, writes no
workspace/model/evidence or hidden output, runs no scanner/process/network
request and grants no scope, target or execution authority. Existing SDK/Core,
schemas, scoring, source-support and grouping contracts remain unchanged.

See [product usage](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/PATHS_ANALYSIS.md)
and [ADR 0083](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/adr/0083-explicit-saved-graph-path-cli.md).

::: fuzzy1337.path_commands
