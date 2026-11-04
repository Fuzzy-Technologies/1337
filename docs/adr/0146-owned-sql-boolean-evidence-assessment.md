# ADR 0146: Owned SQL boolean evidence assessment

## Status

Experimental design for the internal assessment slice of #411, following
[ADR 0144](0144-owned-sql-boolean-response-sampling.md).

## Decision

Compose a read-only evaluator over four ordered, independently confirmed native
samples on one admitted loopback SQLite GET path coordinate. The four roles are
baseline, true, false and repeated baseline. The origin and fixture route prefix
stay fixed, with one final path input slot. The scope and policy revisions,
operator and per-request budgets stay constant across the comparison. Each probe
still belongs to its existing native execution boundary.

The trusted in-process owner supplies the workspace state captured before
execution, the four exact plans it used to confirm and launch the probes, and
only the terminal summaries returned for this assessment. Require an exact
ordered suffix of current workspace job
references. Interleaved jobs, reused acquisitions and wrong role inputs fail
the join. Reopen both worker streams by acquisition identity, verify the exact
invocation and execution metadata, and require the matching current saved
observation. Equal bytes or equal blob references alone cannot prove two
independent executions. Preserve incomplete execution as a partial result.

The proof binds invocation, workspace job references, acquisition IDs and saved
observations. The terminal summary and acquisition manifests omit the policy
revision and confirmation intent. The repeated baseline can also share its
intent digest with the original baseline. Separate authorization therefore
relies on the trusted owner passing the actual plans and corresponding
results from its individually confirmed calls.

Compare verified complete worker body digests only:

| Evidence                                                                | Assessment               |
| ----------------------------------------------------------------------- | ------------------------ |
| Baselines differ                                                        | Unstable baseline        |
| Stable baselines and equal true and false samples                       | No differential observed |
| Stable baselines equal the true sample and differ from the false sample | Differential candidate   |
| Other complete combinations                                             | Inconclusive             |
| A missing or unsuccessful sample                                        | Partial                  |

A candidate describes this finite response pattern. Bodies are transient in the
current worker contract. Digest metadata supports only this comparison, while
distinguishing reflected input from SQL execution requires body interpretation.
The evaluator reads local retained evidence and returns a classification in
memory.

## Deferred boundaries

A product workflow needs an explicitly owned durable parent assessment journal
binding the run ID, ordered child jobs, exact plans and acquisition IDs. This
slice relies on trusted current in-process results and does not infer a parent
assessment from existing workspace history or expose a persisted or public
schema. A future owner must bound the full operation, recheck authorization for
each separately confirmed request and preserve the executed prefix on every
failure. Body interpretation, other request locations, error and timing
profiles, and any Finding policy require separate designs and controls.

## Verification

Use the existing governed sampler on the owned SQLite target for both actual
vulnerable and parameterized routes. Cover role drift, stale and mixed run
receipts, conflicting saved observations, corrupted original evidence,
instability and missing or failed samples. Verify that comparison performs no
target operation and creates no Finding.
