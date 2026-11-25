# Reviewed passive batch routing

Ordinary branches and master retain their existing acceptance conditions. A
develop PR whose head starts with `feature/passive-batch-` requests a narrower
scope. The branch name grants nothing: the common routing job must verify the
entire actual change inventory against a separately reviewed immutable policy.

The shared `passive-acceptance-routing.yml` workflow checks out candidate Git
objects without running candidate code and independently checks out the exact
`PASSIVE_POLICY_COMMIT`. Only the isolated helper from that policy checkout is
executed. The policy commit contains `tools/passive_scope.py` and
`contracts/passive-integration-policy.json`. This supports the initial routing
PR even when develop has no routing helper yet. A missing or placeholder pin
cannot certify the requested batch.

The exact manifest contains `schema_version: 1`, the actual `base_commit`, the
exact `head_ref` and an ordered `changes` array. Each record binds `path`,
`old_mode`, `new_mode`, `old_blob` and `new_blob`. The complete Git raw diff uses
NUL delimiters, full object IDs and disabled rename/external-diff behavior. Only
consistent regular-file addition, modification or deletion is supported. The
actual base must remain the merge base; a changed base requires a fresh review.
The helper bounds both policy and diff to 1 MiB and at most 512 changed files.
Duplicates, unknown fields, missing bytes, links, renames, mode changes,
unreviewed/mixed files and altered source blobs remain held.

Every product and infrastructure change needs its reviewed exact blob identity.
To avoid a commit self-reference, only the common routing workflow can instead
set `new_blob: null` and add `normalized_sha256`. That digest covers the entire
workflow after replacing the value of its one exact
`  PASSIVE_POLICY_COMMIT: "40-hex-characters"` line with forty zeros. The actual
literal must match the executing policy checkout. No other workflow text or
product contents are normalized. Publish the independently reviewed policy
commit before inserting its exact pin into the candidate workflow.

Only the required Python workflow runs the shared router. Optional standalone
acceptance workflows apply a context veto directly to their existing jobs: a
develop PR with a `feature/passive-batch-` head cannot launch those jobs. They
start no router, checkout or unrelated runner for that request. The veto also
blocks old diagnostic markers and does not depend on the manifest result.

The sole required router emits `full`, `passive` or `hold`. A requested batch
with missing, failed or mismatched verification defaults to hold and visibly
fails routing. The required Python guards independently refuse missing/held
scope, so suppression of optional jobs cannot grant a mergeable pass. Exact
manifest verification and the required deterministic passive checks must
succeed. Omitted optional suites contribute no execution evidence. Master and
ordinary-work execution steps, prerequisites, assertions, artifacts, cleanup
and job scheduling retain their original conditions.

The primary Python workflow owns the required deterministic passive profile and
its final guards. Optional acceptance routing is not proof that a scanner,
external target, installed provider or live source was exercised. Required CI
checks and independent review remain integration gates.
