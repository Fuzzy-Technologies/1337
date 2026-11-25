# Reviewed passive batch routing

Ordinary branches and master retain their existing acceptance conditions. A
develop PR whose head starts with `feature/passive-batch-` requests a narrower
scope. The branch name grants nothing: the common routing job must verify the
entire actual change inventory against a separately reviewed immutable policy.

The shared `passive-acceptance-routing.yml` workflow checks out candidate Git
objects without running candidate code. It fetches the upstream repository's
fixed `refs/heads/feature/ci-batch-policies` ref once and captures its immutable
commit. The upstream URL comes from the actual GitHub server/repository context,
never a candidate parameter or local policy ref. Every subsequent policy read
uses that captured commit, even if the upstream branch later advances.

The registry holds one independent JSON manifest per batch under
`contracts/passive-batches/`. It is data only: the classifier is read from
`tools/passive_scope.py` at the actual PR base SHA and executed with `python3 -I`.
No classifier from the candidate or policy registry executes. A missing base
classifier or registry entry holds the request. Product PRs do not change a
shared policy commit literal or carry their own admission manifest.

The exact manifest contains `schema_version: 1`, the actual `base_commit`, the
exact `head_ref` and an ordered `changes` array. Each record binds `path`,
`old_mode`, `new_mode`, `old_blob` and `new_blob`. The complete Git raw diff uses
NUL delimiters, full object IDs and disabled rename/external-diff behavior. Only
consistent regular-file addition, modification or deletion is supported. The
actual base must remain the merge base; a changed base requires a fresh review.
The helper bounds both policy and diff to 1 MiB and at most 512 changed files.
Duplicates, unknown fields, missing bytes, links, renames, mode changes,
unreviewed/mixed files and altered source blobs remain held.

Every product and infrastructure change, including the routing workflow itself,
needs its full reviewed old/new blob IDs and modes. Registry records have exactly
the five raw fields above. The loader rejects normalized records and null blob
exceptions before invoking the base classifier. Registry entries must themselves
be ordinary `100644` Git blobs within the original manifest byte ceiling; links
and executable files are refused.

## Create and review one independent registry entry

The exact entry selection is:

```text
contracts/passive-batches/<key>.json
key = SHA256(b"1337-passive-registry-v1\0" + base_sha_ascii + b"\0" + head_ref_utf8 + b"\0" + exact_raw_diff)
```

The NUL framing and complete raw diff bind the actual base, exact request branch,
every changed filename, mode and full old/new blob identity. The Git diff must be
the same ordered output used by CI, not a name-only or normalized projection.
Two independent reviewed batches have separate entries in one registry commit.
An identical raw diff on another branch or base selects a different entry.

Prepare the exact final product tree first. In an owned review directory, obtain
the original base classifier and complete raw diff:

```bash
git --no-replace-objects show "$BASE_SHA:tools/passive_scope.py" > /owned/review/base-scope.py
git --no-replace-objects diff --no-ext-diff --raw -z --no-renames --abbrev=40 \
  "$BASE_SHA" "$HEAD_SHA" > /owned/review/raw-diff
python3 -I - "$BASE_SHA" "$HEAD_REF" /owned/review/raw-diff \
  /owned/review/base-scope.py /owned/policy-checkout <<'PY'
import hashlib
import json
from pathlib import Path
import runpy
import sys

base, head, selected, classifier, registry = sys.argv[1:]
with Path(selected).open("rb") as stream:
    raw = stream.read(1024 * 1024 + 1)
changes = runpy.run_path(classifier)["Changes"](raw)
framed = b"1337-passive-registry-v1\0" + base.encode("ascii") + b"\0" + head.encode("utf-8") + b"\0" + raw
relative = "contracts/passive-batches/" + hashlib.sha256(framed).hexdigest() + ".json"
destination = Path(registry) / relative
destination.parent.mkdir(parents=True, exist_ok=True)
with destination.open("x", encoding="utf-8") as stream:
    json.dump({"schema_version": 1, "base_commit": base, "head_ref": head,
               "changes": changes}, stream, sort_keys=True, separators=(",", ":"))
print(relative)
PY
```

`/owned/policy-checkout` is a separate checkout of `feature/ci-batch-policies`,
not the product checkout. Review its one new manifest against the final diff and
commit it to that registry through the existing owner-managed process. Do not
copy candidate policy code or infer trusted entries from the candidate branch.
CI fetches the registry commit that exists when verification starts. Publishing
an entry alone does not trigger a PR workflow; the next actual readiness/update
event or explicitly rerun check captures the then-current registry snapshot.

This migration itself needs no commit self-reference: its complete new workflow
blob is known before the independently stored registry manifest is committed.
The already present base classifier supports raw exact records. Previously
started PR runs retain their original workflow/policy revisions; do not edit
their evidence or product branches to migrate an in-flight run. A subsequent
rebase changes the base/diff and needs a freshly reviewed registry entry.

## Acceptance and unchanged execution boundaries

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
