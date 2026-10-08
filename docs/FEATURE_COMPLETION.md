# Automatic Feature completion

The project owner requested automatic completion when all native sub-issues are
ready. The post-merge workflow implements this delivery rule without requiring a
separate tracking Task for the automation itself.

## Completion rule

Only an open issue with native GitHub Type `Feature` in this repository can be
closed. It must have at least one native sub-issue, and every child must be a local
issue closed with `state_reason: completed`. An open, cancelled (`not_planned`),
duplicate, malformed, or foreign-repository child prevents closure. Labels, issue
body checkboxes, references, and title text are not completion evidence.

Feature acceptance work must be represented in its native children before those
children are marked complete. This job verifies delivery state; it does not infer
product acceptance from prose or repeat product tests. It adds a completion
comment listing the verified children before closing the Feature as `completed`.

## Execution and catch-up

After a human merges a PR into `develop`, `Close merged tasks` first closes open
native Tasks named by its standalone completion references. A reference to a
Feature cannot bypass the native-child completion rule. Feature reconciliation
then scans all open native Features, including work completed before this
automation was introduced. Ready ancestors are reconciled in the same run.

The reconciliation is part of the same workflow because issue changes made with
`GITHUB_TOKEN` do not trigger a second Actions workflow. It uses the trusted merged
`develop` source with repository-scoped issue write permission. It never executes
the submitted PR head with that permission. The reconciliation jobs are serialized;
Task-closing jobs are not cancelled or coalesced.

The workflow activates after this change is merged. It runs on merges into
`develop`; manually closing a Task is picked up by the next merge. It does not
reopen manually closed Features or deploy the site.

## Verification and failure behavior

`tools/complete_features.py` uses the standard library and paginates issue and
sub-issue collections. Failed requests, invalid collection responses, and exceeded
pagination limits fail the job instead of treating partial data as complete. No
credential is written into source, comments, or diagnostic messages. Resource
redirects are rejected rather than forwarding authentication to moved resources.

Immediately before writing, the job re-fetches the Feature and child set. GitHub
does not provide an atomic compare-and-close operation, so a concurrent hierarchy
edit can still occur between verification and mutation. Maintainers should avoid
editing a ready hierarchy during reconciliation; subsequent edits do not cause an
automatic reopen. Earlier verified closures remain valid if a later API call
fails, and a subsequent merge retries the remaining open Features.

Focused tests cover native Type selection, incomplete and cancelled work,
pagination, nested Features, concurrent edits, repeat execution, HTTP failures,
repository boundaries, and the CLI. PR CI runs those tests and the repository
quality gates. Full local gates are intentionally left to CI under the owner's
development preference.
