# fuzzy1337.ci_commands

This Internal command adapter exposes `1337 ci scan` through the existing closed
synthetic Dockerfile/Kubernetes or separate image VERSION/SCAN workflow, selected
finding predicate and saved report owners. `CiParser` and `RunCiCommands` are
implementation entry points; their import paths are not a Stable extension
contract.

The operator supplies profile/source/runtime/worker/material, current authority,
selected-read consent, SAFE approval, explicit severity/status selections, count
limit, completeness acknowledgement and three distinct new output paths. All
paths are validated before launch. JSON, SARIF and JUnit retain the same exact
saved-snapshot pin and original retained evidence; partial publication keeps
per-file facts and a nonzero outcome.

Exit values distinguish satisfied (0), violated (1), invalid setup (2), authority
refusal (3), integrity/storage/export failure (4) and cancellation (130).
Satisfaction applies only to the explicit current-run predicate and does not
establish global clean state. CLI and foreground shell preserve these outcomes
without deriving authority or selection from shell context.

The explicit `synthetic-image` profile requires an archive and independent image
SAFE opt-in. Configuration profiles require source/logical-path inputs and their
configuration SAFE opt-in; cross-profile arguments fail before launch or export.
Image gating consumes both original typed captures and six immutable execution
acquisitions, never detached operation summaries. Original paired acceptance and
exact saved source inventory/detections precede the criterion, and paired current
acceptance is checked again after publication. The complete saved-model digest
is distinct from the JSON payload SHA-256/size checked against the original
publication outcome. Storage/export failures and uncertain acknowledgements
remain nonzero; triage and unrelated retained full-report facts remain intact.

::: fuzzy1337.ci_commands
