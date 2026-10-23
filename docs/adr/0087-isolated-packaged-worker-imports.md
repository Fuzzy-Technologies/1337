# ADR 0087: Isolated packaged worker imports

- Status: Accepted for implementation
- Date: 2026-10-23
- Decision owners: Fuzzy Technologies
- Related work: #40, #59

## Context

The governed executor correctly uses the selected workspace as process cwd and
sanitizes its environment. Python module execution with `-m` nevertheless places
that cwd on the import path. A workspace-local package could therefore replace
a packaged first-party worker, execute under the scanner process account and
emit a fabricated valid observation without contacting the selected endpoint.
Independent owned regressions reproduced this for native HTTP discovery and
closed-page acquisition. No remote exploitability is asserted: the reproduced
precondition is attacker-influenced Python files inside an operator-selected
workspace alongside ordinarily authorized execution.

## Decision

Prepare the packaged native HTTP and closed-page workers as the existing trusted
interpreter followed by `-I -m` and the exact packaged module/arguments. Isolated
imports exclude cwd/PYTHONPATH while preserving the selected installed environment,
including an explicitly installed development checkout. Existing scope, policy,
capability, resource limits, executor cleanup, record validation and model owners
remain unchanged. This is import-path isolation, not an OS process sandbox or
authentication of arbitrary installed environment contents.

Current page-provider invocation validation admits only the isolated prepared
shape. Old non-isolated argv must never be restored for a new product launch.
Pure adapter report normalization may still admit the exact historical prepared
shape derived from the same typed request. It preserves the original argv and
invocation digest; it does not rewrite old evidence to resemble a new execution.
No arbitrary argument removal, alternate interpreter/module, altered timeout or
unvalidated request shape is admitted. Read-only legacy acceptance grants no
capability and cannot authenticate which code originally produced old reports.

Read page-report destination/catalog/body bounds from already validated request
parameters rather than positions that differ between old and isolated argv.
Provider versions and strict worker record schemas remain unchanged. Existing
saved model/evidence consumers retain their original integrity and provenance
semantics; no evidence migration, history rewrite or release is needed.

## Validation

Create inert shadow packages inside disposable owned workspaces. Execute actual
installed governed HTTP discovery and page acquisition, with separate current
scope/consent and owned local listeners. Assert no marker executes, the real
target receives exactly the selected request, and genuine observed evidence and
canonical model facts persist. Preserve denial-before-contact and owned cleanup.

Exact legacy adapter reports must still normalize without changing argv/digest.
Default current page invocation validation must reject that legacy shape.
Mutated legacy/current arguments, fields, evidence and catalog bindings fail.
Run focused native/page/traversal/captured-web regression layers and standard
static checks, then required exact-head shared CI before integration.
