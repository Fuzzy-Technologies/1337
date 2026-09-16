# ADR 0015: Governed Local Executor Boundary

## Status

Accepted

## Context

Tool adapters can prepare immutable argument vectors, but they must not own
process lifecycle, authorization, cancellation, or resource handling. 1337 needs
a first executor that works without a heavyweight tool pack and can stream
progress to the Workbench while preserving exact terminal execution truth.

The initial boundary must not pre-empt the separate Scope and Policy work. A
declared capability is not authority, and a local subprocess API must not become
an unrestricted shell path.

## Decision

1337 introduces an experimental, versioned executor SDK under
`fuzzy1337.executors` and a first `LocalExecutor` implementation.

The executor accepts only a prepared `AdapterInvocation` bound to:

- an explicit capability and maximum impact;
- required and granted privilege identifiers;
- an upstream authorization record containing scope and policy references;
- a SHA-256 digest of the exact immutable invocation;
- a relative workspace below one configured root;
- bounded stdout, stderr, timeout, and termination-grace resources.

The local provider invokes argument arrays through `shell=False` semantics. It
inherits only a small platform environment allowlist and applies an explicit
overlay without recording the overlay values in progress events. It starts an
owned process group where the platform supports it, streams monotonically
sequenced stdout/stderr events, and terminates the owned process on timeout,
cancellation, or output-budget exhaustion.

Provider registration is lazy. Immutable adapter metadata may be discovered at
Workbench startup, but an implementation loader is called only when one of its
capabilities is resolved. The loaded adapter must match its registered
descriptor.

## Consequences

Positive:

- adapters and future raw CLI support share one process-lifecycle boundary;
- long-running tools can produce live progress without losing complete bounded
  stdout/stderr for later evidence capture;
- timeout, cancellation, output limits, launch failures, and non-zero exits
  remain explicit and cannot become success;
- optional providers do not become base-Workbench startup dependencies.

Negative:

- the first portable resource model bounds time and captured output but does not
  yet promise cross-platform CPU, memory, or network sandbox enforcement;
- the authorization record is a binding envelope, not the policy decision
  engine itself; M2 task #32 remains responsible for governed issuance;
- raw evidence persistence and hashing remain separate follow-up work.

## Non-goals

This ADR does not implement policy evaluation, credential resolution, an
evidence store, container/remote executors, provider installation, or an
unrestricted command shell.

## Invariant

> The executor may run only the exact authorized invocation inside its configured
> workspace and resource boundary; any mismatch or lifecycle failure remains a
> failure.
