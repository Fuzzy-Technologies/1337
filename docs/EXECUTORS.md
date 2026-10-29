# Executor SDK

## Status

The `fuzzy1337.executors` Python surface is **Experimental** and versioned by
`EXECUTOR_CONTRACT_VERSION`. Its architecture is defined by
[ADR 0015](adr/0015-governed-local-executor-boundary.md).

## Boundary

The first executor composes with the ToolAdapter SDK without granting authority:

```text
Scope/Policy decision
        ↓
ExecutionAuthorization + CapabilityDescriptor
        ↓
AdapterInvocation
        ↓
LocalExecutor
        ↓
LocalExecutionResult + ordered events
        ↓
future Evidence capture and adapter normalization
```

`ExecutionAuthorization` binds scope and policy references to the SHA-256 digest
of one exact invocation. Task #32 owns the future policy decision that issues
this record; constructing an adapter invocation or advertising a capability is
never sufficient authorization.

## Local execution contract

`LocalExecutor` provides these guarantees:

- argument-array execution without shell interpolation;
- a resolved working directory below one configured workspace root;
- a small inherited platform environment plus an explicit overlay;
- positive timeout, stdout/stderr byte budgets, and termination grace;
- owned-process termination on timeout, cancellation, and output exhaustion;
- monotonically sequenced `started`, `stdout`, `stderr`, and `completed` events;
- a complete bounded byte representation of stdout and stderr;
- non-zero exit, timeout, cancellation, output-limit, and launch-error truth.

An output-limit stop is represented as cancelled execution with the more precise
`OUTPUT_LIMIT` termination reason. It is never reported as successful merely
because a process raced to exit.

Lifecycle observers run in event order without overlapping awaitable callbacks.
If an observer raises or the execution coroutine is cancelled, the executor
terminates and reaps its owned child, cancels and awaits its background tasks,
and then propagates the original failure. This includes the initial `started`
handoff. Cleanup drains captured pipes in bounded chunks without calling the
failed observer or retaining additional output. Repeated cancellation does not
abandon process reaping.

Task #273 covers process-exit races during both TERM and KILL cleanup. A POSIX
`EPERM` can be recovered only after a bounded wait observes the owned child's
exit and a non-mutating group-existence check proves that its group disappeared.
A live child, a remaining or inaccessible group, and other signaling errors
remain explicit `LocalExecutionError` failures. The executor never sends another
mutating signal after observing child exit. Owned exit waits and pipe draining
after a failed observer are bounded by the configured termination grace rather
than waiting indefinitely. Normal awaitable-observer execution retains the
responsiveness contract below.

Recovered races preserve the actual output-limit, timeout, or cancellation
result and captured evidence. Unrecoverable cleanup cannot claim that every
resource was reaped: it is a provider failure, not a new authorization denial or
successful execution. `LocalExecutionJob` uses the sanitized message
`The approved local execution could not complete` for `LocalExecutionError`;
the pre-launch policy denial boundary remains separate.

Awaitable observers must remain responsive. The process-wait timeout does not
bound observer execution; a caller may cancel the execution coroutine while an
observer is suspended. Observer failures return no successful execution result.

## Optional Linux descendant ownership

`LocalExecutor.Execute` and `GovernedLocalExecutor.Execute` accept the explicit
keyword `own_descendants=True` under
[ADR 0091](adr/0091-opt-in-linux-descendant-process-ownership.md). The default is
`False`. Request serialization, approved invocation metadata and result fields
retain their existing contract. Unsupported platforms reject the opt-in before
launching the approved worker.
The kernel must expose the supervisor's direct-child list through procfs and
support sealed anonymous configuration. Missing primitives fail before worker
launch. Required Linux integration CI sets
`FUZZY1337_RUN_DESCENDANT_ACCEPTANCE=1`: unavailable capabilities fail the actual
detached-process tests there. An unsupported local environment can explicitly
skip those positive cases and supplies no acceptance evidence.

The Linux implementation starts an installed isolated supervisor that owns and
reaps detached descendants as a child subreaper. Only that dedicated process
changes its subreaper state. It reads its own kernel child list, never a global
process table. The approved worker receives its original argv and environment;
stdout and stderr remain the original bounded byte streams. Private sealed
configuration and receipt descriptors are not inherited by the worker.
The helper first proves its setup and reports readiness through a separate
private one-byte pipe. The parent then repeats the synchronous launch-policy
check immediately before acknowledging the worker start, with no intervening
await. Denied or interrupted handoffs require verified unstarted cleanup;
abort after a delivered acknowledgement actively stops the known helper and
verifies the actual started or unstarted outcome.

Normal worker exit, timeout, output exhaustion, cooperative cancellation,
observer failure and caller cancellation all require verified descendant cleanup
before returning or propagating the original outcome. Cleanup is bounded at two
seconds and 128 processes/reaps; the parent uses at least three seconds of
termination grace for this opt-in. The `started` event records supervisor
ownership and can precede actual worker startup. A worker spawn failure raises
`LocalExecutionError`, while an actual worker's nonzero or negative signal exit
code remains its own exit status.

A missing or inconsistent receipt, failed cleanup or forced supervisor kill
raises `LocalExecutionError`. It cannot establish a completed cancellation or
successful result. The receipt is a private OS-owned control channel, without
cryptographic attestation. This mechanism supports trusted approved providers;
it provides no same-UID containment, network/filesystem sandbox or universal
guarantee after uncatchable owner termination or kernel failure. Windows and
other platform implementations remain separate work.

## Capability discovery

`LazyAdapterRegistry` accepts immutable `AdapterDescriptor` metadata and a
loader. Listing capabilities does not load an adapter. Resolution loads the
selected provider once and rejects implementations whose runtime protocol or
descriptor differs from the registration.

This keeps optional scanners, browsers, private providers, and large tool packs
out of the base Workbench startup path.

## Example

```python
from pathlib import Path

from fuzzy1337.executors import LocalExecutor

executor = LocalExecutor(Path("workspace"))
result = await executor.Execute(request, on_event=publish_progress)
```

The example assumes `request` already contains a prepared invocation and an
authorization record issued by the governing layer. The executor does not
invent scope, policy, credentials, or privileges.

## Current resource limits

The portable v1 contract enforces elapsed time, captured stdout/stderr size, and
workspace containment. OS-specific CPU, memory, filesystem, and network sandbox
providers may extend this boundary later without making them startup
dependencies of the local-first Core.
