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
