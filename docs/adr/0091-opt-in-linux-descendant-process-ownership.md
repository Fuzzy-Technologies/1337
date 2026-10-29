# ADR 0091: Opt-in Linux descendant process ownership

- Status: Accepted for implementation
- Date: 2026-10-23
- Related work: #59, #53

## Context

Optional browser providers can start detached descendants outside the current
executor's original process group. Observing the direct worker's exit does not
prove those descendants exited. A bounded owner is required before the proposed
offline browser backend can claim completed cancellation or timeout cleanup.

## Decision

Add keyword `own_descendants: bool = False` to local and governed execution.
The existing request dataclasses, serialization, approved invocation, default
argv/environment path and terminal result contracts remain unchanged. Opt-in
is available only on Linux and refuses unsupported platforms before launch.
The executor first opens only its own main-thread kernel child interface and
refuses an unavailable interface before launching the supervisor or worker.
The supervisor independently reads its own fresh empty child list before launch.
It strengthens resource ownership and grants no additional execution authority.

Launch one installed `python -I` supervisor in the executor's existing owned
session. The supervisor alone enables Linux child-subreaper behavior and a
parent-death termination signal, checking the parent-identity setup race.
The approved worker starts in a separate session. Never change the workbench's
subreaper state or inspect a global process table.

Pass the original approved argv and existing worker environment through a
bounded sealed anonymous memfd. The supervisor starts with a separately
sanitized environment; untrusted worker environment overrides cannot alter
the trusted helper's Python loader. A private bounded pipe carries a strict
versioned receipt binding the configuration digest, original signed-integer
worker return code and cleanup result. The worker does not inherit either
control descriptor. A separate private readiness pipe confirms completed
supervisor setup. The parent consumes its fixed byte, repeats the synchronous
current-authority check, and writes the worker-start gate without an intervening
await. Closing the gate before acknowledgement proves an unstarted worker;
an acknowledgement lost after delivery requires actual worker cleanup instead.
Cancellation during readiness cannot consume or corrupt receipt framing.
The receipt is an OS-owned control channel, not a
cryptographic attestation or a security sandbox.

Forward original stdout/stderr directly and preserve their byte and quota
semantics. `STARTED` records supervisor ownership, before the worker may finish
starting. No result is complete until the supervisor exits and its exact receipt
is verified. A known worker spawn failure is an executor launch error; a real
worker's nonzero or negative signal return code remains its actual result.

## Bounded cleanup

The supervisor is single-threaded and the sole reaper of its children. On worker
exit or termination it reaps exited children, reads only its fresh kernel-owned
direct-child list, then kills still-unreaped direct or adopted descendants.
It never reaps between reading that list and signaling it, so listed child PIDs
remain reserved against reuse. Detached grandchildren become visible through
subreaper adoption and are handled in subsequent waves.

Cleanup has a two-second deadline and a 128-process/reap bound. Success requires
both `ECHILD` and an empty fresh child list. Kernel/ownership errors, exceeded
bounds or incomplete cleanup produce failure, never guessed success. Opt-in
parent grace is at least three seconds, leaving the existing default unchanged.
Every abort path, including observer exceptions and caller cancellation, must
verify the receipt before propagating normal completion/cancellation semantics.

An absent/malformed receipt, forced supervisor kill or inconsistent exit status
raises `LocalExecutionError` with unknown cleanup. A worker or supervisor killed
by an uncatchable signal, parent/kernel death, or same-UID interference cannot be
contained absolutely by this mechanism. It is intended for trusted approved
providers; failure remains explicit rather than claiming universal OS isolation.
Windows Job Objects and other platform implementations require separate work.

## Acceptance

Use only pytest-owned Python fixtures and exact recorded process identities.
Verify fork/double-fork/setsid descendants on normal exit, cancellation, timeout,
output overflow, observer abort and caller cancellation. Confirm every owned
descendant has exited within the bound. Verify original output/environment/argv
and signed return codes, spawn/configuration/receipt failures, descriptor cleanup,
unsupported-platform refusal and unchanged default execution/serialization.
No network, browser download or security target is needed for this foundation.
Run focused tests during implementation and the shared full gate only at final
PR integration readiness.
