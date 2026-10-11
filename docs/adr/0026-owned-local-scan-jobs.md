# ADR 0026: Owned local scan jobs and ordered events

- Status: Accepted
- Related work: #39, #30

## Decision

Add an Experimental, schema-v1 `fuzzy1337.jobs` library. A `ScanJob` owns one
asynchronous provider task in one process and one event loop. `Start()` returns
without awaiting the provider: the queued snapshot and sequence-zero state event
are immediately available. Running and exactly one terminal state follow in
order. The terminal states are completed, failed and cancelled. A provider failure,
deadline or resource limit never becomes successful completion.

Immutable, contiguous events carry state, progress, heartbeat, normalized
observations, evidence attachments or existing Security Object Model deltas.
Consumers can replay from a sequence cursor or await new events without blocking
the producer. Consumer cancellation does not cancel the owned provider task.
Event history has an explicit bound; exhaustion fails the job while retaining
the prefix and a terminal event. Providers report progress and heartbeat where
available; the runner does not invent measured progress.

The handle is bound to an explicit owner reference. Cancellation from a different
owner is rejected. Queued cancellation prevents provider invocation. Running
cancellation first signals the provider and exposes a request event; the terminal
state is emitted only after its cleanup returns. `CancelAndWait()` can cancel the
owned task after a bounded cooperative grace period. Providers must cooperate
with task cancellation and reap resources before returning. Providers are trusted
first-party code, not a sandbox for hostile Python.

Jobs do not issue scope approval, pick targets, widen impact, apply model state,
or create a second evidence format. A local-process bridge accepts an already
bound `LocalExecutionRequest` and an execution callable. The callable may be
bound to the governed executor and its fresh policy context. It preserves stdout
and stderr in `LocalEvidenceStore` before reporting process failure or invoking a
normalization handler. Artifact attachments bind the immutable evidence record
to job, workspace and scope ownership; they do not authorize collection or claim
that a reference alone proves byte integrity. Already published attachments
survive failure and cancellation. Arbitrary exception messages are not copied
into events, avoiding accidental disclosure of provider arguments or credentials.

## Boundaries

This is an in-process lifecycle, not a durable queue, distributed scheduler,
restart recovery system, scanner command, or user interface. Lost process state
does not imply a successful job; durable evidence remains in its existing store.
Authenticated callers must resolve the requesting principal before invoking a
handle: an owner-reference string is not an authentication mechanism. Handler
code may publish only model deltas already accepted by the owning model boundary.

## Validation

Deterministic providers exercise all state transitions, monotonic progress,
cursor replay, bounded history, owner denial, cooperative and forced cancellation,
consumer detachment, deadlines, classified failures and retained evidence.
Integration tests use the actual local executor, evidence store and model contracts
with bounded synthetic local processes. They verify exact failure/cancellation
truth, evidence ownership and no provider launch after queued cancellation.
