# Local scan job lifecycle

`fuzzy1337.jobs` is an Experimental schema-v1 library for the Quick Scan and
future workflow orchestration layer. A job owns one trusted asynchronous provider
task, ordered notifications and artifact attachments. It adds no scanner command
or authorization grant. See [ADR 0026](adr/0026-owned-local-scan-jobs.md).

## Start and follow a job

Create a `JobSpec` with unique job ID, workspace, scope, authenticated owner,
provider ID and finite deadline. Bind a provider implementing
`async Run(context: JobContext) -> None`, then call `ScanJob.Start()` from an
asyncio loop. `Snapshot()` and `EventsSince()` immediately expose queued status;
the provider runs on a later loop turn. The provider's running state appears
before any provider work.

`Events(sequence=-1)` replays retained notifications and follows new ones through
the terminal event. `EventsSince(sequence)` returns an immutable replay snapshot.
A sequence is the last observed cursor, so reconnection starts strictly after it.
Multiple readers do not consume one another's events. Cancelling a waiting client
or event subscriber detaches that client and leaves the job running. All mutation,
waiting and live subscription belongs to the same event loop. Polling snapshots
does not execute provider code.

Events serialize through the existing `adapters.SerializeContract` boundary:
`schema_version`, `job_id`, `sequence`, `kind`, `data`. Sequence numbers begin at
zero and remain contiguous. The discriminator selects typed immutable payloads:
state, measured progress, heartbeat, cancellation request, normalized observation,
evidence attachment, existing `ModelDelta` or classified failure. Raw stdout,
stderr, argv and environment values are not event payloads. Providers must avoid
secrets in deliberately supplied observations and safe error messages.

## Progress, failure and cancellation

The state chain is queued → running → completed/failed/cancelled. Queued owner
cancellation goes directly to cancelled without invoking the provider. Progress
uses monotonic completed-unit counts and an optional fixed total. Heartbeat means
provider liveness, not successful discovery or measured completion. The runner
does not invent heartbeat or a percentage for silent tools.

`Cancel(requested_by)` requires the resolved owner principal. Authentication and
scope approval are upstream responsibilities. Running cancellation emits an
immediate request event and sets `context.Cancellation`; the job remains running
until the provider reaps its resources. `CancelAndWait()` adds a finite grace
period before cancelling the owned task, then awaits cleanup. Trusted providers
must honor asyncio cancellation; arbitrary hostile Python cannot be contained by
this library. `Wait()` returns a terminal snapshot, including partial artifacts
and a failure classification when applicable.

Failed jobs distinguish authorization, provider, normalization, storage, timeout,
output-limit and internal failures. Providers use `JobError(JobFailure(...))` for
deliberate non-secret errors. Unexpected exception text is replaced by a generic
internal failure. Job deadlines and event history are bounded; history exhaustion
retains the event prefix plus failure/terminal notifications, never success.

## Reuse the governed executor and evidence/model contracts

`LocalExecutionJob(request, execute, result_handler=None)` runs one already bound
`LocalExecutionRequest`. Its scope and provider must match the job. The callable
can be an existing `LocalExecutor.Execute`, or a `functools.partial` binding the
governed executor's grant and fresh-context arguments. Production orchestration
must obtain the policy grant upstream; creating a `JobSpec` never approves a scan.

Bind an existing `LocalEvidenceStore` to the job. The local bridge captures bounded
stdout and stderr there, including failed/timed-out/cooperatively cancelled
process outcomes, before reporting terminal process failure. Successful execution
may call an asynchronous result handler with the existing `AdapterReport`.
Normalize raw evidence, apply updates through the owning model boundary, and
publish its returned delta with `context.ModelChanged(delta)`. The job does not
apply or duplicate model state.

`context.CaptureEvidence()` validates workspace/scope/provider attribution,
publishes through the existing evidence store, and returns a job-owned immutable
attachment. Exact attachment replay is idempotent. Published attachments survive
later failures, including normalization failure. Cancellation cleanup may capture
evidence before terminal sealing. A hard task cancellation or job deadline can
interrupt a provider before it returns final captured streams; only records
already published are guaranteed to remain. The local executor still reaps its
owned subprocess before task cancellation propagates.

Job state/event history is in memory. Process restart recovery, persistent queues,
distributed scheduling and unbounded event retention are outside this contract.
Durable evidence remains independently reopenable through its existing store.
