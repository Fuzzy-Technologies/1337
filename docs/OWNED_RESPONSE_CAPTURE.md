# Experimental original-response capture

The `response` commands preserve one approved original HTTP request and response
as source evidence. They do not produce a security assessment. A later offline
engine can consume those originals through a separately approved workflow.

Live capture currently requires Linux and an explicitly selected owned listener.
The first profile supports only anonymous HTTP at `127.0.0.1` or `[::1]`, an
explicit port from 1024 through 65535, and these reviewed paths:

- `/zap-passive/missing`
- `/zap-passive/fixed`
- `/zap-passive/body-decoy`

The listener must return the exact corresponding non-secret response in the
[versioned catalog](../tests/contract/fixtures/zap-passive.oracle.v1.json).
Caller headers, cookies, authentication, DNS, query strings, redirects and retries
are outside this profile. A differing response is refused without retaining its
bytes or hashes. Existing page-capture and web-check workflows keep their own
contracts.

## Plan and capture

Select an existing workspace, current source scope/consent and explicit SAFE
permission for `native.loopback-response` / `http.synthetic-response-capture`.
The policy file supplies permission; the execution approval flag supplies the
separate workflow approval. The selected owner is an explicit operator actor
reference, independent of the scope consent attester.

Planning makes no target request:

```bash
1337 response capture workspace --target http://127.0.0.1:8080/zap-passive/missing \
  --scope owned-response-scope --owner operator --policy response-policy.json --plan
```

Execute the same selected profile with explicit approval:

```bash
1337 response capture workspace --target http://127.0.0.1:8080/zap-passive/missing \
  --scope owned-response-scope --owner operator --policy response-policy.json \
  --approve-safe-response-capture
```

The capture makes one GET and preserves its original request, full admitted
headers/body, worker record, empty stderr and execution receipt. The model stores
a stable Endpoint and a receipt-bound source Observation. Repeated captures keep
their original job and evidence associations; unrelated objects and operator
triage are preserved.

The summary reports actual original references and persistence status. A later
failure can follow a real model or workspace write; observed committed state is
reported without a retry or rollback claim. Approved private staging remains
retained in this initial profile, including after successful persistence.

## Replay retained originals

Use the original receipt ID returned by capture:

```bash
1337 response replay relocated-workspace --receipt sha256:ORIGINAL_RECEIPT_DIGEST
```

Replay verifies original manifests, bytes, receipt and the persisted source
association. It contacts no listener, launches no capture worker and writes no
model, workspace or replacement evidence. The original listener, selected runtime
and current scope/policy inputs are unnecessary. Copy the retained workspace and
canonical evidence together when relocating it; an unavailable or uncommitted
source/job association remains unknown rather than being invented.

The SDK exposes `PlanOwnedResponseCapture`, `RunOwnedResponseCapture` and
`ReplayOwnedResponse`. A trusted `current_owner_provider` can refresh actor
attribution at live authority boundaries. Replay takes no current execution
permission. See the [technical contract](OWNED_RESPONSE_CAPTURE_CONTRACT.md) for
record, custody and failure semantics, and [ADR 0095](adr/0095-owned-response-zap-passive-profile.md)
for the separate proposed ZAP analysis boundary.
