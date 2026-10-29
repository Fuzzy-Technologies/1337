# Owned-loopback native content crawl

The development checkout provides Experimental `1337 scan crawl` and the
`PlanNativeCrawl` / `RunNativeCrawl` SDK. The packaged first-party worker reads
links from complete admitted responses, without a production body catalog.
It stores source observations and structural request templates. It creates no
security Finding and grants no permission to run a discovered check.

This guide describes the Experimental development interface. All 31 independent
owned-target worker/SDK/CLI cases have passed across focused verification runs,
including actual cancellation and relocated offline reopen. The exact final
shared integration gate and platform matrix remain required; this capability
has not been released. See the [contract](NATIVE_CONTENT_CRAWL_CONTRACT.md)
and [ADR0097](adr/0097-owned-loopback-content-crawl.md).

## Select current authority

Use an already owned listener and explicitly select its complete finite URL set.
At most sixteen canonical anonymous HTTP URLs at `127.0.0.1` or `[::1]` are
admitted. The seed and every selected URL must share one exact origin, including
the effective port. Ports use canonical decimal 1..65535. Use concrete ASCII
paths of at most 1024 characters without percent escapes or variables, no query or fragment,
and omit explicit default port `:80`. HTTPS, DNS, authentication, sessions,
custom headers, redirects and retries are outside this profile.

Supply selected URLs in distinct canonical lexical order, including the seed.
The seed is the sole initial request: selection alone does not schedule a page.
Only a link discovered from an admitted predecessor can schedule another selected
URL. Cycles and shared leaves are suppressed. Unselected or unsafe hrefs remain
count-only; their raw values are not retained.

From the development checkout, use `uv run --locked 1337` in place of `1337`
below. The immutable v0.2.1 installation baseline does not contain this workflow.
Choose actual consent validity timestamps in `CONSENT_FROM_UTC` and
`CONSENT_UNTIL_UTC`; both must be aware ISO-8601 values covering the intended work.
Register and allow every selected exact URL and the actual literal IP:

```bash
1337 workspace create owned-crawl --id owned-crawl --name "Owned content crawl"
1337 scope create owned-crawl --id owned-pages \
  --allow-url http://127.0.0.1:8080/index \
  --allow-url http://127.0.0.1:8080/leaf --allow-ip 127.0.0.1 \
  --grant-consent --owner attester:local-lab \
  --consent-reference consent:owned-listener \
  --valid-from "$CONSENT_FROM_UTC" --valid-until "$CONSENT_UNTIL_UTC"
```

Record only consent you actually hold. The scope's independent consent attester
is distinct from the executing `--owner operator:local-lab`. Neither reference
authenticates an external identity. Exclusion/deny rules take precedence; an
excluded or unregistered selected URL refuses the complete selection even when
that URL would be unreachable. Planning and discovery never expand scope.

Store this explicit current typed policy as `native-crawl-policy.json`:

```json
{
  "policy_id": "owned-native-crawl",
  "revision": 0,
  "maximum_impact": "SAFE",
  "permissions": [{
    "capability_id": "http.owned-loopback-crawl",
    "adapter_id": "native.crawl",
    "maximum_impact": "SAFE",
    "granted_privileges": []
  }],
  "max_authorization_seconds": 300
}
```

The file is reread at authority boundaries. Its permission and the independent
SAFE workflow approval are both required. A loopback address or discovered link
cannot replace either one. Current actor attribution, complete scope/consent and
source/IP permission are checked at planning, each grant, final launch and before
Save. Issued original grants are revalidated at launch and before persistence.

## Plan, approve and inspect

Planning performs no target request and issues no execution grant:

```bash
1337 scan crawl owned-crawl --scope owned-pages --owner operator:local-lab \
  --seed http://127.0.0.1:8080/index \
  --selected http://127.0.0.1:8080/index \
  --selected http://127.0.0.1:8080/leaf \
  --policy native-crawl-policy.json --plan
```

After inspecting that intent, select the same inputs with explicit approval:

```bash
1337 scan crawl owned-crawl --scope owned-pages --owner operator:local-lab \
  --seed http://127.0.0.1:8080/index \
  --selected http://127.0.0.1:8080/index \
  --selected http://127.0.0.1:8080/leaf \
  --policy native-crawl-policy.json --approve-safe-crawl --events-json
1337 workspace open owned-crawl --json
```

The foreground shell accepts the same explicit `scan crawl` arguments; its
selected object supplies no authority. `--json` selects one terminal summary;
`--events-json` emits actual safe job events followed by a summary. Choose one.
`--plan` rejects approval and event-stream combinations.

The SDK uses the same current owners and limits:

```python
from pathlib import Path

from fuzzy1337.native_crawl_workflow import PlanNativeCrawl, RunNativeCrawl
from fuzzy1337.nucleiscan import ReadNucleiPolicy
from fuzzy1337.policy import ImpactPolicy


def CurrentPolicy() -> ImpactPolicy:
    """Read the selected current strict policy without manufacturing permission."""

    return ReadNucleiPolicy(Path("native-crawl-policy.json"))


selected = (
    "http://127.0.0.1:8080/index",
    "http://127.0.0.1:8080/leaf",
)
plan = PlanNativeCrawl(Path("owned-crawl"), "owned-pages", selected[0], selected,
    "operator:local-lab", CurrentPolicy)


async def CaptureOwnedPages():
    """Invoke from an existing async owner after explicit review and approval."""

    return await RunNativeCrawl(Path("owned-crawl"), "owned-pages", selected[0], selected,
        "operator:local-lab", CurrentPolicy, approve_safe_crawl=True)
```

`ReadNucleiPolicy` is the existing strict `ImpactPolicy` file decoder also used by
the CLI. SDK callers may instead supply their own trusted synchronous typed
policy reader. Both SDK entry points accept optional
`current_owner_provider: Callable[[], str] | None`. A supplied trusted reader is
called afresh and must return the original selected owner exactly. Without it,
the selected owner is attribution only; external principal changes cannot be
detected. The consent attester is never substituted for the executing actor.

## Finite work and source facts

Pass `limits=NativeCrawlLimits(...)` from `fuzzy1337.native_crawl` in the SDK.
The CLI exposes the same limits:

| CLI flag                 | Default | Accepted range |
| ------------------------ | ------- | -------------- |
| `--max-pages`            | 16      | 1..16          |
| `--max-depth`            | 4       | 0..4           |
| `--concurrency`          | 2       | 1..4           |
| `--max-total-body-bytes` | 262144  | 1..1048576     |
| `--interval`             | 0.05 s  | 0.05..1 s      |
| `--timeout`              | 30 s    | 0.05..60 s     |
| `--max-body-bytes`       | 16384   | 1..65536       |
| `--request-timeout-ms`   | 3000    | 50..5000       |

Reserve a whole wave's worst-case body and page quotas before dispatch; unused
body reservations are not refunded. A bound that would omit reachable selected
work fails rather than returning a truncated completed frontier. One original
operation clock includes waits, acquisition, evidence, ordered commits and
cleanup. Cleanup is awaited after expiry; there is no real-time cleanup promise.

Each page makes one literal-loopback GET. Complete framing and timely EOF precede
report admission; HTTP 200 HTML also requires full bounded UTF-8 lexical admission.
Admitted HTTP 200 plain/octet-stream and 4xx responses are terminal source
observations with no link discovery. Unsupported media/status, redirects,
truncation, trailing bytes and invalid HTML are failed, unassessed work.

The model stores structural Endpoints/complete RequestTemplate collections and
immutable `web.owned-crawl-response` / `web.owned-crawl-link` Observations.
Original job, input/set digests, report/control IDs and occurrence ordinals bind
these facts. Original admitted stdout and empty stderr stay distinct from the
separately labeled parent control receipt. Bodies and arbitrary headers remain
transient; a body digest cannot reconstruct or independently replay extraction.

An operator may separately select a discovered endpoint for the
[native web check](NATIVE_WEB_CHECKS.md). Its STANDARD permission and exact-plan
confirmation remain independent. Crawl never launches it automatically, and
structural crawl Endpoint keys are not aliases for legacy exact-URL Git keys.

## Partial state, cancellation and verification

Pages commit in deterministic breadth/depth then lexical order, with an original
expected-revision model Save per page and at most one workspace Save attempt.
Unrelated attributes, complete request collections and operator triage are
preserved. Earlier commits and original acquisitions survive later failure.
Cancellation drains original tasks/workers, including repeated caller cancellation;
fresh authority and a final pure cancellation check precede each Save.

Inspect `completed_urls`, `model_saves`, `workspace_persistence_status`, actual
reopened revisions, `original_record_ids`, `acknowledged_record_ids` and
`custody_status`. A lost acknowledgement can report `observed-committed`,
`observed-unchanged` or `unconfirmed`; it does not trigger retry, rebase or rollback.
A late event or persistence failure can follow a real committed model transition.
Retained evidence without acknowledged workspace association does not become a
completed capture automatically. Exit codes are 0 completion, 2 invalid inputs,
3 current authority denial, 4 execution/storage failure and 130 cancellation.

Keep the canonical workspace and evidence together for relocated offline reopen.
`workspace open` contacts no target and starts no crawl worker; it verifies retained
state without recomputing extraction from absent bodies. There is no crawl resume
or target-contacting historical replay command.

Follow [ordinary pytest functional verification](FUNCTIONAL_TESTING.md). Existing
unit/mock checks and the [mutable graph source oracle](../tests/fixtures/native_crawl_graph/README.md)
do not establish installed execution acceptance. Required independent acceptance
must exercise actual seed-to-leaf SDK/CLI requests, fixed/decoy changes, scope
denial, original custody, partial/cancelled saves and relocated reopen before
claiming the runtime or platform matrix verified.
