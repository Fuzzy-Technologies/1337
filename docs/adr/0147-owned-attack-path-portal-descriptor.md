# ADR 0147: Evidence for the owned Portal role and advertised route

## Status

Accepted by the owner, 2026-11-09. Advances #118 under #115.

## Context

The attack-path-mini Portal currently serves `service.portal` and
`POST /session` as JSON at `GET /`. [ADR 0036](0036-bounded-native-http-discovery.md)
retains status and exact URL only. The existing original-content SDK requires
complete HTTP/1.1 200 plain text or HTML with `Connection: close`; the current
Portal returns HTTP/1.0 JSON. An availability observation, a digest without
verified bytes, or the scenario's `evidence.discovery` alias cannot substitute
for the Portal response.

## Decision

Add one fixed read-only descriptor to the repository-owned Portal fixture:
`GET /.well-known/attack-path-mini`. Keep the original JSON route unchanged.
Serve `HTTP/1.1 200 OK`, `Content-Type: text/plain; charset=utf-8`, the exact
`Content-Length`, and `Connection: close` with actual EOF. The complete ASCII
body has these two lines with LF after each, no CR, BOM or extra bytes:

```text
service_id=service.portal
route=POST /session
```

Rehearse on an explicitly selected literal loopback port using the existing
[`RunOwnedContentResponseCapture`](../OWNED_CONTENT_RESPONSE_CAPTURE_CONTRACT.md)
SDK. Register and allow the exact descriptor URL and literal IP under current
consent. The rehearsal must own the started Portal listener and select the URL
from that launch; a response cannot authenticate the process or make arbitrary
localhost services eligible. Require the existing SAFE capability permission,
execution approval and separate byte-retention opt-in. Use the existing
governed executor and custody. One anonymous GET, no caller headers or credentials,
no redirects, no route following, and no change to Compose networking or
default exposure. Admission of an internal container endpoint needs a separate
decision; the loopback rehearsal does not establish it.

After teardown, use `ReplayOwnedContentResponse` on the selected workspace and
original receipt ID. Require the durable job and exact selected source URL and
scope, all seven original role records, and the exact body bytes via the original
body acquisition. Check the source against the expected Portal descriptor URL,
even if another URL returned identical bytes. Report a read-only demo fact:
the Portal descriptor **advertised** `service.portal` and `POST /session`.
Carry the original receipt, job and body acquisition IDs with that fact. Keep
the captured GET Endpoint distinct from the untested advertised POST coordinate.
No product model write beyond the SDK's existing source observation is needed
for this first step; do not publish a new observation schema or CLI.

The scenario mapping to `service.portal` and `endpoint.portal-session` is
declared context. [ADR 0047](0047-attributed-offline-reachability-projections.md)
precludes a pivot inferred from this source. The descriptor proves neither that
the POST succeeds nor any identity, Finding, effective control or reachability
state. #120 owns governed validation and per-hop proof. Other services, durable
role/route projection and the complete #116 oracle remain separate work.

## Verification

- Positive: start the actual owned Portal with the descriptor enabled. Capture
  exactly one anonymous GET with the admitted wire and body above. After stopping
  the listener and moving the workspace, replay the same job and seven original
  role IDs and derive the same single advertised role/route from the verified body.
- Authority refusal: omit the capture approval, retention opt-in or exact URL/IP
  admission. Observe zero target requests and no original source.
- Source refusal: retain the real legacy JSON response as a transport control.
  The content capture refuses it, retaining only safe diagnostics. A complete
  plain-text body with `route=GET /session` instead of `route=POST /session`
  is capturable but cannot establish the proposed fact. A different URL,
  foreign receipt or corrupted original also cannot establish it. These are
  unassessed cases and create no Finding or reachability transition.

The [focused integration test](../../tests/integration/test_attack_path_portal_role_route_capture.py)
exercises the Portal descriptor and legacy JSON response through the existing
capture and replay SDK.
