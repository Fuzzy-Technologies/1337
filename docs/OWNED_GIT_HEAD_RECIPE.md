# Find one real issue with the installed core

This recipe uses the accepted first-party `git-head-exposure` check. It produces
one LOW-severity Git metadata exposure Finding, verifies a fixed negative control,
then reopens and reports the saved state offline. Only installed 1337 and CPython
3.11+ are needed at runtime. No scanner download, model API, container, browser,
pytest or source checkout is required to run the copied example.

Use the [version-specific installation](QUICKSTART.md#install-a-reviewed-wheel)
and activate its environment first. This is 0.3.0 candidate documentation; the
immutable v0.2.1 release lacks this command. Retain the actual installed version
and source revision. A candidate rehearsal does not establish final PyPI delivery.

## Start the owned fixture

Save the following complete script as `owned_git_head_demo.py` in a new working
directory. The same [standalone script](examples/owned_git_head_demo.py) is provided
for download. It serves constant synthetic bytes, reads no files and binds only
to `127.0.0.1`. There is no real Git repository or secret in the fixture.

```python
# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Serve two fixed nonsecret loopback responses; never read files or contact another service."""

from __future__ import annotations

import argparse
import json
import socket
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import cast


class OwnedServer(HTTPServer):
    """Own one bounded local listener and a two-request synthetic receipt."""

    def __init__(self, port: int) -> None:
        """Bind only IPv4 loopback, using zero for an operating-system-selected test port."""

        super().__init__(("127.0.0.1", port), OwnedHandler)
        self.timeout = 0.25
        self.requests: list[str] = []

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        """Bound an accepted client's headers so partial requests cannot hold the fixture open."""

        connection, address = super().get_request()
        connection.settimeout(2)
        return connection, address


class OwnedHandler(BaseHTTPRequestHandler):
    """Return only one inert Git HEAD canary and one fixed denial."""

    def do_GET(self) -> None:
        """Respond from constants, with no disk access, redirects, authentication or cookies."""

        exposed = self.path == "/.git/HEAD"
        label = "exposed" if exposed else "fixed" if self.path == "/fixed/.git/HEAD" else "other"
        cast(OwnedServer, self.server).requests.append(label)
        body = b"ref: refs/heads/main\n" if exposed else b"Not Found\n"
        self.send_response(200 if exposed else 404)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, format: str, *args: object) -> None:
        """Keep arbitrary request values out of logs; only fixed receipt labels are reported."""


def Main() -> int:
    """Stop after two requests, ten minutes or Ctrl+C and report the actual owned teardown."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--seconds", type=int, default=600)
    options = parser.parse_args()

    if options.port != 0 and not 1024 <= options.port <= 65535 or not 1 <= options.seconds <= 600:
        parser.error("select port 0 or 1024..65535, and seconds 1..600")

    server = OwnedServer(options.port)
    host, port = server.server_address
    print(json.dumps({"schema_version": 1, "state": "serving", "host": host, "port": port,
        "exposed_url": f"http://{host}:{port}/.git/HEAD",
        "fixed_url": f"http://{host}:{port}/fixed/.git/HEAD", "max_requests": 2}), flush=True)
    deadline = time.monotonic() + options.seconds

    try:
        while len(server.requests) < 2 and time.monotonic() < deadline:
            server.handle_request()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

    print(json.dumps({"schema_version": 1, "state": "stopped", "requests": server.requests,
                      "listener_closed": True}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
```

In terminal 1, run:

```bash
python owned_git_head_demo.py --port 8765
```

The first JSON line reports the two exact URLs and `state: serving`. If port 8765
is occupied, choose another explicit unprivileged port and substitute its actual
value in both URLs below before creating scope or planning. The fixture closes
its listener after two requests, ten minutes or Ctrl+C. Keep that terminal open;
planning and denied execution must not consume either request.

## Create the workspace, consent and policy

In terminal 2, using the same activated environment:

```bash
1337 --version
mkdir git-head-demo
1337 workspace create git-head-demo/workspace --id owned-git-head --name "Owned Git HEAD example" --json
HEAD_FROM=$(python -c 'from datetime import UTC,datetime; print(datetime.now(UTC).isoformat())')
HEAD_UNTIL=$(python -c 'from datetime import UTC,datetime,timedelta; print((datetime.now(UTC)+timedelta(minutes=10)).isoformat())')
1337 scope create git-head-demo/workspace --id local \
  --allow-url http://127.0.0.1:8765/.git/HEAD \
  --allow-url http://127.0.0.1:8765/fixed/.git/HEAD --allow-ip 127.0.0.1 \
  --grant-consent --owner operator:owned-git-head \
  --consent-reference consent:owned-git-head-example \
  --valid-from "$HEAD_FROM" --valid-until "$HEAD_UNTIL" --json
```

The commands above use Bash variable assignment. In PowerShell, obtain the same
bounds with `$HEAD_FROM = (Get-Date).ToUniversalTime().ToString("o")` and
`$HEAD_UNTIL = (Get-Date).ToUniversalTime().AddMinutes(10).ToString("o")`, and enter
the continued commands as single lines. Workspace and scope creation return 0.
Scope records your authority for only the two selected URLs and their actual IP;
registration, consent and policy remain separate requirements.

Save this exact JSON as `git-head-demo/policy.json`:

```json
{
  "policy_id": "owned-git-head-example",
  "revision": 0,
  "maximum_impact": "STANDARD",
  "permissions": [{
    "capability_id": "web.git-head-check",
    "adapter_id": "native.web-check",
    "maximum_impact": "STANDARD",
    "granted_privileges": []
  }],
  "max_authorization_seconds": 300
}
```

This policy permits only the selected capability at STANDARD impact. It does not
confirm a particular invocation. The check makes one GET, with a two-second
request timeout and ten-second job deadline. It follows no redirect and performs
no URL expansion, repository download or additional scan.

## Inspect and approve the exact exposed-endpoint plan

```bash
1337 scan web git-head-demo/workspace --check git-head-exposure \
  --scope local --owner operator:owned-git-head \
  --target http://127.0.0.1:8765/.git/HEAD --policy git-head-demo/policy.json \
  --request-timeout 2 --timeout 10 --plan --json
```

Expected: exit 0 with a read-only plan, including
`policy_plan.intent_sha256`. Review the selected URL, impact and limits. Planning
must not contact the target. An unchanged command without either `--plan` or
confirmation returns 3 before contact; it grants no execution permission.

After you explicitly approve this actual plan, copy its real digest into the
command below in place of `EXPOSED_INTENT_SHA256`:

```bash
1337 scan web git-head-demo/workspace --check git-head-exposure \
  --scope local --owner operator:owned-git-head \
  --target http://127.0.0.1:8765/.git/HEAD --policy git-head-demo/policy.json \
  --request-timeout 2 --timeout 10 --confirm-plan EXPOSED_INTENT_SHA256 \
  --confirmation-reference approval:owned-git-head-exposed --json
```

Expected: exit 0, `state: completed`, `object_counts.finding: 1`. The saved Finding
has check ID `native.git-head-exposure`, severity `low` and disposition `open`.
Its evidence attributes a complete HTTP 200 plain-text response to the approved
endpoint. This is metadata exposure; it does not establish source recovery,
credential exposure or exploitability. The nonsecret fixture response is exactly
`ref: refs/heads/main` followed by a newline.

## Check the fixed control with its own approval

The different URL needs a fresh plan and explicit approval; never reuse the
exposed URL's digest:

```bash
1337 scan web git-head-demo/workspace --check git-head-exposure \
  --scope local --owner operator:owned-git-head \
  --target http://127.0.0.1:8765/fixed/.git/HEAD --policy git-head-demo/policy.json \
  --request-timeout 2 --timeout 10 --plan --json
```

Review and approve that plan, then substitute its real digest below:

```bash
1337 scan web git-head-demo/workspace --check git-head-exposure \
  --scope local --owner operator:owned-git-head \
  --target http://127.0.0.1:8765/fixed/.git/HEAD --policy git-head-demo/policy.json \
  --request-timeout 2 --timeout 10 --confirm-plan FIXED_INTENT_SHA256 \
  --confirmation-reference approval:owned-git-head-fixed --json
```

Expected: exit 0 and `state: completed`. The control returns a complete HTTP 404
and adds no Finding. The same workspace still contains the original one Finding;
checking a different fixed endpoint does not resolve or delete the exposed
endpoint's finding. Terminal 1 now reports `state: stopped`,
`requests: ["exposed", "fixed"]` and `listener_closed: true`.

## Reopen and export after the fixture stops

```bash
1337 workspace open git-head-demo/workspace --json
1337 report export git-head-demo/workspace --format json --output git-head-demo/model.json --json
1337 report export git-head-demo/workspace --format html --output git-head-demo/model.html --json
1337 report export git-head-demo/workspace --format sarif --output git-head-demo/model.sarif --json
```

Each returns 0; reopen verifies the retained evidence and reports one Finding.
Export receipts acknowledge `output_published: true` and share the exact reopened
model revision/snapshot digest. Open `git-head-demo/model.html` to inspect the
Finding, selected endpoint and evidence references. The JSON and SARIF retain
the same Finding with `scan_completeness: not-assessed`. A single positive and
negative check do not establish general scanner coverage or a clean target.

Keep the complete workspace and reports together. The check retains the original
bounded execution report and streams, including response digest/length and
predicate outcome; it does not retain the HTTP response body or Git reference
text. Offline verification establishes retained evidence integrity, not a second
assessment of a body that was deliberately not saved.

On refusal or failure, retain actual partial state and exit status. Configuration
2, authorization 3, execution/evidence/storage 4 and cancellation 130 are distinct
from completed assessment 0. Never broaden scope, reuse a changed plan, overwrite
reports or delete evidence to make a rerun pass. Existing workspaces and report
filenames are refused; choose fresh owned output for another approved rehearsal.
See [native web checks](NATIVE_WEB_CHECKS.md) and [report export](REPORT_EXPORT.md)
for the owning contracts.
