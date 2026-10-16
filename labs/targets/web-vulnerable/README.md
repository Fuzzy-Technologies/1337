# Owned web vulnerability target

This first-party target pack executes three small real mechanisms against
non-secret data owned by each test. It is separate from `web-micro`, whose
command, inclusion, SSRF and upload markers remain simulations.

`oracle.v1.json` is a handwritten, versioned source of expected target behavior
and detector matches. The server does not read the oracle. Target-only passing
tests establish the target mechanisms and controls; they do **not** establish
scanner detection, accuracy or confirmed exploitability. A provider consumer
must independently preserve its raw evidence and compare actual detections with
the oracle. Unsupported or unexecuted provider cases are not true negatives.

## Mechanisms and controls

- Git exposure reads `public/.git/HEAD` from the helper-owned temporary tree.
  The fixed route denies access before reading; the decoy serves an HTML example
  containing a plausible HEAD line without reading the file. The redirect case
  returns a relative location pointing to the exposed route. A no-follow
  consumer must record only the redirect request and zero file reads. This is
  a Git detection negative control, not an open-redirect claim.
- SQLite uses a fresh in-memory database with two synthetic rows. A baseline,
  true Boolean input and false Boolean input execute an interpolated SELECT.
  Only the true input discloses `owned-private-row`. The fixed route binds that
  same input as a parameter; the decoy performs the safe query and mentions the
  canary only in a documentation field. All queries run after `query_only` and
  an authorizer restrict access to SELECT/READ of the owned table; a progress
  handler also bounds virtual-machine work. No filesystem database, extension,
  attachment, general SQL input or external destination is accepted. A single
  response match means **owned SQL canary disclosure**; the finite baseline,
  true, false, fixed and decoy cases establish the differential target behavior.
- HTML reflection inserts one harmless custom element into an HTML main
  element. The fixed route HTML-escapes the same input; the decoy places it in
  a comment. This is an **unsafe HTML reflection candidate**, not a browser
  execution or confirmed XSS result. Attribute, script, DOM, stored and browser
  execution contexts are not assessed.

The finite input is explicitly supplied in the URL path. SQL apostrophes and
markup are percent-encoded; the closing HTML tag keeps an ordinary path slash.
The four SQL payload routes explicitly select literal `=` as their sole spelling.
The prior `%3D` spelling is rejected with 404 before SQL execution; there are no
accepted aliases. This fixture selection follows observed provider wire behavior
and does not authorize rewriting an earlier approved target URL.
The existing product URL/scope rules accept these paths unchanged. Queries,
fragments, encoded path separators, traversal, alternate payloads, credentials
and arbitrary route input are not added to the provider contract. There is no
traversal, SSRF, shell, command execution or file upload mechanism in this pack.

## Lifecycle and observations

`tests/web_vulnerability_helpers.py` exposes:

```python
with OwnedWebVulnerabilityTarget(tmp_path / "target") as target:
    url = target.Url("sql-true")  # Also accepts an exact Oracle()["cases"] record.
    owned_root = target.root
    observed = target.Observe()
```

The helper creates an ephemeral child under the supplied parent, writes only
synthetic canaries, binds `127.0.0.1` on an ephemeral port and starts one owned
non-daemon service thread. It signals readiness without a hidden HTTP probe.
It closes accepted sockets before stopping and joining the service, including
when input is an incomplete header or the test body fails. Temporary files are
removed on exit. It supports context-managed local testing, not public hosting.
Incomplete-header tests retain the existing two-second socket read deadline and
three-second thread join, exercising both shutdown and actual deadline fallback.

`Observe()` returns copied `requests`, `file_reads`, `queries`, `reflections` and
`errors` lists. File-read records contain the owned relative path and actual
content SHA-256; queries contain the executed input, parameterization choice and
actual selected rows; reflections contain the input and insertion context.
These are target-side facts, separate from scanner evidence. Unknown routes and
requests with credential/body headers are rejected with a fixed redacted request
record; incidental access/error logging is disabled. The server has no outbound
HTTP behavior and never consults the checkout's own Git metadata.

## Focused verification

```bash
uv run --locked --extra dev pytest --no-cov -n 2 \
  tests/contract/test_web_vulnerability_contract.py \
  tests/integration/test_web_vulnerability_target.py
```

The contract suite checks the independent oracle and existing URL boundary. The
integration suite uses actual loopback HTTP, verifies file changes affect the
response, reads independent SQLite/HTML facts, exercises rejection/failure paths,
and proves deterministic cleanup. These checks require no external scanner,
browser, container, Internet target or third-party service.
