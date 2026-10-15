# Owned web file-access target

This first-party pack exercises actual path traversal inside a temporary,
test-owned filesystem. It advances the synthetic-target work in #59 using the
explicit QUERY coordinate already represented by #58. It does not implement a
scanner, broaden a provider execution profile or establish detector accuracy.

## Contract and mechanism

The helper creates `public/hello.txt` and `private/canary.txt` below its own
temporary root. Neither file contains real credentials or host data. The six
reviewed HTTP GET cases are handwritten in `oracle.v1.json`; the server does
not read that oracle or use expected matches to choose response bodies.

| Case                | Mechanism                                                    | Expected result                  |
| ------------------- | ------------------------------------------------------------ | -------------------------------- |
| Public baseline     | Vulnerable join reads `public/hello.txt`                     | Public bytes, 200                |
| Private traversal   | `public` joined with `../private/canary.txt` reads a sibling | Actual private canary bytes, 200 |
| Fixed traversal     | Public-subtree containment rejects the same input before IO  | Denial, 403                      |
| Fixed public        | Contained join reads the legitimate public file              | Public bytes, 200                |
| Missing control     | Declared `private/missing.txt` is absent from the owned tree | Actual missing-file result, 404  |
| Documentation decoy | JSON mentions the canary without reading any file            | Documentation only, 200          |

The vulnerable variant intentionally lacks the public-subtree check. A separate
fixture boundary still restricts every accepted input and actual read to the
finite owned root. The fixed variant applies public containment before filesystem
inspection. File reads retain the actual relative path, input, byte count and
SHA-256; changing the owned file changes the response. Creating the declared
missing control file changes its response as well. These checks establish real
filesystem behavior rather than preselected success markers.

Queries remain explicit, for example:

```text
/files/vulnerable?name=..%2Fprivate%2Fcanary.txt
```

The current Nuclei `single-get-exact-url` profile rejects query-bearing URLs.
Contract tests preserve that refusal. This pack adds no alternate encoding,
transport bypass, scope exception or execution grant to make a scanner accept
the input. Future scanner acceptance needs a separately reviewed governed query
request path and actual provider evidence. Structural `RequestTemplate` and
`InjectionPoint` support alone is not execution permission.

## Bounds and observations

Only the six exact raw request targets are accepted. Unknown spellings,
additional/repeated parameters, alternate encodings, absolute paths, traversal
beyond the owned fixture, credential headers and request bodies are rejected
before decoding or inspecting the filesystem. Unknown request values are
represented only by a fixed redacted observation. The server emits no incidental
access or error logs.

The accepted file inputs are finite. Symbolic links, nonregular files and files
exceeding 256 bytes are rejected before opening content; an additional bounded
read rejects unexpected growth. Every candidate remains within the helper-owned
root. This is a test fixture whose filesystem is owned by the test, not a general file server
or a defense against a concurrent hostile local filesystem administrator.

`tests/web_file_access_helpers.py` supplies an ephemeral literal-loopback listener,
one non-daemon thread, temporary files and detached target observations:

```python
with OwnedWebFileAccessTarget(tmp_path) as target:
    url = target.Url("private-traversal")
    observed = target.Observe()
```

Readiness performs no hidden HTTP request. Cleanup stops new dispatch, interrupts
accepted sockets, closes the listener and joins the thread before removing the
owned tree. Actual incomplete-header, test-body and service-loop failure cases
exercise that lifecycle. No outbound request, command execution, arbitrary file
selection or public hosting entry point is provided.

## Focused verification

```bash
uv run --locked --extra dev pytest --no-cov -n 2 \
  tests/contract/test_web_file_access_contract.py \
  tests/integration/test_web_file_access_target.py
```

Target-only passing tests establish the finite mechanisms and negative controls.
They provide no scanner TP/FP/FN/TN score, standards coverage, arbitrary host-file
disclosure claim or scanner efficacy claim. An unexecuted provider is not a true
negative.
