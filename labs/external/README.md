# Optional external regression targets

This pack complements the first-party micro-targets with a pinned, isolated
OWASP Juice Shop application. It is implemented by
[ADR 0021](../../docs/adr/0021-pinned-optional-external-target-pack.md).
WebGoat, crAPI, and Benchmark were evaluated in that decision; they are not
executable targets in this inventory.

## Run the selected pack

Docker Engine and Docker Compose must already be available. From the repository
root, explicitly permit the pinned image pull and run the ordinary pytest suite:

```bash
FUZZY1337_EXTERNAL_TARGETS=juice-shop uv run --locked --extra dev pytest \
  tests/functional/test_external_targets.py -o addopts='' -v
```

With the variable unset, the external test is skipped before any Docker command
or network request. An enabled pack fails if Docker is unavailable or any
lifecycle/provenance/health check fails. No public demo is contacted. The pytest
fixture creates a unique Compose project, checks readiness, performs read-only
HTTP contract probes inside the container, and removes its container and network
even after failures.

## Immutable provenance and cost

`juice-shop.v1.json` records official release/source/registry provenance and
the index plus supported platform digests. `target.schema.json` rejects unknown
fields, unsupported versions, mutable image references, and unbounded resource
budgets. The Compose file uses JSON, a YAML subset, so the offline policy gate
and Docker consume the same definition without a new parser dependency.

| Resource or operation | Bound or measured provenance                              |
| --------------------- | --------------------------------------------------------- |
| Application release   | Juice Shop 20.2.0, source revision in the target manifest |
| Compressed download   | Approximately 109 MiB per supported Linux platform        |
| CPU / memory / PIDs   | 1 CPU, 768 MiB memory, 128 PIDs                           |
| Image pull            | 180 seconds; explicit opt-in only                         |
| Compose startup       | 120 seconds plus 10 seconds for command completion        |
| HTTP readiness        | 60 seconds; each request limited to 3 seconds             |
| HTTP response body    | 64 KiB per read, plus one byte to detect overflow         |
| Diagnostic logs       | Last 200 lines; 15 seconds                                |
| Compose cleanup       | 45 seconds plus 30 seconds for empty-project verification |

One writable container layer allows upstream database initialization. It has no
host mounts or persistent volumes. The container joins only an internal Docker
network with no external route and publishes no host port. Docker Engine does not
apply host port mappings to internal networks, as explained in ADR 0021.
It drops all capabilities and disallows privilege escalation. The image remains
in the local Docker cache after teardown; containers, networks, and their
application state are removed.

The startup fixture verifies `/rest/admin/application-version` equals 20.2.0,
the image reference and configuration ID of the running container, and its
OS/architecture and platform manifest against the pinned OCI index. An unrelated
HTTP 200 response does not satisfy readiness.

Each request uses `docker compose exec -T` to launch the image's fixed Node
executable and the first-party `node:http` probe. HTTP options fix the destination
to container loopback `127.0.0.1:3000`, without URL resolution, proxy variables, or
redirect following. The Node deadline is 75% of the three-second parent budget,
leaving time for process launch and output collection. Request duration includes
Docker exec launch latency. Expiry destroys the HTTP resources and retains received
status, raw headers, and bounded UTF-8 body text before child exit 124; the parent
preserves the original command outcome and marks the observation as timed out.

## Evidence and interpretation

Generated evidence is ignored under `functional-evidence/external-juice-shop/`:

- `command-*.json`: exact argv, stdout/stderr, exit status, timeout flag, duration;
- `request-*.json`: container-loopback address/path, status, headers, body, errors;
- `provenance.json`: release/source/index/platform/running-image attribution;
- `report.json`, `matrix.md`, `matrix.html`: one generated qualitative result.

The dedicated CI job explicitly enables the pack and retains these records even
after failures. Version/root/search observations verify the target contract and
regression pipeline. The oracle is incomplete, so confusion counts and absolute
accuracy are withheld. This smoke does not execute a production scanner or
measure vulnerability-detection effectiveness. The first-party micro-target
oracle remains the deterministic source for known-answer metrics.
