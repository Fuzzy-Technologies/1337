# Optional Nmap Adapter

`fuzzy1337.adapters.nmap` is an Experimental implementation of the existing
[ToolAdapter SDK](TOOL_ADAPTERS.md), defined by
[ADR 0024](adr/0024-bounded-optional-nmap-adapter.md). It prepares finite commands
and interprets evidence. It never authorizes or starts a target scan and never
persists Security Object Model updates.

The supported surface is `NmapAdapter`, its `Descriptor`, `CheckHealth`,
`PrepareInvocation`, and `NormalizeReport` operations, `NmapReportError`, and the
documented `NMAP_*` version/resource constants. Parser, parameter-validator, and
health helper functions are Internal. Import the concrete adapter explicitly;
the base SDK import does not discover, install, or require Nmap.

## Availability and provider ownership

Nmap is an optional operator-installed system executable. The repository neither
bundles it nor changes the Apache-2.0 license of 1337. Nmap's own distribution
and licensing terms remain separate; see the official
[Nmap Public Source License](https://nmap.org/npsl/). Installation and executable
selection belong to the operator, not to a request's parameters.

Construction performs no I/O. `CheckHealth()` resolves the selected executable
and runs only `(executable, "--version")`, without shell interpolation or a
target. The probe has a three-second wait deadline and retains at most 16 KiB
plus one overflow-detection byte. Cleanup kills and reaps the owned process;
capture workers are bounded and do not grant network scan permission. Missing or
unlaunchable tools are `UNAVAILABLE`; failed, unrecognized, timed-out, or oversized
version output is `DEGRADED`. An available observation supplies the version but
does not prove the next scan will succeed.

The executable is operator-selected and trusted. These limits do not sandbox a
malicious replacement executable, its child processes, or its external effects.
An earlier observed version may be passed explicitly as `provider_version`; no
implicit health probe runs during preparation or parsing.

## Finite request profiles

Both initial capabilities require an explicitly approved `STANDARD` impact.
They do not accept credentials or arbitrary flags.

| Capability                  | Command behavior                              |
| --------------------------- | --------------------------------------------- |
| `network.tcp-connect`       | Unprivileged TCP connect discovery (`-sT`)    |
| `network.service-discovery` | TCP connect plus `-sV --version-light` probes |

The request's parameter keys must be exactly:

| Parameter         | Accepted contract                                                   |
| ----------------- | ------------------------------------------------------------------- |
| `address`         | One unscoped literal IPv4/IPv6 address; no DNS name, CIDR, or range |
| `ports`           | 1–1024 unique integer TCP ports, each within 1–65535                |
| `timeout_seconds` | Integer 1–3600; used for both executor and Nmap host time limits    |

Multicast and unspecified addresses are rejected. Port numbers are sorted and
IP spelling is canonicalized offline. `target_reference` remains an opaque
provider subject reference; it is never parsed as the address or resolved by DNS.
Policy must verify the actual address, ports, target binding, and impact before
issuing `ExecutionAuthorization` for the resulting exact invocation digest.

Prepared argv always includes `--unprivileged -n -Pn -sT`, explicit `-p`,
`--host-timeout`, and `-oX -`; IPv6 adds `-6`. `-n` prevents reverse DNS, `-Pn`
omits the host-discovery phase, and `-sT` avoids selecting a privileged raw scan.
The service capability adds only `-sV --version-light`. These operations send
network traffic when a governed executor runs them. They are not passive or
authorization decisions. NSE, UDP, OS detection, traceroute, target expansion,
custom tool flags, and a public scanning CLI are outside this initial adapter.

## Governed execution and evidence

```python
from fuzzy1337.adapters.nmap import NmapAdapter

adapter = NmapAdapter(store.Read, provider_version=observed_version)
invocation = adapter.PrepareInvocation(approved_request)
```

The caller supplies the existing [LocalExecutor](EXECUTORS.md) with that exact
invocation, a matching capability, and an explicit upstream authorization.
Adapters do not construct scan authorization. The caller then stores bounded
stdout and stderr with [LocalEvidenceStore](EVIDENCE.md), including the actual
invocation digest, terminal execution facts, tool version, workspace/scope
references, and offset-aware collection times in `EvidenceProvenance`.

`AdapterReport` retains those immutable evidence references. Exactly one
`stdout` reference supplies XML. The injected reader is normally `store.Read`;
normalization additionally checks the expected digest and byte count. Evidence
store failures propagate. No raw bytes, XML argument strings, credentials,
environment values, or discovered files are copied into normalized results.

## Parsing and normalized output

XML must be UTF-8 and no larger than 4 MiB. Streaming structural validation caps
the document at 65,536 elements and depth 32. The parser permits Nmap's inert
`<!DOCTYPE nmaprun>` declaration but rejects internal subsets, external/system
DTDs, entity declarations, CDATA, and other active declarations. Stylesheet
processing instructions are ignored; neither stylesheets nor DTDs are loaded.
This deliberately bounded profile is not a validating implementation of every
extension accepted by the full Nmap DTD.

The report must match the adapter's prepared finite argv and timeout. XML must
identify `scanner="nmap"`, contain at most one host whose literal address matches
the approved request, and contain only unique requested TCP ports with known
states. A successful executor result additionally requires XML
`runstats/finished/@exit="success"`. Malformed successful output raises
`NmapReportError`; malformed failed/timed-out/cancelled output produces only an
explicit `nmap.parse` incomplete diagnostic, retaining the original report.

Existing SDK envelopes carry:

| Envelope               | Meaning                                                                |
| ---------------------- | ---------------------------------------------------------------------- |
| `nmap.run` observation | XML completion/version facts and the original executor terminal state  |
| `network.host`         | Literal address, host status/reason, and grouped `extraports` metadata |
| `network.port`         | Reported TCP number, state, and reason                                 |
| `network.service`      | Reported name, method/confidence, product/version, and CPE metadata    |
| Object enrichment      | `host`, `port`, and `service` proposals using provider references      |
| Relation enrichment    | `has-port` and `hosts-service` proposals                               |

The host reference is `request.target_reference`; port references append
`:tcp:<number>`, and service references append `:service`. These are deterministic
provider references, not authoritative Security Object Model identities. A model
consumer must explicitly map them. Grouped omitted ports remain grouped; the
adapter does not invent per-port states from `extraports`. Missing hosts or
services remain absent. Open ports and service names do not become vulnerability
findings.

`nmap.run.complete` reports the XML completion marker, not a new execution state
or proof that all requested ports were assessed. Even complete XML from failed,
timed-out, or cancelled execution preserves that original terminal failure in
`result.report.execution` and in the run observation. Raw evidence survives
independently from these interpretations.

## Focused verification

```text
python -m pytest tests/unit/test_nmap_adapter.py tests/integration/test_nmap_evidence.py -q
python -m pytest tests/functional/test_nmap_loopback.py -q
```

The unit selection verifies exact argv, bounds, malformed/partial output,
DTD/entity/encoding rejection, evidence integrity, failure truth, and immutable
SDK envelopes. The integration fixture is an explicitly synthetic XML producer;
it executes the exact prepared command through the real LocalExecutor and
Evidence Store, without network activity. Its POSIX executable fixture is
explicitly skipped on Windows; portable unit coverage still runs there.

The optional functional test uses a genuine installed Nmap against two sockets
owned by the test on `127.0.0.1`: one listening and one bound without listening.
Its machine-readable known-answer oracle, actual tool provenance, raw evidence,
and normalized result are retained in the owned temporary workspace. Missing
Nmap explicitly skips this test. This two-port observation oracle makes no
vulnerability-accuracy claim and never scans an Internet or arbitrary LAN host.

## Official provider references

The finite argv and parser shape were checked against these first-party Nmap
documents on 2026-10-05; no provider source, database, DTD, or report fixture was
copied into the repository:

- [Port scanning techniques](https://nmap.org/book/man-port-scanning-techniques.html)
- [Service/version detection](https://nmap.org/book/man-version-detection.html)
- [Miscellaneous options: IPv6, unprivileged mode, version](https://nmap.org/book/man-misc-options.html)
- [XML output, stdout, and report fields](https://nmap.org/book/output-formats-xml-output.html)
- [Nmap Public Source License](https://nmap.org/npsl/)
