# ADR 0030: Reviewed optional Nuclei HTTP profiles without scan authority

## Status

Accepted — 2026-10-11

## Context

Task #36 requires another concrete consumer of the existing ToolAdapter,
executor, and evidence contracts. Nuclei templates can contain intrusive checks,
multiple protocols, redirects, executable logic, payload expansion and external
callbacks. Installing the tool or selecting a severity is not authorization or
proof of a bounded check. The adapter must preserve its optional familiar CLI
boundary without creating an alternate executor or provider-specific model.

## Decision

Introduce the Experimental `fuzzy1337.adapters.nuclei` module. Nuclei remains an
optional operator-installed tool under its own terms. The base SDK neither imports
the module nor installs Nuclei or its template collection.

The initial `web.http-template-check` capability requires `STANDARD` impact, one
credential-free literal-IP HTTP(S) URL, a total timeout, a bounded request rate,
and the SHA-256 identity of a finite operator-configured `NucleiProfile`. Each
`NucleiTemplate` binds a local regular YAML file to exact size/hash, template ID,
source/revision, and a review reference for `single-get-exact-url`. That review
attests to one GET at the exact input URL, without other destinations, redirects,
payload expansion, credentials, local file access, executable logic or callbacks.
The adapter verifies artifact bytes, not the semantic review or the reviewer's
identity. Arbitrary YAML supplied by a request is never accepted; the trusted
operator owns the selected immutable files and review declarations. A hash is not
a signature, and signed templates alone would not prove the desired impact.

Preparation reads only the explicit bounded reviewed artifacts and emits familiar
shell-free Nuclei flags. An explicitly empty config overrides ambient Nuclei
configuration. HTTP filtering, JSONL output, raw/template omission, disabled
updates/OAST/redirects/stdin/httpx, single-host/single-template concurrency, zero
retries, bounded response size and per-request time are explicit. No general raw
flag passthrough, template/workflow URL, download, update, headless, code, fuzzing,
cloud upload or broad template-pack selection is provided. Earlier observed
Nuclei 3.x version metadata is required before preparation.

The only process operation owned by the adapter is the bounded local version
probe `-version -duc`, without targets or templates. Actual target execution
requires the existing exact `ExecutionAuthorization` and governed executor. The
profile digest binds artifact and review provenance into the invocation digest.
The executor's limits remain independent from the tool's own CLI limits.

Normalization verifies one explicit stdout evidence reference and parses bounded
UTF-8 JSONL with unique keys, finite numbers and structural limits. Matches must
name the selected HTTP template, exact approved URL, and consistent optional
host/IP/template-path fields. Findings use existing generic SDK envelopes with
source identity, selected provenance and raw-evidence attribution through the
unchanged enclosing report. They do not create Findings or mutate model state.
Successful malformed output fails explicitly. Unsuccessful malformed/partial
output yields only a parse diagnostic; valid partial matches remain incomplete.
Empty successful stdout means zero reported matches, not proof that every selected
template ran or that the target is safe. Replay does not require template files.

## Consequences

- Nmap and Nuclei share the existing provider-neutral boundaries without changing
  their contracts, dependencies, or startup requirements.
- Review declarations and artifact ownership are a trusted operator boundary;
  hostile concurrent file replacement and network isolation are not solved here.
  Files must remain immutable from preparation through execution. Upstream policy
  must approve the exact URL and reviewed profile; the adapter issues no approval.
- Genuine upstream CLI/output documentation defines compatibility, while tests use
  source-controlled owned YAML/JSONL and a synthetic executable that performs no
  network activity. A genuine installed-tool scan has not been executed by these
  tests and cannot be claimed as their evidence.
- Controlled tests cover reviewed-file drift, request/profile binding, SDK import
  isolation, parser/evidence integrity, actual finite local version processes and
  the real executor → evidence store → JSONL normalization path.
- Broader protocols, named DNS destinations, query credentials, arbitrary CLI
  profiles and orchestration require separately approved scope/policy contracts.

Primary compatibility references:
[Nuclei CLI flags](https://github.com/projectdiscovery/nuclei/blob/dev/README.md#command-line-flags)
and [Running Nuclei](https://docs.projectdiscovery.io/opensource/nuclei/running).
