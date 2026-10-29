# Web scanner migration matrix

## Purpose

This document makes the M4 Web Scanner NG boundary explicit before code is
ported or an external engine is wrapped. 1337 must retain its differentiated
workbench behavior — scope, policy, durable Security Objects, evidence, and
reachability — without recreating mature generic scanner engines or importing
their implementation histories.

No source code, signatures, templates, or license-restricted data is copied
from the projects listed below. They are evaluated as external providers or as
conceptual input only.

## Decision

1337 owns the provider-neutral web-security contract and orchestrates suitable
engines behind it.

| Area                      | 1337 owns                                                                               | External provider boundary                  | Decision                                  |
| ------------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------- | ----------------------------------------- |
| Scope and authorization   | Target/scope rules, impact gate, confirmation, audit trail                              | Provider receives only a bounded invocation | Native                                    |
| Request model             | Endpoint, RequestTemplate, InjectionPoint, session/evidence identities                  | Providers may consume/export requests       | Native in #58                             |
| Discovery scheduler       | Deterministic queue, URL normalization, deduplication, cancellation, live object deltas | Browser/AJAX crawl can enrich seeds         | Native orchestration; provider enrichment |
| Browser interaction       | Session/evidence integration and safe launch policy                                     | Playwright/Chromium execution               | Adapter-backed in #59                     |
| Passive checks            | Evidence normalization, finding identity, policy and reporting                          | ZAP passive rules and compatible scanners   | External adapter                          |
| Template checks           | Template provenance, selection policy, raw evidence, normalized result                  | Nuclei engine and reviewed template set     | External adapter (#36)                    |
| Active checks             | Bounded request generation, impact policy, canary assertions                            | ZAP or future specialized providers         | External adapter; no unsafe default       |
| Findings and graph inputs | Evidence, confidence, Security Objects, Relations, reachability inputs                  | Provider alerts/observations                | Native normalization                      |

## Source inventory and disposition

| Project / source | Valuable concept                                                                             | Disposition                      | Rationale                                                                             |
| ---------------- | -------------------------------------------------------------------------------------------- | -------------------------------- | ------------------------------------------------------------------------------------- |
| OWASP ZAP        | Automation, passive-vs-active separation, context-aware spidering, OpenAPI import, reporting | Optional external ToolAdapter    | Mature engine; 1337 preserves scope/evidence/model semantics around it                |
| Nuclei           | Declarative checks, versioned template provenance, targeted execution                        | Optional external ToolAdapter    | Template execution is useful, but templates and engine do not become the domain model |
| Playwright       | Stateful browser automation and browser-derived traffic                                      | Browser provider                 | Browser control is not a durable 1337 truth store                                     |
| w3af             | Plugin separation, crawl/check pipeline, audit output lessons                                | Conceptual input only            | Do not copy legacy engine or plugin code into the new async architecture              |
| Arachni          | Separation of audit framework and checks                                                     | Retired as implementation source | Repository is archived; no runtime dependency or code migration                       |
| OWASP WSTG       | Human-readable test taxonomy and scenario vocabulary                                         | Reference mapping only           | Taxonomy informs coverage; it is not a scanner engine or evidence source              |

## Evidence for migrated concepts

The development candidate implements the following independent concepts through
the shared owners below. Implementation status describes the declared profile;
it does not transfer the legacy engine's claimed coverage to 1337.

| Concept                            | New owner and verification                                                                                                      | Remaining boundary                                                                                          |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Requests and injection coordinates | `fuzzy1337.requests`; versioned contract and actual model relocation tests                                                      | Structural coordinates and symbolic bindings; no arbitrary request assembly or execution                    |
| API baseline generation            | `ImportOpenApi` and `GenerateOpenApiRequest`; independently consumed previews and model/evidence integration                    | Bounded offline synthetic previews; authenticated assembly and general schema solving remain open           |
| Concurrent discovery               | `LocalWebTraversalProvider`; actual overlapping acquisition, ordered commits, cancellation and consent-expiry integration tests | Explicit owned-loopback pages and reviewed body catalog; broader crawling and browser execution remain open |
| Git metadata exposure              | Original `git-head-exposure.yaml`; genuine Nuclei, actual owned HEAD file and fixed/decoy/redirect controls                     | Selected endpoint and supported symbolic-reference grammar; no implicit path discovery or source recovery   |
| SQL input behavior                 | Original `owned-sql-canary-disclosure.yaml`; real read-only SQLite target with baseline/true/false/fixed/decoy cases            | Owned result-canary disclosure only; no generic differential SQLi, timing inference or arbitrary extraction |
| Reflected input                    | Original `unsafe-html-reflection.yaml`; actual raw/escaped/comment responses and genuine provider                               | Candidate unsafe HTML reflection; browser-confirmed, DOM, stored and other XSS contexts remain open         |

The three response checks share the existing [Nuclei workflow](NUCLEI_WORKFLOW.md).
Their [declared predicates and acceptance](NUCLEI_WEB_CHECKS.md) bind manifest and
template hashes to the actual invocation, provider version, original streams,
target observations and persisted Findings. Metrics come from those Findings and
the independent oracle. Failed runs retain their evidence; rejected, skipped and
unexecuted inputs do not become true negatives. The exact-path admission guard
also rejects provider URL rewriting and decoded expression delimiters before
invocation. It does not authorize an alternative spelling.

Generic SQLi, filesystem traversal/LFI detection, SSRF, command/template injection,
authorization and session attacks, business-logic abuse and AI-specific attacks
need their own governed producer, independent positive/fixed/decoy targets and
actual detector acceptance. Neither an injection coordinate nor a target-only
mechanism establishes that coverage.

## Current taxonomy references

Reference check on 2026-10-15: [OWASP Top 10 2025](https://top10.owasp.org/2025/),
[API Security Top 10 2023](https://api-security.owasp.org/editions/2023/en/0x11-t10/),
[WSTG v4.2](https://wstg.owasp.org/v4.2/),
[ASVS 5.0.0](https://owasp.org/projects/asvs),
[ATT&CK v20.0](https://attack.mitre.org/resources/versions/) and
[ATLAS content 2026.09](https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/manifest.yaml)
provide distinct risk, test, requirement or adversary-technique vocabularies.
WSTG v5.0 remains in development; ATLAS content and its format version are separate.
These references guide future scenario selection and do not assert implemented
detectors, passed verification requirements or complete framework coverage.

The [reviewed historical mapping baseline](STANDARDS_MAPPING_BASELINE.md) remains
unchanged. Its versioned classifications and exact-content decisions cannot be
silently relabeled to newer editions. New current-version mappings require their
own reviewed source pins and evidence-bound classification; the web slices above
do not establish an AI or prompt-injection detector.

## Non-negotiable migration guards

- Do not copy source code, checks, templates, signatures, or global mutable
  runtime state from legacy scanners.
- Do not make ZAP, Nuclei, Playwright, Chromium, or a template bundle a required
  dependency for `1337` startup.
- Do not treat a provider alert as an authoritative Finding without preserving
  the raw report, invocation, provider version, scope, and parser provenance.
- Do not enable active, brute-force, credential, callback, or mutation behavior
  by default. Scope and impact policy decide each bounded invocation.
- Do not make provider output a separate web-scanner database. It enriches the
  shared Security Object Model through observations, evidence, findings, and
  relations.
- Do not use an archived scanner as a packaged runtime dependency.

## Implementation sequence

1. #58 defines the provider-neutral request and injection contracts.
2. #59 implements bounded native discovery and the optional browser provider.
3. #36 introduces Nuclei through the M2 ToolAdapter contract.
4. A later M4 task may add the ZAP adapter after the same health, invocation,
   evidence, parser, scope, and impact contracts exist.
5. #143–#147 reuse the request/evidence contracts for API and GraphQL security;
   they do not fork a second scanner model.

## References

- [OWASP ZAP Automation Framework](https://www.zaproxy.org/docs/desktop/addons/automation-framework/)
- [OWASP ZAP passive scanner](https://www.zaproxy.org/docs/desktop/addons/passive-scanner/)
- [OWASP ZAP OpenAPI automation support](https://www.zaproxy.org/docs/desktop/addons/openapi-support/automation/)
- [Nuclei project](https://github.com/projectdiscovery/nuclei)
- [Nuclei MIT license](https://github.com/projectdiscovery/nuclei/blob/main/LICENSE.md)
- [Playwright for Python](https://github.com/microsoft/playwright-python)
- [w3af project](https://github.com/andresriancho/w3af)
- [Arachni project](https://github.com/Arachni/arachni)
- [OWASP Web Security Testing Guide](https://github.com/OWASP/wstg)
