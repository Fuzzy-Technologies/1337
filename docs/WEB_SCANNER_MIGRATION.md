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
|---------------------------|-----------------------------------------------------------------------------------------|---------------------------------------------|-------------------------------------------|
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
|------------------|----------------------------------------------------------------------------------------------|----------------------------------|---------------------------------------------------------------------------------------|
| OWASP ZAP        | Automation, passive-vs-active separation, context-aware spidering, OpenAPI import, reporting | Optional external ToolAdapter    | Mature engine; 1337 preserves scope/evidence/model semantics around it                |
| Nuclei           | Declarative checks, versioned template provenance, targeted execution                        | Optional external ToolAdapter    | Template execution is useful, but templates and engine do not become the domain model |
| Playwright       | Stateful browser automation and browser-derived traffic                                      | Browser provider                 | Browser control is not a durable 1337 truth store                                     |
| w3af             | Plugin separation, crawl/check pipeline, audit output lessons                                | Conceptual input only            | Do not copy legacy engine or plugin code into the new async architecture              |
| Arachni          | Separation of audit framework and checks                                                     | Retired as implementation source | Repository is archived; no runtime dependency or code migration                       |
| OWASP WSTG       | Human-readable test taxonomy and scenario vocabulary                                         | Reference mapping only           | Taxonomy informs coverage; it is not a scanner engine or evidence source              |

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
