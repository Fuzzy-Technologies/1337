# Security terminology and public copy guide

This guide defines preferred security terminology for current 1337 documentation,
marketing copy, discovery metadata, and localization.

It does **not** rename stable code identifiers, external standards, issue titles, or
historical wording that must remain unchanged for traceability.

## Editorial principles

- Prefer established cybersecurity terms over literal translation or invented
  category names.
- Keep product-defined architecture terms explicit when they are intentionally
  project concepts, for example **Security Object Model**, **Capability Fabric**,
  **Executor Runtime**, and **Evidence & Provenance**.
- In Russian public copy, preserve established English technical names only when
  practitioners commonly use them or when they are canonical product/API names.
- Do not translate terminology in a way that changes its security meaning.
- Avoid legal-admissibility claims. 1337 can preserve integrity, provenance,
  acquisition history, and chain of custody; a court or other authority decides
  admissibility under the applicable jurisdiction.

## Canonical terms

| Concept                  | Preferred English                                                                                               | Preferred Russian                                                                                                                                         | Avoid / note                                                                                                                                                             |
| ------------------------ | --------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| AI-model independence    | **model-agnostic**, **AI-model-agnostic** when extra precision is useful                                        | **без привязки к конкретной ИИ-модели / поставщику модели**                                                                                               | Avoid **model-neutral** and **AI-neutral** in current public copy: they are less precise and can be misread as referring to threat models or neutrality toward AI itself |
| Human-facing product     | **open security workstation**, **security workspace**                                                           | **открытая рабочая среда ИБ**                                                                                                                             | Workbench remains part of the product name                                                                                                                               |
| Security Object Model    | **Security Object Model**, **live Security Object Model**                                                       | **Security Object Model**, **модель объектов ИБ**                                                                                                         | Canonical product architecture term; do not reduce it to asset inventory                                                                                                  |
| Native discovery         | **native discovery**                                                                                           | **встроенное обнаружение**, **native discovery** in practitioner copy                                                                                      | Means first-party discovery that can build the initial model before optional tool providers are installed                                                                 |
| Workflow lens            | **lens**, **workflow lens**                                                                                     | **линза**, **рабочий срез** where natural                                                                                                                  | A view/query/action focus over shared state, not a separate database or product                                                                                            |
| Agentless-first          | **agentless-first**                                                                                             | **без обязательных агентов**, **agentless-first**                                                                                                         | Describes deployment preference; optional persistent sensors may still exist later                                                                                        |
| Modular tooling          | **modular security tooling**, **tool provider**, **capability provider**                                        | **модульный security tooling**, **подключаемый инструмент / provider**                                                                                     | External tools enrich the shared model; avoid calling the Workbench merely an orchestrator                                                                                 |
| AI execution layer       | **runtime for AI security agents**, **security execution runtime**                                              | **рантайм для ИИ-агентов в ИБ**, **контур выполнения операций ИБ**                                                                                        | Avoid **cyber agent runtime** and **security harness** in marketing copy; both are ambiguous outside project context                                                     |
| Penetration testing      | **penetration testing**, **penetration tester**                                                                 | **тестирование на проникновение**; **пентест / пентестер** are acceptable practitioner shorthand                                                          | Prefer the full English term in formal product copy                                                                                                                      |
| Attack surface           | **attack surface**, **attack surface management**                                                               | **поверхность атаки**, **управление поверхностью атаки**                                                                                                  | Established vendor terminology                                                                                                                                           |
| Reachability             | **reachability**, **reachability analysis**                                                                     | **достижимость**, **анализ достижимости**                                                                                                                 | In Russian, use it for technical reachability; it does not replace a threat model                                                                                        |
| Attack path              | **attack path**, **attack path analysis**                                                                       | **путь атаки**; **маршрут атаки** may be used when matching external/vendor terminology                                                                   | Prefer **analysis** over invented phrases such as attack-path reasoning in public category copy                                                                          |
| Finding / finding set    | **finding**, **finding set**                                                                                    | **результат проверки**, **выявленная проблема**; **находка** is acceptable in research/report prose                                                       | Choose by context; the canonical domain object may remain `Finding` in code/contracts                                                                                    |
| Remediation / control    | **remediation**, **security control**                                                                           | **устранение / исправление**, **мера защиты**                                                                                                             | In Russian marketing prose prefer **мера защиты** over literal **контроль**; Control may remain a canonical domain-object name                                           |
| Scope                    | **scope**, **authorized scope**                                                                                 | **границы проверки**, **разрешённая область проверки**                                                                                                    | Bare English scope is acceptable in code/configuration, but avoid it in Russian marketing prose                                                                          |
| Software supply chain    | **software supply chain**, **software supply-chain security**                                                   | **цепочка поставки ПО**, **безопасность цепочки поставки ПО**                                                                                             | Avoid bare Supply chain in Russian public headings when a natural Russian term fits                                                                                      |
| API security             | **API security testing**, **API security scanning**, **OpenAPI / Swagger**, **GraphQL**                         | **анализ безопасности API**, **сканирование API**                                                                                                         | Keep protocol/schema names in English                                                                                                                                    |
| Digital forensics / DFIR | **digital forensics**, **DFIR (digital forensics and incident response)**                                       | **цифровая криминалистика**, **DFIR / расследование и реагирование на инциденты**                                                                         | Avoid invented compounds such as judicial-forensic                                                                                                                       |
| Chain of custody         | **chain of custody**; **chain-of-custody record** when used attributively                                       | Explain on first use as **chain of custody — цепочка хранения доказательств**; **цепочка обеспечения сохранности доказательств** is a more formal variant | Do not call it a special type of chain-of-custody evidence                                                                                                               |
| Legal / forensic use     | **law-enforcement investigation**, **judicial proceedings**, **forensic workflow supporting legal proceedings** | **расследование правоохранительных органов**, **судебное разбирательство**, **судебно-экспертный / криминалистический процесс** where context requires    | Do not claim universal court admissibility                                                                                                                               |
| Evidence layers          | **source/raw evidence → observation → finding/correlation → interpretation**                                    | **исходные данные/доказательства → наблюдение → находка/корреляция → интерпретация**                                                                      | AI output is not automatically evidence or a confirmed finding                                                                                                           |
| Incident reconstruction  | **incident timeline**, **observed attack path**, **observed attack graph** (1337 project term)                  | **хронология инцидента**, **наблюдавшийся / подтверждённый данными путь атаки**                                                                           | Keep uncertainty/confidence explicit                                                                                                                                     |

## Russian security-marketing style

For Russian product copy, prefer terminology already common in professional Russian
cybersecurity communication:

- **анализ защищённости**;
- **тестирование на проникновение / пентест**;
- **поверхность атаки**;
- **достижимость целевых систем**;
- **пути / маршруты атак**;
- **меры защиты**;
- **цифровая криминалистика**;
- **расследование инцидентов**.

Established engineering terms such as **CI/CD**, **API**, **OpenAPI**, **GraphQL**,
**Runner**, **Artifact Registry**, **Deployment**, **Production**, **Kubernetes**,
**Docker**, **runtime**, and **shell** may remain English where translation would
reduce clarity for the target audience.

Canonical architecture labels such as **Capability Fabric** and **Scope & Policy**
may remain English in headings, but surrounding Russian prose should be natural
Russian rather than word-for-word translation.

## Reference vocabulary used for this review

- NIST CSRC, [Digital Forensics](https://csrc.nist.gov/glossary/term/digital_forensics)
  — integrity, chain of custody, repeatability, reporting, and possible use in
  judicial proceedings.
- NIST CSRC, [Chain of Custody](https://csrc.nist.gov/glossary/term/chain_of_custody)
  — documented movement/handling of evidence through collection, safeguarding, and
  analysis.
- Tenable Exposure Management, [Attack Path](https://docs.tenable.com/exposure-management/Content/attack-path/attack-path.htm)
  — attack paths to critical assets, security controls, remediation, and scan-based
  verification.
- Elastic Security, [AI for Security Operations](https://www.elastic.co/security/ai)
  — current public use of **model-agnostic** for customer-selectable AI models.
- Positive Technologies, [Web applications and development infrastructure threatscape](https://ptsecurity.com/research/analytics/web-applications-and-development-infrastructure-threatscape-2026-2027-trends-and-forecasts/)
  — current Russian use of **анализ защищённости** and established offensive-security
  vocabulary; other PT materials use **меры защиты** and **поверхность атаки**.
- Kaspersky, [Digital Forensics](https://www.kaspersky.ru/resource-center/definitions/digital-forensics)
  and [Incident Response](https://www.kaspersky.ru/enterprise-security/incident-response)
  — **цифровая криминалистика**, **цифровые улики**, **реагирование на инциденты**,
  and incident-timeline reconstruction.
- BI.ZONE, [Pentest, AppSec and Red Team](https://bi.zone/expertise/insights/pentest-appsec-i-red-team-iznutri-proekty-uyazvimosti-rekomendatsii/)
  — practitioner-facing Russian use of **пентест**, **тестирование на проникновение**,
  **выявленные уязвимости**, and remediation language.
- IAEA Russian terminology for **chain of custody** uses the formal concept
  **цепочка мер по обеспечению сохранности доказательств**; practitioner material
  also commonly uses **цепочка хранения доказательств**.

## Historical documents

CHANGELOG.md is append-only historical documentation. Older terminology in
historical entries may be retained when changing it would rewrite the record.

Accepted ADRs may include a dated terminology clarification when wording is refined
without changing the architectural decision.
