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
- Public localization is adaptive, not word-for-word. Write for native security
  practitioners in each language, preserving meaning rather than English syntax.
- In Russian and Simplified Chinese public copy, preserve English only for established
  acronyms, product names, protocol/schema names, and intentional architecture labels.
  Generic engineering nouns must be translated naturally.
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
| Native discovery         | **native discovery**, **built-in discovery** in practitioner copy                                              | **встроенное обнаружение**; **встроенный сканер** when describing the concrete user-facing action                                                         | Means first-party discovery that can build the initial model before optional tool providers are installed                                                                 |
| Workflow lens            | **lens**, **workflow lens**                                                                                     | **рабочее представление** in public copy; **линза** is acceptable when discussing the architecture concept                                                 | A view/query/action focus over shared state, not a separate database or product                                                                                            |
| Agentless-first          | **agentless-first**                                                                                             | **без обязательных агентов**                                                                                                                               | Avoid the English adjective in Russian public prose; optional persistent sensors may still exist later                                                                    |
| Modular tooling          | **modular tooling**, **tool provider**, **capability provider**                                                 | **модульные инструменты**, **подключаемый инструмент / модуль**                                                                                            | Do not mix generic English nouns such as tooling/provider/capability into Russian public prose; external tools enrich the shared model                                    |
| AI execution layer       | **runtime for AI security agents**, **security execution runtime**                                              | **контур выполнения для ИИ-агентов**, **контур выполнения операций ИБ**                                                                                   | Prefer natural Russian public copy over bare **runtime** unless discussing the engineering component                                                                      |
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

## English practitioner-facing style

Public English copy should read like security product documentation written by an
experienced practitioner, not like an internal architecture note.

Prefer concrete terms such as **built-in discovery**, **shared model**, **evidence**,
**attack surface**, **reachability**, **attack path**, **security control**, and
**retest**. Avoid exposing internal phrasing such as **truth store**, **substrate**,
or other implementation-oriented language when a direct practitioner term exists.

Architecture labels remain valid where they help explain the product, but landing-page
copy should describe what the operator sees and does.

## Russian security-marketing style

Russian public copy must read as original professional Russian, not as translated
English syntax.

Prefer terminology already common in Russian cybersecurity communication:

- **анализ защищённости**;
- **тестирование на проникновение / пентест**;
- **поверхность атаки**;
- **достижимость целевых систем**;
- **пути / маршруты атак**;
- **меры защиты**;
- **цифровая криминалистика**;
- **расследование инцидентов**;
- **рабочее пространство**;
- **встроенный сканер / встроенное обнаружение**;
- **выявленная проблема / результат проверки**;
- **хронология**;
- **повторная проверка**.

Do **not** mix generic English nouns into Russian prose when a normal professional
Russian equivalent exists. In particular, avoid bare **tooling**, **workspace**,
**provider**, **capability**, **finding**, **timeline**, **validation**, **evidence**,
**runtime**, **scope**, and **impact** in public sentences.

Established names and acronyms such as **CI/CD**, **API**, **SDK**, **MCP**,
**OpenAPI**, **GraphQL**, **SBOM**, **DFIR**, **DevSecOps**, **Purple Team**,
**Kubernetes**, **Docker**, **Nmap**, and **Nuclei** may remain English.

Canonical architecture labels such as **Security Object Model**, **Capability
Fabric**, **Evidence & Provenance**, and **Scope & Policy** may appear in parentheses
on first use. Surrounding prose must remain natural Russian.

## Simplified Chinese security style

Simplified Chinese public copy must use terminology and sentence structure natural to
Chinese security practitioners rather than transliterating English architecture
phrases.

Prefer established terms such as:

- **攻击面**;
- **网络可达性**;
- **攻击路径**;
- **横向移动**;
- **安全控制 / 防护控制**;
- **取证材料**;
- **时间线**;
- **复测**;
- **工作空间**;
- **内置扫描与发现**;
- **可追溯**.

Avoid mixing generic English nouns such as **workspace**, **provider**, **capability**,
**lens**, **agentless-first**, or **runtime** into running Chinese prose. Preserve
standard acronyms and product names such as **API**, **SDK**, **MCP**, **SBOM**,
**DFIR**, **DevSecOps**, **Purple Team**, **Nmap**, **Nuclei**, **Kubernetes**, and
**Docker**.

For project-defined architecture terms, use a natural Chinese term followed by the
canonical English name on first use where useful, for example **安全对象模型
（Security Object Model）** and **证据与来源追踪（Evidence & Provenance）**.

In user-facing copy, prefer **内置扫描与发现** or **内置发现** over the literal
calque **原生发现** unless quoting an internal architecture identifier.

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
- Alibaba Cloud Security Center, [Attack Surface Management](https://www.alibabacloud.com/help/zh/security-center/user-guide/attack-surface-management-overview)
  and [Attack Path](https://www.alibabacloud.com/help/zh/security-center/user-guide/risk-of-attack)
  — current Simplified Chinese use of **攻击面**, **网络可达性**, **攻击路径**,
  **横向移动**, **风险资产**, and **安全控制** vocabulary.
- IAEA Russian terminology for **chain of custody** uses the formal concept
  **цепочка мер по обеспечению сохранности доказательств**; practitioner material
  also commonly uses **цепочка хранения доказательств**.

## Historical documents

CHANGELOG.md is append-only historical documentation. Older terminology in
historical entries may be retained when changing it would rewrite the record.

Accepted ADRs may include a dated terminology clarification when wording is refined
without changing the architectural decision.
