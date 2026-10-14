# ADR 0080: Explicit local IOC artifact CLI

- Status: Accepted bounded consumer decision
- Date: 2026-10-14
- Related work: Task #85, Feature #83, M8

## Context

ADR 0076 supplies a verified offline IOC artifact API, but no installed product
entry point. A small consumer can make that exact evidence contract usable
without deciding the separate incident/event/entity/process schema or treating
supplied tokens as Findings, scan targets or maliciousness proof.

## Decision

Expose Experimental `1337 trace ioc import|inspect` and its foreground shell
equivalent. The command requires an existing explicit physical workspace and
uses the unchanged `ioc_artifacts` acquisition/replay owner. No independent
parser, evidence schema, model writer, dataset or executor is added.

Import selects one absolute regular non-secret file, all source/version/logical
locator/license fields, an exact lowercase expected SHA-256, opaque collection
scope attribution and explicit owner/read-consent references. The existing
`ArtifactReadConsent` validates the selected-file declaration before reading.
It does not authenticate the actor or authorize assessment. The unchanged IOC
receipt records its existing source/budget/acquisition attribution; it does not
gain collector-identity or consent fields. Source-declared locators remain data
and are never read.

Five caller limits retain the accepted SDK defaults and independent hard ceilings:
64 KiB bytes, 256 lines/items and 512 bytes per line/token. A declared oversize
file is refused before opening; reads use at most one overflow byte and never
acquire truncated input. Physical parents, regular kind, one link and nonzero
identity are observed. Full device/inode/size/mtime/ctime identities must remain
equal within the path view and within the owned handle view. The existing
platform-aware comparison binds the two views; Windows ctime may differ between
APIs, but a change within either view is always rejected. Observed guards do not
claim protection against every hostile concurrent filesystem writer.

The consumer requires exact original SDK result/record/snapshot types. It reopens
all original immutable manifests, verifies source/receipt/provenance/request pins
and independently reparses successful snapshots with the original returned
receipt anchor. Refused digest/parse states retain verified raw and receipt
records and supply no usable snapshot. Refusal is checked against original bytes,
not merely the returned state label.

Inspect requires both caller-retained `--snapshot` and independent original
`--receipt` manifest identities. It calls the existing replay owner and never
infers its trusted receipt from candidate metadata. It rejects source/consent
overrides and requires neither the original physical source file nor current
target authority. It performs no acquisition, Core/workspace save, process,
network resolution or scan. Original receiver times and source-declared times
retain their existing separate meanings.

Structured output is a schema-one terminal summary of counts, observed source
hash/length, acquisition times and immutable identifiers. Original tokens,
source bodies, physical filenames, declared source/license text and owner/read
references are not copied into summaries or generic diagnostics. The entire
`trace` shell namespace is protected from stored history/replay, including
invalid commands and native input history.

## Failure and acknowledgement

| Exit | Meaning                                                           |
| ---- | ----------------------------------------------------------------- |
| 0    | Original acquisition or independently anchored replay verified    |
| 2    | Invalid grammar, declaration, budget or selected physical file    |
| 4    | Refused acquisition, integrity/storage failure or unknown outcome |
| 130  | Interrupted operation                                             |

Import reports `evidence_commit: confirmed` only after all returned original
records verify. A storage error or interruption after acquisition begins reports
`unknown`; immutable orphan records may already exist. No rollback or atomic
multi-record transaction is claimed. Confirmed refused originals remain visible
through their raw/receipt identifiers. Inspect reports `not-attempted` because it
does not publish evidence. Core mutation remains `none` throughout.

## Consequences

The installed CLI makes the accepted candidate artifact profile useful without
claiming Task #85 completion. Broader parsers, collector/custody semantics,
Core matching, incident timelines, maliciousness, publisher authenticity and
observed attack paths remain separate accepted-contract/owner work.
