# ADR 0029: Read-only workflow lens contract

- Status: Accepted implementation decision under ADRs 0009, 0010, and 0012
- Date: 2026-10-11
- Related work: #81, #79

## Context

The shell can select a persona label, but it cannot describe that lens to an
automation client or render actual canonical objects differently. M2 requires
small reusable views of the existing model, without waiting for jobs, advanced
DFIR ingestion, or attack-path analysis.

## Decision

Add the Experimental `fuzzy1337.lenses` Python surface and schema version 1 at
`contracts/workflow-lens.schema.json`. An immutable descriptor declares preferred
object/relation kinds, an offline default query, contextual suggestions,
capability preferences, source/evidence/history overlays, attribute-label
mappings, and client-neutral presentation hints. Initial identifiers remain
`pentest`, `dfir`, `devsecops`, and `purple`.

Queries use typed kinds, literal key substrings, exact JSON attribute matches,
an explicit provenance requirement, and observation inclusion. There is no
executable query expression, handler locator, plugin import, or network access.
An explicit caller query replaces the preset query; it does not mutate the
descriptor. Empty kind lists mean all currently supported kinds, permitting
additive domain families without a second model.

`LensDescriptor.Project` consumes one immutable `ModelState` and returns only
canonical object, induced relation, and retained observation references, together
with workspace ID, revision, lens ID, and resolved query. Relations require both
endpoints in the selected object set; observations require a selected subject.
Chronological ordering uses normalized acquisition times with reference ties.
It describes observation history, not an inferred incident timeline. The view
format cannot be opened as an authoritative model document.

Descriptor decoders reject unsupported versions, unknown/missing fields,
unsupported kinds, malformed filters, and duplicate identifiers. Suggestions and
capability names do not prove availability and are not executable callbacks.
Attribute mappings rename display labels only; they never derive security facts.
Clients may render overlays by reading the canonical records and evidence APIs.
Evidence references alone do not verify artifact integrity.

The shell explicitly opens an existing portable workspace with
`model <workspace-path>`. `view model [--json]` renders that snapshot, and
`lens [<name>] --json` exposes metadata. A model view without a loaded snapshot
fails explicitly. Opening or switching a lens never saves workspace/model state,
changes registration/consent/policy, chooses impact, or starts execution. A failed
open retains the previous bound snapshot. Reopening is explicit; this change
does not subscribe to jobs or pretend a loaded snapshot is a live stream.

## Validation

Unit and schema/decoder contract tests exercise all four descriptors, filters,
strict JSON equality, immutable metadata, induced relations, chronological
observation order, and rejected authority/execution fields. Integration tests
open real isolated workspace/model/evidence stores through the shell and compare
all stored bytes before and after switching lenses. They also exercise missing
and corrupt state, exact IDs/revisions, machine output, and actual terminal
surface versus inventory views. No scanner, browser, external target, paid
service, or persona-specific persistence is needed.

## Consequences

Human, CI, and agent clients can inspect and query the same lens contract.
Presentation remains independent of Scope/Policy and governed execution.
Live job binding, mature DFIR timelines, CI risk gates, and Purple detection/path
analysis remain responsibilities of their respective work items.
