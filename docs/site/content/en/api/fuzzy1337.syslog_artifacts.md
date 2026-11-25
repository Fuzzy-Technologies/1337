# fuzzy1337.syslog_artifacts

Experimental SDK version one exposes `SyslogSource` (including `ToDict`),
`SyslogAcquisition`, `ImportSavedSyslogFile` and `LoadSavedSyslog`.
All other classes, functions, constants and helpers in this module are Internal.
These functions compose the unchanged [artifact reader](fuzzy1337.artifact_inputs.md),
[local evidence owner](fuzzy1337.evidence.md) and
[pure source parser](fuzzy1337.syslog_records.md), without a new storage/Core family.

Import requires an existing physical workspace, one explicitly selected owned
non-secret file, independent raw SHA-256, declared source/version/locator,
explicit framing, scope attribution and selected-file actor/consent references.
The original tool version remains unknown unless declared; the actual parser
identity/version is separate. The original is retained byte for byte with a
closed profile-specific receipt pinning its exact raw manifest, parser/limits,
source/framing, descriptive read declaration and normalized-document checksum.
A checksum refusal publishes nothing; correctly pinned malformed input retains
the original and refusal receipt without usable records.

Raw and receipt ACKs are independent `not-attempted|unknown|confirmed` facts.
A later failure does not roll back earlier verified publication. Recovery after
a lost reply requires an actually committed original receipt and independently
retained original receipt ID and raw checksum. No automatic retry, signing,
authentication, orphan cleanup or atomic two-record promise is introduced.

Reopen takes only the workspace, independent original receipt manifest ID and
independent raw checksum. It preflights role/media/size before eager owner reads,
checks the complete selected chain/provenance, and reparses exact retained bytes
before returning records. Acquisition times do not change. A copied complete
workspace works after the caller file is removed; no model/scope creation,
source locator retrieval, clock, acquisition or file write occurs. The returned
`ackBasis` is `verified-present`, distinct from original caller ACK history.
The profile does not register new workspace evidence references or automatically
attach log records to reports; use the explicit original pins to inspect it.

See the
[operator guide](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/SYSLOG_SAVED_IMPORT.md)
for bounded wire fields, framing, SDK example, refusal/recovery and owner limits.
The file-read references do not authenticate an actor or authorize assessment.
No Core Event, incident, identity, compromise, applicability or scoring claim
follows from the source-only records.

::: fuzzy1337.syslog_artifacts
