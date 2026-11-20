# ADR 0148: Verified offline image layer attribution

## Status

Proposed — 2026-11-18. Design slice for
[M4 task #377](https://github.com/Fuzzy-Technologies/1337/issues/377).

## Context

[ADR 0040](0040-verified-image-package-normalization.md) preserves the original
provider-observed DiffID order. [ADR 0112](0112-read-only-image-sbom-view.md)
projects image/package containment. An ordered DiffID list and package
membership alone leave the origin of individual files and packages unknown.

## Proposed decision

Add an opt-in Internal read-only projection over one explicitly selected
config image, one retained Docker-save export and one admitted native Trivy
schema-2 container-image report. Reuse the existing workspace, model, evidence,
[native image admission](0093-governed-native-image-product-workflow.md) and
[local image export](0114-governed-local-image-reference-export.md) owners.
The projection operates on their existing records and saved snapshot. The
ordinary image inventory, evidence, model and execution contracts remain the
source of truth.

Verify two original acceptance chains in the selected workspace before using
the retained export and report as inputs to the projection. The local image
export owner verifies the completed inspect, save and reference recheck under
ADR 0114, including the original stdout and its recorded scope, acquisition
and execution. A refused, incomplete or reassigned export remains ineligible
even if its retained stdout is a complete archive.

The native image replay owner verifies the accepted original VERSION and SCAN
receipts and all six original capture roles under ADR 0093. Require the SCAN
receipt to bind the accepted original VERSION prerequisite. Match the complete
retained archive's SHA-256 and byte length to the exact archive INPUT in the
original SCAN receipt. These checks verify recorded custody and execution
facts without seeking live authorization. Require the original admitted report,
exact config image, original package occurrence and canonical package membership
on the selected saved basis. A same-tag, same-package or config-only match
supplies no archive association. Recheck the saved workspace and model bases
before returning the complete projection.

### Digest domains and layer order

- Archive SHA-256 identifies the complete retained Docker-save tar. The
  artifact input manifest SHA-256 identifies the artifact manifest.
- The config digest is SHA-256 of the exact original config member. Verify it
  against the selected config identity and the original report's config ID.
- The distribution manifest digest identifies exact distribution manifest
  bytes. Docker-save `manifest.json` supplies local member order. A manifest
  selection or provider-reported manifest alias supplies no attribution in
  this profile, including when its hash bytes equal the selected config ID.
- The layer DiffID identifies the complete uncompressed layer tar stream.
  A distribution layer descriptor digest identifies its blob bytes in its own
  domain. This profile accepts ordinary uncompressed layer members and never
  substitutes a descriptor digest for a DiffID.

Use the sole Docker-save manifest entry's `Layers` array from base to top,
paired by index with the verified config's `rootfs.diff_ids`. Require equal
lengths and recompute each DiffID over the corresponding complete tar member.
Any ordered report DiffID list supplied in this digest domain must agree with
this verified order. Keep zero-based ordinals and repeated DiffIDs. A digest-only
source claim that matches multiple ordinals remains ambiguous. History entries
and member enumeration supply no ordering authority.

### Attribution and limits

Project original `Results[]/Packages[]` occurrences only. A package layer
requires an explicit source `Layer.DiffID` with one verified matching ordinal.
When the occurrence also supplies a supported `FilePath`, require an agreeing
file layer before returning the package attribution. A file layer comes from
the topmost visible ordinary file at that exact image-relative POSIX path.
Apply ordinary whiteouts and opaque directories to lower layers before applying
writes in the current layer. An ordinary file that replaces a lower-layer
directory removes all of that directory's lower-layer descendants from the
visible namespace. A later directory replacing that file starts with an empty
subtree. Descendants become visible only through explicit writes in that layer
or subsequent layers. Keep source package association and archive file supplier
as distinct facts. A package-related path proves neither ownership of other files
nor installation history.

Use bounded in-memory tar reads with no extraction or link following. Initially
admit ordinary files, directories and canonical empty whiteout markers. Refuse
unsafe or conflicting archive structures, including duplicate paths within
a layer, any ordinary file with a descendant member in the same layer regardless
of member order, and unsupported member types. Absent source fields, unsupported
source paths, hidden or absent files and missing or ambiguous joins produce an
explicit `unknown` attribution with a bounded reason. Invalid selected original
custody, a contradictory required digest/order binding, changed saved bases or
exceeded quotas refuse the whole projection.

Return the pinned saved revision and snapshot hash, exact original acquisition
references and package coordinates, and, when established, layer ordinal and
DiffID plus the original file member coordinate. Bound the archive by the
existing 64 MiB limit, use the existing report/evidence and source limits, and
cap this profile at 256 layers, 65,536 total layer entries, 4,096 occurrence
rows and 1 MiB serialized output. Keep raw paths and provider text in original
evidence. The projection performs local read-only replay without collection,
scanner execution, runtime access, network requests or persisted updates.

## Data-only acceptance

1. Independently hand-author a two-layer archive and report oracle with a base
   file, a top-layer replacement and a unique package DiffID claim. Assert the
   exact ordered digests, supplier ordinals and source coordinates.
2. Cover a deleted file, an opaque directory with a same-layer write, a repeated
   DiffID, missing source fields and a package/file ordinal disagreement.
   Assert the individual known and unknown outcomes.
3. Use base files `app/a.txt` and `app/sub/b.txt` and an ordinary file `app` in
   layer 1. Assert that `app` resolves to ordinal 1 and both descendants have
   `unknown` attribution. Add a layer 2 directory `app` and an explicit write
   to `app/a.txt`. Assert that `app/a.txt` resolves to ordinal 2 and file
   attribution for `app` and `app/sub/b.txt` is `unknown`. Refuse the complete
   projection if an ordinary file `app` and `app/a.txt` occur in the same layer,
   in either member order.
4. Reject swapped or tampered archive/receipt bytes, corrupted config or layer
   bytes, inconsistent order, unsafe paths and each quota boundary. Assert
   that a same-value manifest or descriptor digest yields no config/layer join.
   Refuse a complete archive retained by a refused or reassigned export and
   an archive whose length or SHA-256 differs from the original SCAN INPUT.
5. Replay from a relocated saved workspace after removing the original selected
   paths. Check deterministic output, unchanged owner bytes and complete
   refusal on snapshot change. Exercise the no-write and no-network boundaries.
