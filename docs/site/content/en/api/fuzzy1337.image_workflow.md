# fuzzy1337.image_workflow

This Internal assembled consumer offers `ImageScanSelection` and
`RunSyntheticImageScan` for the closed reviewed image fixture, using accepted
artifact operations, owned jobs, canonical stores and existing report exporters.
Interpretation is delegated to the single Experimental
`fuzzy1337.synthetic_images.ApplyVerifiedSyntheticTrivyImages` owner; the small
`fuzzy1337.image_evidence` helper produces exact original operation captures.
It publishes a successful delta only after original model/workspace CAS saves.
Raw process/evidence facts survive failure, and a post-save storage failure keeps
the actual saved revision visible. Requested export has its own outcome and
atomic publication truth. Source remains `synthetic.trivy`; completeness remains
`not-assessed`. No native scanner, installation or arbitrary target is enabled.

`ImageScanSummary.captures` adds an optional trailing tuple after existing report
fields and carries both actual original typed VERSION/SCAN captures in memory.
The existing `ToDict()` JSON and detached operation summaries exclude this proof;
neither summary JSON nor retained bytes reconstruct current execution authority.
The CI consumer verifies the original pair, all six execution acquisitions,
exact saved source facts and current paired acceptance before applying its
explicit criterion. Original model/workspace saves and separate export
acknowledgement semantics remain unchanged.

See [Closed synthetic image workflow](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/IMAGE_WORKFLOW.md).

::: fuzzy1337.image_workflow
