# fuzzy1337.path_analysis

This Experimental profile-v1 library explains an explicit verified reachability
projection against its exact canonical model basis. `AnalyzeReachabilityPaths`
retains original bounded paths and attributes node/relation participation and
single-removal leverage to the returned candidates. Truncated counts remain
sample-only. A separate bounded walk checks structural choke points over the
selected non-BLOCKED graph; an exhausted budget leaves the conclusion unknown.

`PathAnalysisLimits` bounds that independent work. `PathSemanticGroup` declares
disjoint presentation memberships while retaining every original member and
transition. The grouped view never becomes a traversable quotient graph. Result
constructors and helper functions are Internal.

ADR 0066 and `docs/PATH_ANALYSIS.md` define the selected-graph boundary. This pure
library performs no I/O, changes no model identity, and grants no execution
authority. Structural leverage does not establish exploitability or risk reduction.

::: fuzzy1337.path_analysis
