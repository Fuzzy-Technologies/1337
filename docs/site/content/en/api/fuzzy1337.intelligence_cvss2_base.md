# fuzzy1337.intelligence_cvss2_base

Experimental pure CVSS 2 base calculation accepts only original immutable
`CveCvss2Statements`, retaining the source inspection once with a separate
ordered frozen calculation per assessment. Each value has its assessment
position, algorithm `cvss2-base-2.10` and integer score in tenths; the public
constructor accepts no calculated fields. `DisplayScore()` renders exactly one
decimal digit.

Exact integer arithmetic implements FIRST equation 2.10 with final rounding
only, an explicit zero-impact branch, and no intermediate rounding or impact
clamping. Source vectors, asserted scores, context and snapshot bytes remain
unchanged. Optional metrics do not create temporal/environmental results. No
source correction, severity conversion, target matching, network execution or
publisher authentication follows.

`docs/INTELLIGENCE_CVSS2_BASE.md` and ADR 0107 define the bounded calculation
contract, finite-domain rounding evidence and separate source/derived output.

::: fuzzy1337.intelligence_cvss2_base
