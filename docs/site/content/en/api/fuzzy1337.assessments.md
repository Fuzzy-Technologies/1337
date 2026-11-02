# fuzzy1337.assessments

Experimental pure five-level interpretation of an explicitly supplied CVSS base
score through the required, pinned FuzzyRoutines 2.1.0 public UFS API. The source
score, normalized input, five original membership grades, selected label and
library/scale/rule versions remain separate and reproducible. Missing input stays
unknown; boolean, nonfinite and out-of-range inputs are refused.

Memberships are not exploitation probabilities, conventional CVSS categories or
action priorities. This presentation changes no Finding severity, triage, evidence
or saved model/report schema. ADR 0122 and `docs/FUZZY_ASSESSMENTS.md` describe the
bounded pilot; composite contextual risk remains later work.

::: fuzzy1337.assessments
