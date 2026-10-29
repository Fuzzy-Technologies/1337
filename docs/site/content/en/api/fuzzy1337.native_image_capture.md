# Internal native Trivy capture

This Internal producer collects independent actual VERSION and SCAN executions
through the bounded existing local executor. Explicit read consent and exact
caller-issued invocation authorization remain required. Selected binary,
database and archive facts are checked before and after collection.

Original stdout, stderr, terminal execution and invocation provenance retain
their own immutable records. SCAN association requires the original successful
VERSION with the same owner and selected material, including its receipt's
original provenance. Observed version never rewrites the original invocation.

ADR 0058 and `docs/TRIVY_ACCEPTANCE.md` define the restricted custody prerequisite.
It issues no native artifact product grant and performs no model persistence;
the legacy health-only import contract remains separate.

The additive bounded collector described in ADR0094 uses a fixed owned material
helper, opaque observation proofs and durable original-outcome custody. See
`docs/NATIVE_IMAGE_OBSERVATION.md`; historical capture defaults remain unchanged.

::: fuzzy1337.native_image_capture
