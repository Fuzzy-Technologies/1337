# fuzzy1337.adapters.contracts

The Experimental version-one SDK requires typed request, invocation, execution,
report, evidence and normalized-output records at nested constructor boundaries.
Invocation/report/result envelopes and their members require exact concrete SDK
types; subclasses can add mutable serialized fields and are refused. Extend
providers through `ToolAdapter` and provider data through immutable attributes.
Ordered tuple/list/iterator inputs are detached; mutable mappings and duck records
are refused rather than retained inside a frozen envelope. Valid serialized field
shapes and values remain unchanged. These checks confer no source or execution trust.

::: fuzzy1337.adapters.contracts
