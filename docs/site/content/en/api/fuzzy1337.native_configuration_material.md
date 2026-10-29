# Internal native configuration material observation

This observer owns one selected-read stage and fixed installed create/verify
helpers on supported Linux x86_64 ownership. Only the original observer accepts
its exact issued proof object. Proof binds the selection, read owner, workspace,
operation, original stage and scratch identity; copies and detached receipts
cannot acquire that association.

Each helper consumes one inclusive 12-second slot from the caller's existing
observation ledger: up to three seconds READY, six seconds worker and three
seconds cleanup. Control handling and response validation share that slot.
Cancellation settles the original helper and monitors before returning. Unknown
cleanup or changed material refuses proof and retains uncertain private state;
`Close()` removes only the exact known terminal generated tree.

See ADR 0109. Material proof grants no scanner execution, artifact-policy grant,
evidence acceptance or product SDK/CLI enrollment. Installed-helper acceptance
remains separate from genuine Trivy product acceptance.

::: fuzzy1337.native_configuration_material
