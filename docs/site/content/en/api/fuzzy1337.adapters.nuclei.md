# fuzzy1337.adapters.nuclei

This Experimental optional adapter prepares finite reviewed local HTTP templates
and normalizes verified raw JSONL through existing ToolAdapter SDK envelopes.
`CheckHealth` runs only a bounded local version probe. Target execution requires
separate upstream authorization and the existing governed executor.

`NucleiAdapter`, `NucleiTemplate`, `NucleiProfile`, `NucleiReportError` and declared
budget constants form the supported surface. Implementation helpers remain
Internal. The external Nuclei executable and reviewed templates are operator
supplied and are not bundled with the base Workbench. Review metadata and digest
checks do not substitute for semantic review or a network sandbox.

::: fuzzy1337.adapters.nuclei
