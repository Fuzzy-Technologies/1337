# fuzzy1337.adapters.trivy

This Experimental optional adapter prepares one finite SAFE offline image archive
vulnerability scan and normalizes verified raw schema-v2 JSON through the accepted
ToolAdapter SDK. A separate executor authorization is required to run the scan.

`TrivyAdapter`, `TrivyReportError`, `TrivyHealthProbe` and declared resource budget
constants form the supported surface. Parsing, file validation and evidence
helpers remain Internal. Trivy and its offline database cache are operator
supplied; registry and local daemon image references remain deferred.

`ProbeHealth` returns exact bounded version stdout for separately attributed
immutable evidence. Success requires matching tool version and provider-observed
DB metadata; failed execution never produces successful findings. The adapter
does not persist state or provide process/filesystem/network sandboxing.

::: fuzzy1337.adapters.trivy
