# fuzzy1337.report_commands

Internal foreground CLI/shell consumer of the existing workspace, model, scope,
evidence and report owners. Its house-style helpers are not new public SDK APIs.
ADR 0049 and ADR 0077 define bounded JSON/SARIF/HTML/JUnit publication and failure truth.
No command starts a scan or establishes source success or scan completeness.

All four explicit formats consume the same exact owner-verified saved snapshot.
HTML and JUnit delegate to the existing pure SDK renderers; the outcome format
enum grows additively at schema version 1. Report publication exits zero even
when the JUnit artifact contains retained failing Finding cases. Original triage,
failed-source facts, quotas and no-clobber/post-link acknowledgement truth remain
unchanged. Export neither reads current authority as permission nor acquires data.

::: fuzzy1337.report_commands
