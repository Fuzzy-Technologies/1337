# Reporting contract fixtures

The four `snapshot.*` files contain deterministic first-party synthetic report
projections. They preserve failed acquisition metadata and all four finding
dispositions. No target is scanned, external catalog membership is asserted, raw
artifact is included, or human approval is manufactured. Format changes require
an explicit review of the corresponding golden diff and independent semantic
assertions; tests never rewrite these files automatically.

`sarif-schema-2.1.0.json` is the unchanged official OASIS SARIF 2.1.0 schema:

- Source: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json>.
- SHA-256: `ad6db49878699b091f3eeb765b6e29e92a34bad4da88664d000c923b549c3a25`.
- Published version: OASIS Standard, 2020-03-27.
- Specification and notices: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html>.

The official schema remains unchanged and is used only by deterministic offline
tests. Validation uses its declared JSON Schema draft. Project runtime exports
load no schema, network service, or third-party executable.
