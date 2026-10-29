# Frozen original schema-1 artifact replay

These bytes were collected by an independent reviewer using the unchanged
`8e7d40a` artifact SDK and its owned lifecycle fixture before the schema-2
migration. Both physical stage and workspace were removed before replay testing.
They are intentionally immutable compatibility fixtures, not reusable authority.

The source was only `owned-input`, the original reviewed lifecycle worker and
current trusted CPython under explicit `owner:test`/`attester:test` fixture scope.
No target was contacted. The captured process stdout, empty stderr, original
metadata, physical marker facts and random run/grant references remain exact.
Do not regenerate this fixture with operation-aware dataclasses or new grants.

| Original fact    | Frozen value                                                                              |
| ---------------- | ----------------------------------------------------------------------------------------- |
| Metadata SHA256  | `4e5d538f3630757eadd2cbcd8be077a7f5471c46585d8594bae9f7da64334563`                        |
| Stdout SHA256    | `76613b243099e09fda13117811c3651bc1918cc3772da07fd0601e8c5106c333`                        |
| Intent SHA256    | `b925f262e2e4a2c572d54da63a3f7b6daeeaa1c0c737c538f8287409d3ad2295`                        |
| Authorization ID | `artifact-authorization:0bba640c5ae94c199965befa14321f03b5fb5851bb29a855e54af479385a7044` |

Verification hashes the original schema-1 field shape. It reads no current
physical stage, issues no grant and does not infer VERSION or a richer family.
The contract regression rejects schema-2 fields injected into the old record.
