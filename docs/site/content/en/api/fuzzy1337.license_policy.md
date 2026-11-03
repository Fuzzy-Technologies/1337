# fuzzy1337.license_policy

This Internal module matches a finite SPDX 2.3.1 expression grammar against a
caller-authored atom table. It is not a supported Python extension contract.
Use the Experimental opt-in installed `1337 sbom image --license-policy` route
for original-source verification before interpreting a saved assertion.

`LicensePolicy` rejects implicit, conflicting and compound atom rules. Its
normalized description includes the caller ID, complete allowed/denied atom
sets, the `spdx-expression-policy-v1` profile and a canonical SHA-256 digest.
`EvaluateLicenseExpression` consumes the complete bounded expression, preserving
unknown atoms and distinguishing exact version/exception pairs. It uses no
license database and creates no compliance result, Finding or persistence.

The product route reparses original owned SPDX graph sources and preserves
declared/concluded roles separately. Omitted/NONE/NOASSERTION information,
unsupported profiles and unconfigured atoms remain unknown. See
[the selected policy contract](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/adr/0125-sbom-license-expression-policy.md).

::: fuzzy1337.license_policy
