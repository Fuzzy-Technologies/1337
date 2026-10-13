# fuzzy1337.images

This Experimental contract interprets verified offline Trivy schema-2 image
reports and flat CycloneDX 1.6 package/license inventory through the existing
Security Object Model, evidence store and Finding lifecycle. It creates no
parallel store and performs no target execution or network access.

`ImageIdentity`, `PackageIdentity`, `ApplyVerifiedTrivyImages`,
`ApplyVerifiedSyntheticTrivyImages`, `VerifySyntheticTrivyImageReplay`,
`ApplyVerifiedCycloneDx` and exported version/resource constants form the supported
surface. Other helpers remain Internal. Image config/manifest digests are distinct;
package identities include exact installed version and qualifier context.
The Internal `TrivyCandidates` helper constructs a pure candidate batch only after
the native wrapper's unchanged evidence/version checks; it grants no acceptance
and exposes no caller-selected namespace.
The Internal `SyntheticTrivyCandidates` helper constructs the closed fixture's
isolated asset, relation, observation and Finding candidates. It performs no
evidence admission, authorization, model application or persistence.
The separate synthetic importer uses
original typed VERSION/SCAN proof, six exact stream/receipt roles and the canonical
fresh pair facade. Every fixture asset/Finding/reference has its fixed synthetic
namespace, preserving colliding native objects and triage. Historical replay
returns original immutable SCAN attribution without live acceptance or writes.
Manifests/bytes and their source/workspace/scope/execution attribution are verified
before returning one in-memory transition. Scanner accuracy, signature/cache
attestation, complete PURL support, SPDX and nested component profiles are outside
this delivery. See [Image normalization](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/IMAGES.md).

::: fuzzy1337.images
