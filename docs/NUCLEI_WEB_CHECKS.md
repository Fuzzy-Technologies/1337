# Reviewed web response checks

The development candidate ships three first-party response checks in
`fuzzy1337/data/nuclei/`. They use the existing optional
[Nuclei workflow](NUCLEI_WORKFLOW.md) and its reviewed
`single-get-exact-url` profile. Every selected template sends one GET to the exact
operator-supplied URL. It adds no path, query, credential, payload sequence,
redirect, executable expression, callback or other protocol.

The pack is original project material. It contains no legacy scanner code,
signature collection or copied check implementation. Its versioned
`manifest.v1.json` records exact artifact sizes, SHA-256 digests and review
references. These bind reviewed bytes; they are not signatures or execution
permission. The package includes the YAML and manifest resources.

## Implemented response predicates

| Template ID                             | Required response facts                                                                 | Interpretation limit                                                    |
| --------------------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `fuzzy1337-git-head-exposure`           | HTTP 200, plain/octet-stream media type, complete supported symbolic Git HEAD reference | Exposed metadata; no source-recovery or credential-exposure claim       |
| `fuzzy1337-owned-sql-canary-disclosure` | HTTP 200, JSON media type, exact `rows` object containing only `owned-private-row`      | Owned read-only canary disclosure; not a general SQL injection detector |
| `fuzzy1337-unsafe-html-reflection`      | HTTP 200, HTML media type, inert raw probe in the selected `main` element               | Candidate unsafe HTML reflection; no browser execution or proven XSS    |

Git reference components are a deliberately bounded subset: one through eight
slash-separated components, each one through 64 ASCII letters, digits, underscores
or hyphens, beginning with a letter or digit. Dotted, Unicode and detached HEAD
forms are not assessed. The response body must contain the complete reference,
so an HTML documentation example does not satisfy this predicate.

The SQL check recognizes a non-secret row owned by the acceptance target. The
actual target executes a read-only SQLite query: the vulnerable route interpolates
the selected path value, while the fixed route uses a parameterized query.
Independently approved baseline, true, false, fixed and documentation-decoy cases
establish that target's real mechanism. Each case remains a separate exact-URL
invocation with separate authorization and evidence. This pack performs no generic
parameter discovery, adaptive payload generation, response-difference inference,
database writes, timing attack or arbitrary data extraction.

The reflection check uses the inert
`<fuzzy1337-probe>owned</fuzzy1337-probe>` element in an exact selected response
context. The fixed route HTML-escapes the input; the decoy puts it in a comment.
Matching this response does not establish JavaScript execution, arbitrary HTML
parser context, browser security-policy bypass or exploitability.

## Select existing product interfaces

Read installed resources through `importlib.resources.files("fuzzy1337")`, then
select one manifest entry and construct the existing `NucleiTemplate` and
`NucleiProfile` objects. For an ordinary filesystem installation, this example
materializes an explicitly selected Git-check profile in a new operator-owned
directory without granting target access:

```python
import hashlib
import json
from importlib.resources import files
from pathlib import Path

from fuzzy1337.adapters import SerializeContract
from fuzzy1337.adapters.nuclei import NucleiProfile, NucleiTemplate

pack = files("fuzzy1337").joinpath("data/nuclei")
manifest = json.loads(pack.joinpath("manifest.v1.json").read_text(encoding="utf-8"))
record = next(item for item in manifest["templates"] if item["family"] == "git")
raw = pack.joinpath(record["filename"]).read_bytes()
assert len(raw) == record["size_bytes"]
assert hashlib.sha256(raw).hexdigest() == record["sha256"]
owned = Path("owned-web-check-profile").absolute()
owned.mkdir()
template_path = owned / record["filename"]
template_path.write_bytes(raw)
configuration = owned / "empty.yaml"
configuration.write_bytes(b"{}\n")
template = NucleiTemplate(
    record["template_id"], str(template_path), record["sha256"], record["size_bytes"],
    record["source_reference"], record["source_revision"], record["review_reference"],
    record["reviewed_profile"],
)
profile = NucleiProfile("selected-git-check", (template,), str(configuration))
(owned / "profile.json").write_text(SerializeContract(profile), encoding="utf-8")
```

Keep those files and the selected executable immutable through the operation.
Supply the resulting profile to `1337 scan nuclei` with an initialized workspace,
current explicit URL/IP scope, owner and STANDARD capability policy. First use
`--plan`; execute only with the exact reviewed intent digest and a separate
confirmation reference, as documented in the workflow. The package never infers
permission from a template, payload or known target path.

SQL and reflection input is already part of the explicitly selected path. The
template generates no additional request. Existing canonical URL checks remain
unchanged: queries, fragments, credentials and ambiguous traversal encodings are
unsupported. A rejected traversal request is not assessed; it is not a successful
negative vulnerability result. The pack does not expand native discovery's
status-only records or the reviewed page-capture catalog.

## Genuine acceptance and retained evidence

The independently authored
[web-vulnerable target](../labs/targets/web-vulnerable/README.md) and handwritten
oracle supply file-backed Git disclosure, real read-only SQLite behavior and
raw/escaped HTML responses. Fixed, decoy, baseline, false and redirect cases are
explicit negatives. Redirect acceptance checks the actual request log to prove
that the vulnerable destination was never followed.

The functional consumer uses a genuinely installed Nuclei binary through
`PlanNucleiScan`, explicit `PolicyConfirmation`, `RunNucleiScan`, governed jobs,
the owning evidence store and canonical Findings. Template IDs and actual saved
findings determine detections; expected results never manufacture matches.
Missing confirmation produces no target request, raw provider stream or finding.
Raw stdout/stderr retain provider version and invocation digest. Persisted model
observations retain template hash, source, review and profile identity. Findings
remain open with unknown confidence, and workspace/report reopen rechecks actual
evidence integrity.

```bash
FUZZY1337_NUCLEI_BINARY=/absolute/path/to/nuclei \
  uv run --locked --extra dev pytest \
  tests/functional/test_nuclei_web_checks.py -o addopts='' -q
```

The shared native CI lane supplies the checksum-pinned upstream binary. Absence
of the explicit binary is a skip, never native acceptance. Local YAML/regex
contracts validate artifacts and matcher examples only; they do not substitute
for the actual scanner execution.

`functional-evidence/nuclei-web-checks/` preserves actual plans, terminal summaries,
raw acquisitions, independent target observations and the generated JSON,
Markdown and HTML matrix. Confusion counts use only the finite oracle. Failed
runs withhold accuracy, and untouched cases remain `not-run`. A successful empty
provider output is zero reported matches, not target safety or broad check coverage.

General differential SQL injection, arbitrary crawling, native body acquisition,
browser/DOM execution, SSRF and traversal checks remain outside this pack. There
is no asserted ATLAS detection coverage or automatic standards classification.
Taxonomy relationships require separately reviewed source mappings and do not
prove an attack occurred.

The reviewed request and matcher forms follow the primary
[Nuclei HTTP](https://docs.projectdiscovery.io/templates/protocols/http/basic-http)
and [matcher](https://docs.projectdiscovery.io/templates/reference/matchers)
contracts. Authority and persistence remain governed by
[ADR 0030](adr/0030-reviewed-optional-nuclei-adapter.md),
[ADR 0055](adr/0055-explicit-standard-nuclei-workflow.md) and the existing
[functional metrics contract](adr/0018-oracle-derived-functional-metrics.md).
