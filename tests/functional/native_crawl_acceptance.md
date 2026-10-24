# Genuine native crawl acceptance source

These ordinary pytest runners require the actual current package built offline
and installed into a clean interpreter. Required build, worker, SDK, CLI or local
execution capabilities fail when absent. There are no required-acceptance skips,
fake executor results, synthesized worker success or production-parser oracles.
The source checkpoint collected 28 cases without running any fixture or case.
Actual installation, listeners, workers, SDK/CLI execution and acceptance remain
unexecuted until the coordinator authorizes the reviewed coherent revision.

After that authorization, the focused selection is:

```bash
python -m pytest tests/integration/test_native_crawl_worker_execution.py tests/functional/test_native_crawl_product.py --no-cov -n 0
```

The module-scoped installation fixture builds the current checkout wheel and
installs it offline without dependencies. Each installed consumer gets isolated
owned HOME, XDG and temporary directories. The SDK consumer proves its import is
from the clean installed package. It observes actual LocalExecutor returns and
actual model CAS acknowledgements, returning the original objects unchanged.
The lost-ACK case deliberately raises only after a real acknowledged model Save;
it must preserve the actual committed state and fail without a retry.

The worker suite sends one canonical ASCII JSON argv argument to the fixed
isolated module with closed stdin. It compares original GET bytes, complete
actually sent response/body hashes, exact worker streams, independently
handwritten slots/exclusion counts and closed refusals. The source input and
truth do not use production builder/parser helpers or schema example fixtures.

The SDK suite changes live bytes at the same seed URL while the admitted set
stays fixed. It compares unique contacts by depth-wave membership, preserving
actual within-wave arrival order as evidence. Only model Save/completion order
is lexical and fixed. Positive acceptance requires measured sibling overlap and
B-before-A completion. Existing structural request variants and unrelated
Endpoint attributes must survive complete request collection merging. Original
stdout/stderr/control records bind the actual execution and acknowledgements;
no retained HTTP-body evidence is invented. Reopened canonical state is compared
independently. The fixture's second owned origin directly measures forbidden
off-origin contact, including empty/partial accepts, after both owners clean up.

Fresh registration/IP/exclusion/consent/policy/owner/approval denial requires zero
actual accepts and no real worker or model Save. A trusted reader changes after
a real grant or successful original worker; post-worker drift must preserve
original custody and deny model Save. The crawl consent attester differs from
the fixed executing owner. CLI cases prove only default selected attribution;
they make no external authentication or trusted-reader drift claim.

A separate Git scope preserves the existing checker's requirement that its
selected owner equal its recorded consent attester. Crawl approval is never a
STANDARD Git grant or exact-plan confirmation. Actual positive/fixed/HTML-decoy/
redirect jobs score saved Findings as TP1/TN3 only after completion; failed work
stays unassessed in the persisted matrix. Operator triage must survive actual
rerun and reopen. Legacy exact-URL Git Endpoints stay distinct from structural
crawl Endpoints. The existing checker is unchanged.

The installed CLI suite uses `scan crawl`, repeated explicit `--selected` URLs,
separate `--plan`/`--approve-safe-crawl`, JSON output and actual workspace reopen.
Redirect work must return failed status and retain truthful partial state.
Every case preserves original consumer output and target contact facts under
its pytest-owned evidence directory. Shared full integration CI and any release
remain separate coordinator-owned gates.
