# Nuclei result fixtures

`result.jsonl`, `reviewed-get.yaml` and the Python fixture executables are synthetic
test material. They do not establish genuine provider acceptance.

`native-encoded-result.jsonl` is the exact stdout line retained from the real
checksum-pinned Nuclei 3.4.10 process against the repository-owned loopback SQLite
target. It contains only non-secret owned target data and provider metadata:

- Repository head: `55dd01ba0d69da0d39db3d33419d4f0a31cdce61`.
- [Workflow run 38819757543](https://github.com/Fuzzy-Technologies/1337/actions/runs/38819757543),
  job `116713181132`, artifact `12011699255`.
- Artifact ZIP SHA-256: `5dbdc5bc92d8a376e442681d40891e6811de17d45f050ad6571c6d1365953599`.
- Exact stdout SHA-256: `c11d2590352442185ccf65f653c7033245ceb2693975bcb7f7cb169d632c51e4`.

That run failed normalization after the exact approved request reached the owned
target and Nuclei reported its canary match. The `matched-at` field retains the
encoded request URL; native `url` and `path` are decoded input context. The
regression test preserves the captured bytes and parses them directly. For portable
normalization on Windows and POSIX, it creates a separate copied record with only
the optional `template-path` rebound to a current owned file; every URL, context,
match and provider field remains unchanged. The adapted record has its own evidence
digest and is not described as unchanged cross-platform native replay. Fixture
tests establish normalization only; the genuine functional lane must still prove
all positive and negative cases.
