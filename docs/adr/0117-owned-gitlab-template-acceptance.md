# ADR 0117: Owned real GitLab template acceptance

## Status

Accepted by the integration coordinator for the owner's finite M2/v0.3.0
completion. Actual platform acceptance remains unexecuted until its ordinary
pytest cohort and original evidence gate pass.

## Decision

Verify the public GitLab template with an actual disposable checksum-pinned
GitLab CE server and official runner on an admitted fresh Linux amd64 Docker
host. Require the existing measured four-CPU, 14-GiB RAM and 30-GiB free-storage
bounds before acquisition. Do not prune host resources or claim a hosted label
proves sufficient capacity. Use a fixed official digest-pinned Python base.

The server exposes only one loopback HTTP port. Its private local project runs
the exact public template through a real project-scoped shell runner and two
API-triggered pipelines: approval absent and explicitly approved. No GitLab
account, existing server, deprecated registration token or spoofed predefined CI
variable is used. Generated credentials remain private and are never arguments,
published traces or artifact contents. Refuse credential-bearing originals
instead of redacting them and claiming their bytes remained original.

The canonical Linux `LocalExecutor` owns the runner and its descendants in a
dedicated event-loop thread. A literal fixture request binds only the reviewed
runner binary/configuration and explicitly opted-in owned host; it supplies no
product scan permission. API polling cannot block that process owner. Stop and
join its original execution before deleting known job/server resources. Only
confirmed process and Docker-resource cleanup permits removing private controls;
uncertainty retains them and fails the cohort. No sibling process supervisor,
broad prune, numeric process-group cleanup or success-on-skip is introduced.

Bound acquisition, API reads, setup, pipeline polling and cleanup. Retain the
actual job/pipeline identities, unchanged uploaded ZIP, original trace and
verified source/model/evidence outcomes only after checking for generated and
recognizable credential bytes, including decoded ZIP members. Verify the exact
reopened model digest and all three original acquisitions independently.

Expose the real cohort as ordinary opt-in functional pytest. Missing required
resources or prerequisites fail when enrolled; local absence is explicitly
unexecuted. A focused Draft checkpoint diagnoses this one cohort. Final ready
integration and master runs use the same test and original-evidence gate.


## Exact runner acquisition contract

The first actual platform checkpoint failed before server launch because the
selected official runner binary is larger than the unrelated 128-MiB ceiling.
The original `HEAD` response for
`https://gitlab-runner-downloads.s3.amazonaws.com/v19.5.1/binaries/gitlab-runner-linux-amd64`
on 2026-10-29 reported exactly **141918698 bytes**, last modified
`2026-10-22T17:02:24Z`, S3 version `1wdJovmM9N0JvSEiX1jwqt94QIP4Nv.Y`.
The [official release index](https://s3.amazonaws.com/gitlab-runner-downloads/latest/index.html)
identified ref `v19.5.1`, provider revision
`f411f264f80a4870995a7c49482d02765e86c86e`, and the existing unchanged binary SHA-256
`0e11e71404352e67d286269aee397ec8e2825e0fc91a12f60c04cef0b85edb85`.
The index is a metadata provenance reference; acquisition continues to use the
fixed version URL, never `latest`.

Bind this one provider to its exact original byte count. The actual `GET`
response must declare the same exact `Content-Length` before its first body
read. During-read admission refuses an overrun; final admission requires exact
length and the unchanged vendor checksum before private file creation, mode
changes, verification or launch. No extra `HEAD` request is needed during each
cohort. The 60-second acquisition allowance, single 1500-second cohort allowance,
32-MiB API/trace/artifact cap and cleanup bounds remain unchanged. Deterministic
inert controls cover missing/wrong headers, truncation, overrun and checksum drift.
