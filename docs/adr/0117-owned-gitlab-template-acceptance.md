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
