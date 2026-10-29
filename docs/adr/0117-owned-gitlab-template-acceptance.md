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


## Private bootstrap transport

GitLab's Rails runner uses its `git` account, so it cannot read the host's
owner-only runner-control directory. Keep that directory at mode 0700 and remove
the whole-private read-only server bind mount and bootstrap credential/script
files. Send the fixed bootstrap Ruby program only through private process input
using `docker exec -i <owned-server> gitlab-rails runner -`. The generated token
must match the existing twenty-character lowercase hexadecimal grammar before
being encoded as one Ruby string literal. It never enters argv, environment,
public output or an authentication-bearing host file. Command failures retain
only the existing generic refusal, and public originals retain the existing
credential screening.

GitLab documents the non-root Rails runner and its file-access requirement in its
[operations guide](https://gitlab.com/gitlab-org/gitlab/-/blob/7c942a985f91fcd2c3ad1004d54f98a3c6d6acf6/doc/administration/operations/rails_console.md).
Rails documents `runner -` as its platform-independent standard-input interface
in the [Rails 5.2 release notes](https://guides.rubyonrails.org/v6.1/5_2_release_notes.html#railties).
This transport correction changes no scope, resource budget or bootstrap command
allowance and makes no actual platform acceptance claim.


On readiness failure, retain a fixed phase/category/elapsed-time record and
request only the original server's exact ID/name plus Docker status, running
flag, OOM flag, exit code and restart count. Validate identity and the finite
safe field set before publishing unchanged selected metadata. Never acquire
aggregate configuration/state, environment, health output, GitLab logs or an
initial root password. Diagnosis uses the remaining existing cohort allowance;
a failed diagnostic cannot manufacture readiness or replace the original
failure, and owned cleanup still runs.


## Container-local dependency readiness

The host-published monitoring route timed out in an actual checkpoint. GitLab's
[health-check documentation](https://docs.gitlab.com/administration/monitoring/health_check/)
and [monitoring IP allowlist](https://docs.gitlab.com/administration/monitoring/ip_allowlist/)
make a Docker bridge source address an unsuitable assumption for a localhost-only
monitoring route. This is a source-based explanation, not evidence that the
previous run observed HTTP 403; that run retained no status receipt.

Probe `http://127.0.0.1/-/readiness?all=1` **inside the original server container**
without widening the monitoring allowlist. The pinned package's own
[health-check implementation](https://gitlab.com/gitlab-org/omnibus-gitlab/-/blob/fix-geo-ci-setup/config/software/gitlab-healthcheck.rb)
uses `/opt/gitlab/embedded/bin/curl`; use that explicit vendor path. Bind the
original server ID, existing explicit daemon and private Docker configuration.
The private bootstrap and published-port observation bind that same created ID,
so neither can resolve a replacement container through its mutable name.
Disable curl configuration/proxies, follow no redirects, discard the body, and
retain only its exact three-digit status. Require 200; only 000 transport startup,
502 and 503 remain pending. Other statuses, missing curl and Docker execution
failures are terminal. Admit a nonzero curl transport exit only for its exact
reviewed invocation and an original `000` status; generic command failures remain
refusals. Keep the existing 900-second boot and 1500-second cohort deadlines,
five-second outer probe, four-second transfer and one-second connection limits.
