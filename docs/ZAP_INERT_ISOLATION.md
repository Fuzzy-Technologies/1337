# Closed inert isolation prerequisite

[ADR 0096](adr/0096-closed-inert-isolation-proof.md) freezes the test-only boundary. The exact
closed Linux x86_64 candidate has a verified eight-case genuine CI proof. Shared final
integration is pending at this candidate checkpoint. Java/ZAP runtime and its production
provider/SDK/CLI integration remain unimplemented.

## Verified closed candidate

On 2026-10-24, [CI run 40064389957, job 120784462270](https://github.com/Fuzzy-Technologies/1337/actions/runs/40064389957/job/120784462270)
executed all eight named cases: **8 passed, 0 failed, 0 errors, 0 skipped**. The receipt binds
candidate commit `ccade599cab92c08a21f6a4eeefc2fe3f4ff7e3e` and source tree
`55ec16b27f14655e7908f110d37ef5907c273ce7`. The observed hosted Ubuntu 22.04 image was
`20261012.322.1`, kernel `6.8.0-1064-azure`, with original host UID 1001.

| Case        | Actual termination / state | Exit | Original late-file custody |
| ----------- | -------------------------- | ---- | -------------------------- |
| Normal      | process_exit / succeeded   | 0    | Complete                   |
| Byte quota  | process_exit / succeeded   | 0    | Complete                   |
| Inode quota | process_exit / succeeded   | 0    | Complete                   |
| Timeout     | timeout / timed_out        | -9   | Complete                   |
| Cancel      | cancellation / cancelled   | -9   | Complete                   |
| Peer kill   | cancellation / cancelled   | 137  | Complete                   |
| Deny        | cancellation / cancelled   | -9   | Incomplete; no ACK         |
| Missing     | cancellation / cancelled   | -9   | Incomplete; no late file   |

All eight verified final READY, confirmed owned cleanup and zero host-sink contacts. The peer-kill
case observed direct original-pidfd SIGKILL and peer exit; its actual cancellation classification
and exit 137 remain recorded. Deny refused current authority before ACK. Missing reached the
post-ACK pause without creating the late report. These two expected incomplete custody outcomes
passed their refusal oracles; they did not become successful capture results.

This receipt verifies the closed candidate composition only. It does not complete the shared
final PR gate, establish broader platform support, or implement JVM/ZAP material closure,
engine reports, queue behavior, product SDK/CLI integration or provider enrollment.

## Pinned helper and build

Bubblewrap 0.13.0 is pinned to commit
`719a4fd474d44b26906bcf2b1b0fb6eddd8d56d0`, annotated tag object
`52d23329a689f64a8b601f8b999affb69b9339ac`, and the official release archive
<https://github.com/containers/bubblewrap/releases/download/v0.13.0/bubblewrap-0.13.0.tar.xz>.
The archive must be exactly 129,260 bytes with SHA-256
`4734237473c0e5d695e4e9034a34e43b2dbf5164655bd13fa59ae376b2b7a765` before extraction.
Upstream files and LGPL notices remain unchanged; no upstream source is copied into the
Apache-2.0 first-party fixture.

The separately bounded ordinary CI dependency step may install `build-essential`, `libcap-dev`,
`meson`, `ninja-build` and `pkg-config`. It may not upgrade the host or run upstream
`ci/enable-userns.sh`, which changes host security policy. Compile/install into a private prefix
as the original nonroot runner, with wrap downloads disabled, SELinux/man/completions/upstream
test build/debug logging disabled and an explicit absolute Python. Record actual toolchain,
libcap, image, kernel, source and binary hashes. This is provenance, not a hermetic-build claim.

The first-party fixture builds only with `gcc -static -std=c11 -O2 -D_GNU_SOURCE`. Require
ELF64 x86_64, no PT_INTERP or DT_NEEDED, trusted owner, no SUID/SGID/file capabilities and no
group/world write. Compilation and ELF inspection do not execute it or prove isolation.

The closed owner holds at most nine proof descriptors in addition to standard streams and
executor-owned internals: listener, accepted stream, original directory, direct peer pidfd,
operation directory, two owned host sockets and at most two short-lived custody handles.
Bootstrap has four typed O_PATH slots and at most one temporary handle. The final fixture
starts with only standard streams; at READY its fixed control FD is 4 and a just-consumed
quota FD 3 may transiently remain while sendmsg returns. Known-peer descriptor inspection
rejects any other inherited descriptor. The recorded candidate exercised this closed contract;
new revisions and environments still require the applicable exact-revision acceptance.

## Evidence and refusal

Only the eight closed cases in ADR 0096 are accepted. The first serial normal case must prove
actual rootless support, direct peer pidfd, namespace/mount/alias restrictions, private loopback,
late-file creation and post-cleanup original read. Missing support fails required CI promptly.
Later independent cases use two workers and finite per-test/job ceilings. No live LLM is called.

Normal/quota workloads keep their actual private listener open through `WORK_COMPLETE` and a
fixed original-pidfd SIGUSR1 release, using a blocked signal and atomic sigsuspend wait. Host
refusal precedes that release. Success requires the marker, release, actual exit zero and owned
cleanup. Stop cases use the original timeout/cancellation/direct-peer SIGKILL and actual
post-setsid child readiness; they do not use normal release or fixed sleeps.

Record actual termination, cleanup, quota/namespace observations, denied syscall errors, host
socket counters, the original late-file identity/hash and test evidence. A failed execution may
retain useful original bytes while remaining failed. Sentinel-only retention remains incomplete.
Caller cancellation after ACK still settles the same original task before the first late read.
The original cleanup/custody/owner deadlines remain 20/28/30 seconds. A pending or unknown
cleanup retains the original task, directory, direct peer pidfd and owning test loop instead
of manufacturing a terminal result or closing the live recovery identity. Already-read bounded
bytes may remain in an incomplete outcome. Test artifact failures preserve available admitted
staging and recovery ownership; no replacement execution or publication retry is attempted.
Only confirmed original settlement permits explicit disposal. This handoff is volatile within
the original process; no crash/power-loss recovery or future production receipt is established.
No test result establishes a production receipt, successful ZAP engine or zero Findings.

## Primary sources

- [Pinned bubblewrap options](https://github.com/containers/bubblewrap/blob/v0.13.0/bwrap.xml)
- [Pinned bubblewrap implementation](https://github.com/containers/bubblewrap/blob/v0.13.0/bubblewrap.c)
- [Linux tmpfs limits](https://docs.kernel.org/filesystems/tmpfs.html)
- [Unix socket ancillary data](https://man7.org/linux/man-pages/man7/unix.7.html)
- [Linux 6.5 direct peer pidfd implementation](https://github.com/torvalds/linux/blob/v6.5/net/core/sock.c)
- [Directory FD semantics](https://man7.org/linux/man-pages/man2/open.2.html)
- [Candidate runner inventory](https://github.com/actions/runner-images/blob/ee1ff4569e381a9649b400338bdc8ceb7e18a80e/images/ubuntu/Ubuntu2204-Readme.md)

Ubuntu 22.04 is a temporary candidate, deprecated on 2026-09-17 and scheduled to retire on
2027-04-17. The recorded run proves the closed profile on its observed image; inventory or
kernel metadata alone does not extend that proof to other environments.
