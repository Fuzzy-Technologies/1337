# ADR 0096: Closed inert isolation and original-file custody proof

- Status: Accepted design; execution acceptance pending
- Date: 2026-10-24
- Stability: Experimental test-only contract
- Related: [ADR 0095](0095-owned-response-zap-passive-profile.md)

## Decision

Before introducing Java or a ZAP provider, prove one fixed composition of the existing
`GovernedLocalExecutor` descendant owner, a repository-owned quota bootstrap, pinned non-SUID
bubblewrap 0.13.0, and a statically linked first-party inert C fixture. Nothing in this proof is
installed in `fuzzy1337`, registered as a provider, or imported by production code. It accepts no
caller executable, argument vector, environment, target, path, resource limit, or FD list.

The first prototype invokes a trusted absolute Python as `-I -B <repository bootstrap.py>
<exclusive request>`. This repository-file invocation is test-only and does not establish the
future installed runtime boundary.

## Closed profile

The only supported profile is unprivileged Linux x86_64 with no effective, permitted or ambient
host capabilities. One bootstrap user/mount namespace owns one tmpfs: 67,108,864 bytes,
1,024 inodes, mode 0700, nodev, nosuid and noexec. Bubblewrap must create fresh user, network,
PID, IPC and UTS namespaces, initialize private loopback, disable further user namespaces, drop
all capabilities, set no-new-privileges, and make the minimal root read-only. Home, temporary,
session, report and shared-memory aliases refer to the same quota mount. The root has only the
static fixture, fixed request, private control socket, directories and fixed aliases.

Only four bootstrap-owned O_PATH handles identify quota, fixture, request and socket material.
The fixed `--bind-fd`/`--ro-bind-fd` template consumes them. No caller FD is forwarded. Consumed
handles must close before the final fixture starts. There is no permissive namespace option,
root/SUID/file-capability fallback, host sysctl/LSM change, arbitrary `/proc` or host-root mount.

## Wire and ownership

All integers are unsigned big-endian. Request is exactly 64 bytes: eight-byte magic `1337ZIP1`,
one-byte mode, three zero reserved bytes, two uint16 held localhost ports, a 16-byte random
nonce and a 32-byte binding digest. Modes are closed: normal=0, byte-limit=1, inode-limit=2,
wait=3 and before-report=4. Ports identify only two sockets held by the current pytest owner.
There is no string command language.

The final sandbox alone connects to the pathname Unix socket and sends exactly one 96-byte
READY (no padding): magic `1337ZRD1`, nonce, digest, and five uint64 values: quota device, quota inode,
filesystem block size, blocks and inodes. Exactly one SCM_RIGHTS read-only directory FD
accompanies it. READY fields are untrusted declarations, never substitutes for actual received-FD
stat/statvfs and known-peer kernel inspection. ACK has no padding. Truncation, extra descriptors, control items, trailing bytes or another message
refuse; every received descriptor closes on refusal. ACK is exactly 56 bytes: `1337ZAK1`, nonce,
digest. No retry or second ACK exists. The final fixture does not fork before ACK.

The parent gets the original peer only through Linux x86_64 native-int
`getsockopt(SOL_SOCKET, SO_PEERPIDFD=77)`, requires CLOEXEC, and checks liveness before and after
bounded known-peer inspection and immediately before ACK. SO_PEERCRED PID is only a `/proc`
locator. It is never passed to `pidfd_open` or a numeric signal. Pidfds do not reserve numeric PIDs.

Before ACK the parent verifies the original fixed request/material, same quota/aliases, exact
mount limits/flags, read-only root, capability and namespace facts, private network, absent late
report, current original authority, cancellation and remaining time. A final synchronous fresh
check directly precedes the one bound ACK, with no intervening await. The existing executor's
original prelaunch gate, descendant ownership and cleanup remain authoritative.

## Late-file custody

`setup.bin` contains `1337 ZAP inert setup v1\n` at READY. It is not the late report.
`report/result.bin` must be absent until ACK. After ACK the fixture creates and fsyncs it with
`1337 ZAP inert late-report v1\n` and emits its actual file identity in a bounded stdout record.
The parent first opens/reads that report only after the original executor has completed owned
cleanup. It uses the original retained directory FD, fixed nofollow openat components and full
before/open/after physical identity. Neither setup bytes nor a pre-cleanup cached report proves
late-file custody. Missing late output remains incomplete.

One exact-instance lease owns at most listener, accepted stream, directory and direct-peer
pidfd, plus short-lived material/request/file handles. Every branch closes acquired descriptors.
The parent retains admitted recovery files on uncertain publication. This proof records bounded
test evidence only: it creates no production receipt, evidence grant, Finding or engine claim.

## Budgets and genuine acceptance

Owner ceiling is 30 seconds and job ceiling 32: preflight 2, outer READY 3, invocation 11,
cleanup 4, custody 8, final 2. Inner READY is at most 5 seconds inside invocation. Absolute
monotonic deductions prevent renewal. Report cap is 4 KiB; stdout/stderr 16 KiB each; admitted
private staging 1 MiB. OS calls/fsync are measured fail-on-late, not hard preemption guarantees.
Repeated caller cancellation settles the same original execution task through the original
20-second cleanup ceiling, preserving the first failure. First report read follows confirmed
cleanup only. Custody/publication deduct from the original absolute 28-second ceiling, followed
by the final two seconds. A late cleanup result never causes an early mount-FD close before
bounded custody. Expired custody or uncertain publication stays incomplete and hands off the
original directory, direct peer pidfd and same task. Unconfirmed execution is represented as
unknown with no fabricated terminal result or complete stdout/stderr; only an observed prefix
may be retained. No report read occurs while cleanup is unknown. CloseRecovery refuses to drop
unsettled ownership; confirming an already-settled original task permits disposal without a
new invocation, renewed budget, late first read or successful-custody claim. This is a volatile
test-owner handoff within the same process, not crash-durable FD recovery.

Genuine cases cover normal isolation, aggregate byte/inode ENOSPC, actual timeout, cooperative
cancel, direct peer pidfd SIGKILL with known setsid child cleanup, pre-ACK authority denial, and
ACK followed by cancellation before late report creation. Denied-operation proof requires an operation-specific expected denial, never EINVAL. The fixed
valid CLONE_NEWUSER attempt may return ENOSPC because the pinned helper consumes the private
ancestor namespace allowance. ENOSPC is not admitted for mount, network-namespace or write
denials. No assertion is made that the final visible namespace limit equals zero. Host sink receives zero contacts;
a separate host-bound non-listening port is usable only by private loopback.

For normal/byte/inode completion, the fixture installs a fixed SIGUSR1 handler and blocks that
signal before work can be advertised. After actual work finishes it emits `WORK_COMPLETE` and
atomically waits with sigsuspend and a sig_atomic_t flag. Its private listener remains open until
one fixed SIGUSR1 arrives through the parent's original direct peer pidfd. The parent observes
the actual completion marker, proves host refusal while the original peer/listener remain live,
sends that fixed release once, and requires actual successful exit and owned cleanup. No sleep,
second ACK, caller-selected signal, numeric PID or new deadline is introduced. Wait/timeout/
cancel/kill cases retain their listener until the selected stop and never use normal release.
The wait-mode child acknowledges readiness through an owned pipe only after successful setsid;
the parent fixture emits `OWNED_CHILD` only after receiving that actual child acknowledgment.

A temporary hosted Ubuntu 22.04 x86_64 lane must run the normal genuine case serially before
remaining independent cases run with two workers. Required flag
`FUZZY1337_RUN_ZAP_INERT_ACCEPTANCE=1` converts missing prerequisites to FAIL before payload;
optional local SKIP is not acceptance. Dependency setup is separately bounded; all builds and
proof execution are nonroot. There is no host policy workaround or indefinitely queued
self-hosted fallback. Source review must precede enabling the first genuine run.

## Limits

This trusts the first-party harness, bootstrap, fixture, pinned helper and kernel. It does not
claim resistance to kernel exploits, hostile same-UID host processes, total anonymous-memory
exhaustion, parent crash or power loss. Actual untouched-host namespace/peerFD/quota/custody
capability remains unproven until genuine CI. Even a passing inert proof does not establish
JRE/ZAP/rootfs/addon material closure, JVM initialization/noexec compatibility, report
completeness, queue semantics, product SDK/CLI integration or engine enrollment.
