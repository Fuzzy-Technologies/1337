# Closed inert isolation prerequisite

[ADR 0096](adr/0096-closed-inert-isolation-proof.md) freezes the test-only boundary. There is
currently no accepted genuine run. No production provider or ZAP runtime is introduced.

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

## Evidence and refusal

Only the eight closed cases in ADR 0096 are accepted. The first serial normal case must prove
actual rootless support, direct peer pidfd, namespace/mount/alias restrictions, private loopback,
late-file creation and post-cleanup original read. Missing support fails required CI promptly.
Later independent cases use two workers and finite per-test/job ceilings. No live LLM is called.

Record actual termination, cleanup, quota/namespace observations, denied syscall errors, host
socket counters, the original late-file identity/hash and test evidence. A failed execution may
retain useful original bytes while remaining failed. Sentinel-only retention remains incomplete.
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
2027-04-17. Its documented kernel compatibility does not establish untouched-host capability.
