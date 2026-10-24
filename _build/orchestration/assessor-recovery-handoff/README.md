# Finite continuity assessor recovery source

This frozen bundle contains standalone Python source, synthetic JSON fixtures and their
verification result. It uses the Python standard library and an injected 2030 clock.
It contains no operational controller, automation configuration, signed URL or live agent snapshot.
The fixture identities are synthetic examples.

The current source is `assess.py`. `baseline_assess.py` is the previous exact source used only
to demonstrate the roster omission. `.gitattributes` preserves LF bytes and hashes on checkout.

Run from this directory:

```sh
sha256sum -c SHA256SUMS
python -B verify.py --assessor assess.py --baseline baseline_assess.py --cases cases.json
```

The frozen result was produced by this exact command on Python 3.12.14:

```sh
python -B verify.py --assessor assess.py --baseline baseline_assess.py --cases cases.json --result RESULT.json
```

Ruff also exited zero for:

```sh
ruff check --no-cache assess.py baseline_assess.py verify.py
```

The 29 cases comprise 13 lifecycle/deadline cases, six schema/coverage cases, seven canonical
proof cases and three converse-roster cases. The last three explicitly assert:

1. A registered running owner omitted from the complete explicit roster produces `attention`
   and `registered_active_owner_not_in_roster`, naming that owner. The historical source
   returns `active_or_handoff` with no finding on the same input.
2. Supplying the complete current roster removes that finding.
3. A completed historical owner is excluded from active coverage even with an expired,
   noncanonical old proof. It does not become an active failure.

The result is **attention**, not a fabricated healthy or `UNKNOWN` task outcome. Findings require
the caller to reconcile the current control plane and canonical handoffs. The assessor evaluates
one supplied snapshot; it does not discover agents, resume tasks or renew leases.

Omitting the roster argument reports `owner_coverage_checked=false`; that is no coverage proof.
The driver checks these semantics, source SHA-256s and the exact historical counterexample.
Replaying without `--result` preserves the frozen result and its checksum.

`MANIFEST.json` lists the source objects and actual verification commands. `SHA256SUMS` covers
every frozen object except itself. Publication and recovery paths are the owner's responsibility;
this bundle has no CI or service integration.
