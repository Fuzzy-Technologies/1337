# Attack-path mini target

`attack-path-mini` is a repository-owned graph contract and isolated executable lab
for deterministic attack-path demonstrations and functional tests. It models exactly:

```text
Internet → Portal → Identity → Billing API → Business Event
```

The versioned scenario documents remain data-only and authorize no external target.
The executable lab realizes the same identifiers using repository-owned containers on
an internal Docker network with no host ports.

## Versioned contract

[`scenario.v1.json`](scenario.v1.json) declares stable typed zones, assets, services,
endpoints, identities, controls, findings, evidence, relations, attack paths, phases,
and transitions. [`oracle.v1.json`](oracle.v1.json) fixes the exact expected lifecycle,
negative path, remediation break, and safety boundary. Both documents use schema
version `1` and reject undeclared root fields through their JSON schemas:

- [`scenario.schema.json`](scenario.schema.json);
- [`oracle.schema.json`](oracle.schema.json).

The canonical path progresses through `UNKNOWN`, `POTENTIAL`, `LIKELY`, `CONFIRMED`,
and `BLOCKED`. Each state declares confidence, evidence, inference, and blocking-control
requirements. Evidence retains seeded or discovered provenance; inferred relations and
assessments name their deterministic inference rule.

The fixture has three deliberately bounded outcomes:

- authorized synthetic validation confirms the canonical business-event path;
- a separate path to the billing signing key remains blocked by an effective policy;
- remediation hardens the Portal-to-Identity relation and breaks the canonical path.

The finding includes attributable MITRE ATT&CK metadata and links the technical route
to the integrity impact on invoice settlement. These are fixture facts for validating
future engines, not claims about any real system.

Run the contract and oracle checks with:

```bash
uv run --locked --extra dev pytest \
  tests/contract/test_attack_path_scenario.py \
  tests/functional/test_attack_path_oracle.py
```

## Executable lab

The lab uses five unprivileged, read-only containers:

- a controlled client representing the untrusted entry zone;
- Portal;
- Identity;
- Billing API;
- Business Event store.

Start every service and wait for deterministic health checks:

```bash
docker compose --profile attack-path up --build --wait \
  lab-attack-portal lab-attack-identity lab-attack-events \
  lab-attack-billing lab-attack-client
```

Exercise the canonical path and the policy-blocked negative path:

```bash
docker compose exec -T lab-attack-client python client.py reset
docker compose exec -T lab-attack-client python client.py validate
docker compose exec -T lab-attack-client python client.py negative
```

Apply remediation, prove the path is blocked, and reset the state:

```bash
docker compose exec -T lab-attack-client python client.py remediate
docker compose exec -T lab-attack-client python client.py reset
```

Stop and remove the complete lab:

```bash
docker compose --profile attack-path down --volumes --remove-orphans
```

All credentials, tokens, subjects, and events are fixed synthetic values. The lab has
no host port, privileged container, host-network mode, or dependency on an Internet
target. Restarting the containers or running `client.py reset` restores deterministic
state.

## Rehearse the owned lifecycle

On Linux with Docker Compose, run the isolated lab assertions from the repository
root. Pytest owns startup, health checks and teardown.

```bash
uv run --locked --extra dev pytest -o addopts='' -n 0 --no-cov \
  tests/functional/test_attack_path_lab.py
```

The tests compare actual command payloads with the versioned oracle and inspect
the Business Event store independently. After hardening, a separate attempt
must report the declared blocked relation and leave the event store empty. A
fresh reset must restore the path and create exactly one expected event.
The fixture limits Compose startup and each client invocation to 60 seconds.
Each internal client HTTP request has a two-second timeout.

The Synthetic lab lifecycle CI job requires all selected cases to execute and
retains their JUnit result, source commit, scenario and oracle SHA-256 digests,
and raw Compose command records in its `attack-path-mini-lifecycle` artifact.
This rehearsal covers fixture behavior. 1337 discovery, Core graph projection
and operator-authorized validation have separate acceptance requirements.
