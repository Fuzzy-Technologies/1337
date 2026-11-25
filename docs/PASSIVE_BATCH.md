# Passive product integration

A `feature/passive-batch-*` branch requests the passive profile for a `develop`
pull request. The name does not admit the change. Independent routing checks the
complete Git change inventory against an immutable reviewed policy. Unrecognized,
mixed or changed infrastructure is held before active acceptance can start.
An ordinary branch retains its established acceptance. Master pull requests and
master pushes retain the full profile.

The reviewed batch runs every unit test once on Linux with Python 3.13. The
`tools/passive_test_gate.py` runner distributes parallel tests across bounded
workers and runs any declared serial tests separately. It then measures the
reviewed offline CLI, integration and contract tests, including their child
processes. Every changed Python production module must exceed 80% combined
statement and branch coverage. The unit fixture denies real socket connections.
The other operating-system and runtime jobs exercise their compatibility tests.

The required **Synthetic lab lifecycle** job starts only the safe health service
in a uniquely named Compose project. It checks actual container ownership,
read-only and unprivileged configuration, no published ports, one internal
network, and the exact successful `/health` response. It then stops its own
project and independently requires the project containers and networks to be
absent. A failed startup, health, isolation or teardown assertion fails the job.
The retained receipt describes only those observed properties.

The passive profile does not start browser acceptance, external-target jobs,
attack-path validation or old active diagnostic checkpoints. Those jobs retain
their original full-profile commands. An offline pass establishes retained-data
and compatibility properties; collection, scanner behavior and release acceptance
still require their separate original evidence.

Routing failure is an explicit failed admission, not a skipped-check pass.
The required quality and lifecycle jobs reject a missing or held profile. No
branch protection, scanner control or product authorization is relaxed.
