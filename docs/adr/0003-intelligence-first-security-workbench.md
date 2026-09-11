# ADR 0003: Intelligence-first security workbench

- Status: Accepted
- Date: 2026-09-08
- Decision owners: Fuzzy Technologies

## Context

Security practitioners already use capable specialist tools for discovery,
fingerprinting, testing, and manual validation. Running more tools and collecting
larger vulnerability lists does not by itself preserve context, connect evidence,
or answer what an attacker can reach and what should be fixed first.

1337 must therefore not become merely another scanner launcher or a dashboard
that aggregates raw tool output.

## Decision

1337 is an intelligence-first security workbench. External scanners and native
checks act as sensors; their output is preserved as attributable evidence rather
than treated as the final product.

The architectural reasoning flow is:

```text
Evidence
  → Finding
  → Intelligence
  → Reachability
  → Attack path
  → Risk and remediation context
  → Report
```

Not every assessment will populate every stage, especially in early releases.
The direction is nevertheless stable: a raw finding is an input to reasoning,
not a complete security conclusion.

The platform optimizes for:

- evidence quality and provenance;
- preserved target and assessment context;
- reproducible conclusions;
- attack-path understanding;
- actionable human decisions.

## Consequences

Integrations must retain enough source, timing, scope, and raw-evidence context
for later review. Product work must not measure success only by the number of
integrated scanners or reported findings.

This decision does not claim that the current pre-alpha bootstrap already
implements discovery, attack-path analysis, or reporting. It directs the design
of those future capabilities.
