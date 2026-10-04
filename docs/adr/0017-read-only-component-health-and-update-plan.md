# ADR 0017: Read-only Component Health and Update Plan

## Status

Accepted

## Context

The Workbench exposes runtime diagnostics but has no component inventory or
controlled update workflow. An initial `1337 update` must communicate the actual
local state without downloading packages, executing tool commands, importing
extensions, or modifying its running installation.

The adapter SDK does not imply registered adapters, installed security tools, or
an intelligence dataset catalog. Their availability must remain explicit until
the respective inventory providers exist.

## Decision

Introduce immutable component-health records and a read-only update report under
the internal `fuzzy1337.component_health` module. Both the CLI and the interactive
shell consume the same collector and renderer.

`1337 update [--json]` inspects the current Python runtime and installed `1337`
distribution metadata. It reports all four component families:

| Family                | Initial observation                                             | Update behavior                                      |
| --------------------- | --------------------------------------------------------------- | ---------------------------------------------------- |
| Core                  | Python compatibility and installed distribution version         | Manual review through the approved installation flow |
| Adapters              | Inventory unavailable; the SDK does not establish installations | No installation or implementation loading            |
| Tools                 | Managed tool inventory unavailable                              | No executable discovery or execution                 |
| Intelligence datasets | Dataset inventory unavailable                                   | No file traversal, downloads, or catalog queries     |

Health states distinguish a successful local check, an unavailable inventory,
an unknown result, and a failed check. An unavailable optional inventory does not
fail the command; any required core check that is not healthy returns exit code
`1`. Argument errors return the existing CLI exit code `2`.

The experimental JSON report carries `schemaVersion = 1`, `mode = "inspect"`,
`updateAvailability = "not_checked"`, and `mutationsPerformed = false`.
Installed versions never establish whether a release is current. Empty or
unreadable distribution metadata remains a required failure.

The command accepts no installation, force, remote-check, component-selection,
or arbitrary-command options. The shell's singular `update` command inspects
components; the existing plural `updates` continues to drain Workbench events.

## Consequences

- Operators receive a truthful update starting point from either entry point.
- Shared immutable records separate local health from remote release freshness.
- Future controlled inventory and update providers can build on the model after
  their own contracts and authorization decisions exist.
- The first implementation cannot determine latest versions, install updates,
  or certify the health of unregistered adapters, tools, or datasets.
- Human terminal formatting remains internal. The versioned JSON preview is
  Experimental and does not freeze a public Python SDK namespace.

## Invariant

> Inspecting component health never performs an update or treats an unchecked
> remote version or unavailable inventory as a successful health observation.
