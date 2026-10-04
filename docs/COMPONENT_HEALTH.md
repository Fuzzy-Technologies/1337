# Component Health and Update Inspection

The initial `1337 update` command inspects local component health and explains
the update boundary. It reads the Python runtime and installed `1337`
distribution metadata. It makes no network requests and performs no updates.

```bash
1337 update
1337 update --json
```

The interactive shell accepts the same `update` and `update --json` commands.
Its existing plural `updates` command continues to render queued Workbench
events.

## Observations

| Component family      | Current observation                                      | Meaning                                                      |
| --------------------- | -------------------------------------------------------- | ------------------------------------------------------------ |
| Core                  | Python compatibility and installed distribution metadata | Local prerequisite checks; latest release is not checked     |
| Adapters              | Inventory unavailable                                    | An SDK contract does not prove an installed adapter is ready |
| Tools                 | Managed tool inventory unavailable                       | No executable is discovered or run                           |
| Intelligence datasets | Dataset inventory unavailable                            | No dataset catalog or source is queried                      |

Each component has an immutable identifier, family, health status, optional
installed version, required flag, and human-readable summary. `healthy` records
a successful local observation. `unavailable`, `unknown`, and `failed` remain
distinct and never imply that a component is ready or up to date.

The command returns `0` when all required core observations are healthy, `1`
when a required observation is not healthy, and `2` for invalid CLI arguments.
Unavailable optional inventories remain visible even when the exit code is `0`.
An unsupported Python runtime or missing, empty, or unreadable core distribution
metadata fails the required check.

## Experimental JSON report

The initial JSON report uses `schemaVersion: 1`. Its top-level fields are:

| Field                | Value or meaning                                             |
| -------------------- | ------------------------------------------------------------ |
| `schemaVersion`      | `1`                                                          |
| `mode`               | `"inspect"`                                                  |
| `updateAvailability` | `"not_checked"`; no release source has been queried          |
| `mutationsPerformed` | `false`                                                      |
| `components`         | Ordered local observations and explicit unavailable families |
| `exitCode`           | The required-check result returned by the CLI                |

Component objects contain `id`, `kind`, `health`, `installedVersion`, `required`,
and `summary`. An absent observed version is JSON `null`. Human output is for
operators; consumers should use the explicit versioned JSON preview.

This JSON surface is Experimental under [Compatibility](COMPATIBILITY.md).
`fuzzy1337.component_health` remains an internal Python module. Documentation of
its symbols does not declare a Stable SDK.

## Controlled next step

Review core updates through the installation owner's approved environment or
package workflow. For development, dependency pins and `uv.lock` must change
together in a reviewed PR; [Python development](DEVELOPMENT.md) describes the
locked environment. This inspection command does not regenerate the lock,
install packages, invoke tools, load adapters, or traverse dataset directories.

Installation, automatic remote checks, and component-specific update providers
require subsequent explicit contracts. Unsupported flags such as `--apply`,
`--force`, and `--check` are rejected.

The architecture decision is
[ADR 0017](adr/0017-read-only-component-health-and-update-plan.md).
