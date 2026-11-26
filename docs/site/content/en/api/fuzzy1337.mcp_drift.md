# fuzzy1337.mcp_drift

The Experimental offline review API compares two workspace-owned MCP metadata
snapshots for the same server. `ApproveMcpBaseline` records an explicit
operator decision tied to one verified immutable snapshot. `ReviewMcpDrift`
compares a selected acquisition against the active decision and returns
changes, unknown fields, evidence, and normalized finding references.
A subsequent approval requires the exact saved review reference.

The review covers tool and resource membership, tool input schemas and
declared side-effect hints, and the redacted fingerprint of server
instructions. Positive declarations and explicit section completeness
determine known membership. Replaying the same comparison reuses the stored
review and preserves the decision history.

::: fuzzy1337.mcp_drift
